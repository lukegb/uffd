import os
import secrets
import sys

from flask import Flask, redirect, url_for, request, render_template
from flask_babel import Babel
from werkzeug.routing import IntegerConverter
from werkzeug.serving import make_ssl_devcert
try:
	from werkzeug.middleware.profiler import ProfilerMiddleware
except ImportError:
	from werkzeug.contrib.profiler import ProfilerMiddleware
from werkzeug.exceptions import InternalServerError, Forbidden
from flask_migrate import Migrate

from uffd.database import db, SQLAlchemyJSON, customize_db_engine
from uffd.template_helper import register_template_helper
from uffd.navbar import setup_navbar
from uffd.secure_redirect import secure_local_redirect
from uffd import user, selfservice, role, mail, session, csrf, mfa, oauth2, services, signup, rolemod, invite, api
from uffd.user.models import User, Group
from uffd.role.models import Role, RoleGroup
from uffd.mail.models import Mail

def load_config_file(app, path, silent=False):
	if not os.path.exists(path):
		if not silent:
			raise Exception(f"Config file {path} not found")
		return False

	if path.endswith(".json"):
		app.config.from_json(path)
	elif path.endswith(".yaml") or path.endswith(".yml"):
		import yaml  # pylint: disable=import-outside-toplevel disable=import-error
		with open(path, encoding='utf-8') as ymlfile:
			data = yaml.safe_load(ymlfile)
		app.config.from_mapping(data)
	else:
		app.config.from_pyfile(path, silent=True)
	return True

def init_config(app: Flask, test_config):
	# set development default config values
	app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(app.instance_path, 'uffd.sqlit3')}"
	app.config.from_pyfile('default_config.cfg')

	# load config
	if test_config is not None:
		app.config.from_mapping(test_config)
	elif os.environ.get('CONFIG_PATH'):
		load_config_file(app, os.environ['CONFIG_PATH'], silent=False)
	else:
		for filename in ["config.cfg", "config.json", "config.yml", "config.yaml"]:
			if load_config_file(app, os.path.join(app.instance_path, filename), silent=True):
				break

	if app.env == "production" and app.secret_key is None:
		raise Exception("SECRET_KEY not configured and we are running in production mode!")
	app.config.setdefault("SECRET_KEY", secrets.token_hex(128))

def create_app(test_config=None): # pylint: disable=too-many-locals,too-many-statements
	app = Flask(__name__, instance_relative_config=False)
	app.json_encoder = SQLAlchemyJSON

	init_config(app, test_config)

	register_template_helper(app)

	# Sort the navbar positions by their blueprint names (from the left)
	positions = ["selfservice", "services", "rolemod", "invite", "user", "group", "role", "mail"]
	setup_navbar(app, positions)

	# We never want to fail here, but at a file access that doesn't work.
	# We might only have read access to app.instance_path
	try:
		os.makedirs(app.instance_path, exist_ok=True)
	except: # pylint: disable=bare-except
		pass

	db.init_app(app)
	Migrate(app, db, render_as_batch=True, directory=os.path.join(app.root_path, 'migrations'))
	with app.app_context():
		customize_db_engine(db.engine)

	for module in [user, selfservice, role, mail, session, csrf, mfa, oauth2, services, rolemod, api, signup, invite]:
		for bp in module.bp:
			app.register_blueprint(bp)

	@app.shell_context_processor
	def push_request_context(): #pylint: disable=unused-variable
		app.test_request_context().push() # LDAP ORM requires request context
		return {'db': db, 'User': User, 'Group': Group, 'Role': Role, 'Mail': Mail}

	@app.errorhandler(403)
	def handle_403(error):
		return render_template('403.html', description=error.description if error.description != Forbidden.description else None), 403

	@app.route("/")
	def index(): #pylint: disable=unused-variable
		return redirect(url_for('selfservice.index'))

	@app.route('/lang', methods=['POST'])
	def setlang(): #pylint: disable=unused-variable
		resp = secure_local_redirect(request.values.get('ref', '/'))
		if 'lang' in request.values:
			resp.set_cookie('language', request.values['lang'])
		return resp

	@app.cli.command("gendevcert", help='Generates a self-signed TLS certificate for development')
	def gendevcert(): #pylint: disable=unused-variable
		if os.path.exists('devcert.crt') or os.path.exists('devcert.key'):
			print('Refusing to overwrite existing "devcert.crt"/"devcert.key" file!')
			return
		make_ssl_devcert('devcert')
		print('Certificate written to "devcert.crt", private key to "devcert.key".')
		print('Run `flask run --cert devcert.crt --key devcert.key` to use it.')

	@app.cli.command("profile", help='Runs app with profiler')
	def profile(): #pylint: disable=unused-variable
		# app.run() is silently ignored if executed from commands. We really want
		# to do this, so we overwrite the check by overwriting the environment
		# variable.
		os.environ['FLASK_RUN_FROM_CLI'] = 'false'
		app.wsgi_app = ProfilerMiddleware(app.wsgi_app, restrictions=[30])
		app.run(debug=True)

	babel = Babel(app)

	@babel.localeselector
	def get_locale(): #pylint: disable=unused-variable
		language_cookie = request.cookies.get('language')
		if language_cookie is not None and language_cookie in app.config['LANGUAGES']:
			return language_cookie
		return request.accept_languages.best_match(list(app.config['LANGUAGES']))

	app.add_template_global(get_locale)

	return app

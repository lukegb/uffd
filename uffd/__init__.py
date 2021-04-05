import os
import secrets
import sys

from flask import Flask, redirect, url_for
from werkzeug.routing import IntegerConverter
from werkzeug.serving import make_ssl_devcert
from werkzeug.contrib.profiler import ProfilerMiddleware
from flask_migrate import Migrate

sys.path.append('deps/ldapalchemy')

# pylint: disable=wrong-import-position
from uffd.database import db, SQLAlchemyJSON
from uffd.ldap import ldap
from uffd.template_helper import register_template_helper
from uffd.navbar import setup_navbar
# pylint: enable=wrong-import-position

def create_app(test_config=None): # pylint: disable=too-many-locals
	# create and configure the app
	app = Flask(__name__, instance_relative_config=False)
	app.json_encoder = SQLAlchemyJSON

	# set development default config values
	app.config.from_mapping(
		SECRET_KEY=secrets.token_hex(128),
		SQLALCHEMY_DATABASE_URI="sqlite:///{}".format(os.path.join(app.instance_path, 'uffd.sqlit3')),
	)
	app.config.from_pyfile('default_config.cfg')

	register_template_helper(app)
	setup_navbar(app)

	if not test_config:
		# load the instance config, if it exists, when not testing
		app.config.from_pyfile(os.path.join(app.instance_path, 'config.cfg'), silent=True)
	else:
		# load the test config if passed in
		app.config.from_mapping(test_config)

	# ensure the instance folder exists
	try:
		os.makedirs(app.instance_path)
	except OSError:
		pass

	db.init_app(app)
	Migrate(app, db, render_as_batch=True)
	# pylint: disable=C0415
	from uffd import user, selfservice, role, mail, session, csrf, mfa, oauth2, services, signup, invite
	# pylint: enable=C0415

	for i in user.bp + selfservice.bp + role.bp + mail.bp + session.bp + csrf.bp + mfa.bp + oauth2.bp + services.bp + signup.bp + invite.bp:
		app.register_blueprint(i)

	@app.shell_context_processor
	def push_request_context(): #pylint: disable=unused-variable
		app.test_request_context().push() # LDAP ORM requires request context
		return {'db': db, 'ldap': ldap}

	@app.route("/")
	def index(): #pylint: disable=unused-variable
		return redirect(url_for('selfservice.index'))

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

	return app

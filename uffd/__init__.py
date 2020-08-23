import os
import secrets

from flask import Flask, redirect, url_for
from werkzeug.routing import IntegerConverter

from uffd.database import db, SQLAlchemyJSON
from uffd.template_helper import register_template_helper
from uffd.navbar import setup_navbar


def create_app(test_config=None):
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
		app.config.from_pyfile(os.path.join(app.instance_path, 'config.cfg'))
	else:
		# load the test config if passed in
		app.config.from_mapping(test_config)

	# ensure the instance folder exists
	try:
		os.makedirs(app.instance_path)
	except OSError:
		pass

	db.init_app(app)
	# pylint: disable=C0415
	from uffd import user, selfservice, role, mail, session, csrf, ldap
	# pylint: enable=C0415

	for i in user.bp + selfservice.bp + role.bp + mail.bp + session.bp + csrf.bp + ldap.bp:
		app.register_blueprint(i)

	@app.route("/")
	def index(): #pylint: disable=unused-variable
		return redirect(url_for('selfservice.index'))

	return app

def init_db(app):
	with app.app_context():
		db.create_all()

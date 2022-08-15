import unittest

from flask import Flask, Blueprint, session, url_for

from uffd.csrf import bp as csrf_bp, csrf_protect

uid_counter = 0

class TestCSRF(unittest.TestCase):
	unprotected_ep = 'foo'
	protected_ep = 'bar'

	def setUp(self):
		self.app = Flask(__name__)
		self.app.testing = True
		self.app.config['SECRET_KEY'] = 'DEBUGKEY'
		self.app.register_blueprint(csrf_bp)

		@self.app.route('/', methods=['GET', 'POST'])
		def index():
			return 'SUCCESS', 200

		@self.app.route('/login', methods=['GET', 'POST'])
		def login():
			global uid_counter
			session['_csrf_token'] = 'secret_csrf_token%d'%uid_counter
			uid_counter += 1
			return 'Ok', 200

		@self.app.route('/logout', methods=['GET', 'POST'])
		def logout():
			session.clear()
			return 'Ok', 200

		@self.app.route('/foo', methods=['GET', 'POST'])
		def foo():
			return 'SUCCESS', 200

		@self.app.route('/bar', methods=['GET', 'POST'])
		@csrf_protect()
		def bar():
			return 'SUCCESS', 200
		
		self.bp = Blueprint('bp', __name__)

		@self.bp.route('/foo', methods=['GET', 'POST'])
		@csrf_protect(blueprint=self.bp) # This time on .foo and not on .bar!
		def foo():
			return 'SUCCESS', 200
		
		@self.bp.route('/bar', methods=['GET', 'POST'])
		def bar():
			return 'SUCCESS', 200

		self.app.register_blueprint(self.bp, url_prefix='/bp/')
		self.client = self.app.test_client()
		self.client.__enter__()
		# Just do some request so that we can use url_for
		self.client.get(path='/')

	def tearDown(self):
		self.client.__exit__(None, None, None)

	def set_token(self):
		self.client.get(path='/login')

	def clear_token(self):
		self.client.get(path='/logout')

	def test_notoken_unprotected(self):
		url = url_for(self.unprotected_ep)
		self.assertTrue('csrf' not in url)
		self.assertEqual(self.client.get(path=url).data, b'SUCCESS')

	def test_token_unprotected(self):
		self.set_token()
		self.test_notoken_unprotected()

	def test_notoken_protected(self):
		url = url_for(self.protected_ep)
		self.assertNotEqual(self.client.get(path=url).data, b'SUCCESS')

	def test_token_protected(self):
		self.set_token()
		url = url_for(self.protected_ep)
		self.assertEqual(self.client.get(path=url).data, b'SUCCESS')

	def test_wrong_token_protected(self):
		self.set_token()
		url = url_for(self.protected_ep)
		self.set_token()
		self.assertNotEqual(self.client.get(path=url).data, b'SUCCESS')
	
	def test_deleted_token_protected(self):
		self.set_token()
		url = url_for(self.protected_ep)
		self.clear_token()
		self.assertNotEqual(self.client.get(path=url).data, b'SUCCESS')
	
class TestBlueprintCSRF(TestCSRF):
	unprotected_ep = 'bp.bar'
	protected_ep = 'bp.foo'

import base64

from flask import url_for

from uffd.api.views import apikey_required
from uffd.user.models import User
from uffd.password_hash import PlaintextPasswordHash
from uffd.database import db
from utils import UffdTestCase, db_flush

def basic_auth(username, password):
	return ('Authorization', 'Basic ' + base64.b64encode(f'{username}:{password}'.encode()).decode())

class TestAPIAuth(UffdTestCase):
	def setUpApp(self):
		self.app.config['API_CLIENTS_2'] = {
			'test1': {'client_secret': 'testsecret1', 'scopes': ['getusers', 'testscope']},
			'test2': {'client_secret': 'testsecret2'},
		}

		@self.app.route('/test/endpoint1')
		@apikey_required()
		def testendpoint1():
			return 'OK', 200

		@self.app.route('/test/endpoint2')
		@apikey_required('getusers')
		def testendpoint2():
			return 'OK', 200

		@self.app.route('/test/endpoint3')
		@apikey_required('testscope')
		def testendpoint3():
			return 'OK', 200

	def test_basic(self):
		r = self.client.get(path=url_for('testendpoint1'), headers=[basic_auth('test1', 'testsecret1')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		r = self.client.get(path=url_for('testendpoint2'), headers=[basic_auth('test1', 'testsecret1')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		r = self.client.get(path=url_for('testendpoint3'), headers=[basic_auth('test1', 'testsecret1')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		r = self.client.get(path=url_for('testendpoint1'), headers=[basic_auth('test2', 'testsecret2')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)

	def test_basic_invalid_credentials(self):
		r = self.client.get(path=url_for('testendpoint1'), headers=[basic_auth('test-none', 'testsecret-none')], follow_redirects=True)
		self.assertEqual(r.status_code, 401)
		r = self.client.get(path=url_for('testendpoint1'), headers=[basic_auth('test1', 'testsecret2')], follow_redirects=True)
		self.assertEqual(r.status_code, 401)

	def test_basic_missing_scope(self):
		r = self.client.get(path=url_for('testendpoint2'), headers=[basic_auth('test2', 'testsecret2')], follow_redirects=True)
		self.assertEqual(r.status_code, 403)
		r = self.client.get(path=url_for('testendpoint3'), headers=[basic_auth('test2', 'testsecret2')], follow_redirects=True)
		self.assertEqual(r.status_code, 403)

	def test_no_auth(self):
		r = self.client.get(path=url_for('testendpoint1'), follow_redirects=True)
		self.assertEqual(r.status_code, 401)

class TestAPIGetmails(UffdTestCase):
	def setUpApp(self):
		self.app.config['API_CLIENTS_2'] = {
			'test': {'client_secret': 'test', 'scopes': ['getmails']},
		}

	def test_lookup(self):
		r = self.client.get(path=url_for('api.getmails', receive_address='test1@example.com'), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.json, [{'name': 'test', 'receive_addresses': ['test1@example.com', 'test2@example.com'], 'destination_addresses': ['testuser@mail.example.com']}])
		r = self.client.get(path=url_for('api.getmails', receive_address='test2@example.com'), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.json, [{'name': 'test', 'receive_addresses': ['test1@example.com', 'test2@example.com'], 'destination_addresses': ['testuser@mail.example.com']}])

	def test_lookup_notfound(self):
		r = self.client.get(path=url_for('api.getmails', receive_address='test3@example.com'), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.json, [])

	def test_lookup_case_folding(self):
		r = self.client.get(path=url_for('api.getmails', receive_address='Test1@example.com'), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.json, [{'name': 'test', 'receive_addresses': ['test1@example.com', 'test2@example.com'], 'destination_addresses': ['testuser@mail.example.com']}])

class TestAPICheckPassword(UffdTestCase):
	def setUpApp(self):
		self.app.config['API_CLIENTS_2'] = {
			'test': {'client_secret': 'test', 'scopes': ['checkpassword']},
		}

	def test(self):
		r = self.client.post(path=url_for('api.checkpassword'), data={'loginname': 'testuser', 'password': 'userpassword'}, headers=[basic_auth('test', 'test')])
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.json['loginname'], 'testuser')

	def test_password_rehash(self):
		self.get_user().password = PlaintextPasswordHash.from_password('userpassword')
		db.session.commit()
		self.assertIsInstance(self.get_user().password, PlaintextPasswordHash)
		db_flush()
		r = self.client.post(path=url_for('api.checkpassword'), data={'loginname': 'testuser', 'password': 'userpassword'}, headers=[basic_auth('test', 'test')])
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.json['loginname'], 'testuser')
		self.assertIsInstance(self.get_user().password, User.password.method_cls)
		self.assertTrue(self.get_user().password.verify('userpassword'))

	def test_wrong_password(self):
		r = self.client.post(path=url_for('api.checkpassword'), data={'loginname': 'testuser', 'password': 'wrongpassword'}, headers=[basic_auth('test', 'test')])
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.json, None)

import base64

from flask import url_for

from uffd.api.views import apikey_required
from utils import UffdTestCase

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

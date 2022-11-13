from urllib.parse import urlparse, parse_qs

from flask import url_for, session

from uffd.database import db
from uffd.password_hash import PlaintextPasswordHash
from uffd.remailer import remailer
from uffd.models import DeviceLoginConfirmation, Service, OAuth2Client, OAuth2DeviceLoginInitiation, RemailerMode

from tests.utils import dump, UffdTestCase

class TestViews(UffdTestCase):
	def setUpDB(self):
		db.session.add(OAuth2Client(service=Service(name='test', limit_access=False), client_id='test', client_secret='testsecret', redirect_uris=['http://localhost:5009/callback', 'http://localhost:5009/callback2']))
		db.session.add(OAuth2Client(service=Service(name='test1', access_group=self.get_admin_group()), client_id='test1', client_secret='testsecret1', redirect_uris=['http://localhost:5008/callback']))

	def assert_authorization(self, r, mail=None):
		while True:
			if r.status_code != 302 or r.location.startswith('http://localhost:5009/callback'):
				break
			r = self.client.get(r.location, follow_redirects=False)
		self.assertEqual(r.status_code, 302)
		self.assertTrue(r.location.startswith('http://localhost:5009/callback'))
		args = parse_qs(urlparse(r.location).query)
		self.assertEqual(args['state'], ['teststate'])
		code = args['code'][0]
		r = self.client.post(path=url_for('oauth2.token'),
			data={'grant_type': 'authorization_code', 'code': code, 'redirect_uri': 'http://localhost:5009/callback', 'client_id': 'test', 'client_secret': 'testsecret'}, follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.content_type, 'application/json')
		self.assertEqual(r.json['token_type'], 'Bearer')
		self.assertEqual(r.json['scope'], 'profile')
		token = r.json['access_token']
		r = self.client.get(path=url_for('oauth2.userinfo'), headers=[('Authorization', 'Bearer %s'%token)], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.content_type, 'application/json')
		user = self.get_user()
		self.assertEqual(r.json['id'], user.unix_uid)
		self.assertEqual(r.json['name'], user.displayname)
		self.assertEqual(r.json['nickname'], user.loginname)
		self.assertEqual(r.json['email'], mail or user.primary_email.address)
		self.assertTrue(r.json.get('groups'))

	def test_authorization(self):
		self.login_as('user')
		r = self.client.get(path=url_for('oauth2.authorize', response_type='code', client_id='test', state='teststate', redirect_uri='http://localhost:5009/callback', scope='profile'), follow_redirects=False)
		self.assert_authorization(r)

	def test_authorization_with_remailer(self):
		self.app.config['REMAILER_DOMAIN'] = 'remailer.example.com'
		service = Service.query.filter_by(name='test').one()
		service.remailer_mode = RemailerMode.ENABLED_V1
		db.session.commit()
		self.login_as('user')
		r = self.client.get(path=url_for('oauth2.authorize', response_type='code', client_id='test', state='teststate', redirect_uri='http://localhost:5009/callback', scope='profile'), follow_redirects=False)
		service = Service.query.filter_by(name='test').one()
		self.assert_authorization(r, mail=remailer.build_v1_address(service.id, self.get_user().id))

	def test_authorization_client_secret_rehash(self):
		OAuth2Client.query.delete()
		db.session.add(OAuth2Client(service=Service(name='rehash_test', limit_access=False), client_id='test', client_secret=PlaintextPasswordHash.from_password('testsecret'), redirect_uris=['http://localhost:5009/callback', 'http://localhost:5009/callback2']))
		db.session.commit()
		self.assertIsInstance(OAuth2Client.query.filter_by(client_id='test').one().client_secret, PlaintextPasswordHash)
		self.login_as('user')
		r = self.client.get(path=url_for('oauth2.authorize', response_type='code', client_id='test', state='teststate', redirect_uri='http://localhost:5009/callback', scope='profile'), follow_redirects=False)
		self.assert_authorization(r)
		oauth2_client = OAuth2Client.query.filter_by(client_id='test').one()
		self.assertIsInstance(oauth2_client.client_secret, OAuth2Client.client_secret.method_cls)
		self.assertTrue(oauth2_client.client_secret.verify('testsecret'))

	def test_authorization_without_redirect_uri(self):
		self.login_as('user')
		r = self.client.get(path=url_for('oauth2.authorize', response_type='code', client_id='test', state='teststate', scope='profile'), follow_redirects=False)
		self.assert_authorization(r)

	def test_authorization_without_scope(self):
		self.login_as('user')
		r = self.client.get(path=url_for('oauth2.authorize', response_type='code', client_id='test', state='teststate', redirect_uri='http://localhost:5009/callback'), follow_redirects=False)
		self.assert_authorization(r)

	# Regression test for #115 (OAuth2 authorize endpoint rejects empty scope parameter)
	def test_authorization_empty_scope(self):
		self.login_as('user')
		r = self.client.get(path=url_for('oauth2.authorize', response_type='code', client_id='test', state='teststate', scope='', redirect_uri='http://localhost:5009/callback'), follow_redirects=False)
		self.assert_authorization(r)

	def test_authorization_invalid_scope(self):
		self.login_as('user')
		r = self.client.get(path=url_for('oauth2.authorize', response_type='code', client_id='test', state='teststate', redirect_uri='http://localhost:5009/callback', scope='invalid'), follow_redirects=False)
		self.assertEqual(r.status_code, 400)
		dump('oauth2_authorization_invalid_scope', r)

	def test_authorization_missing_client_id(self):
		self.login_as('user')
		r = self.client.get(path=url_for('oauth2.authorize', response_type='code', state='teststate', redirect_uri='http://localhost:5009/callback', scope='profile'), follow_redirects=False)
		self.assertEqual(r.status_code, 400)
		dump('oauth2_authorization_missing_client_id', r)

	def test_authorization_invalid_client_id(self):
		self.login_as('user')
		r = self.client.get(path=url_for('oauth2.authorize', response_type='code', client_id='invalid_client_id', state='teststate', redirect_uri='http://localhost:5009/callback', scope='profile'), follow_redirects=False)
		self.assertEqual(r.status_code, 400)
		dump('oauth2_authorization_invalid_client_id', r)

	def test_authorization_missing_response_type(self):
		self.login_as('user')
		r = self.client.get(path=url_for('oauth2.authorize', client_id='test', state='teststate', redirect_uri='http://localhost:5009/callback', scope='profile'), follow_redirects=False)
		self.assertEqual(r.status_code, 400)
		dump('oauth2_authorization_missing_response_type', r)

	def test_authorization_invalid_response_type(self):
		self.login_as('user')
		r = self.client.get(path=url_for('oauth2.authorize', response_type='token', client_id='test', state='teststate', redirect_uri='http://localhost:5009/callback', scope='profile'), follow_redirects=False)
		self.assertEqual(r.status_code, 400)
		dump('oauth2_authorization_invalid_response_type', r)

	def test_authorization_devicelogin_start(self):
		ref = url_for('oauth2.authorize', response_type='code', client_id='test', state='teststate', redirect_uri='http://localhost:5009/callback')
		r = self.client.get(path=url_for('session.devicelogin_start', ref=ref), follow_redirects=True)
		# check response
		initiation = OAuth2DeviceLoginInitiation.query.filter_by(id=session['devicelogin_id'], secret=session['devicelogin_secret']).one()
		self.assertEqual(r.status_code, 200)
		self.assertFalse(initiation.expired)
		self.assertEqual(initiation.client.client_id, 'test')
		self.assertIsNotNone(initiation.description)

	def test_authorization_devicelogin_auth(self):
		with self.client.session_transaction() as _session:
			initiation = OAuth2DeviceLoginInitiation(client=OAuth2Client.query.filter_by(client_id='test').one())
			db.session.add(initiation)
			confirmation = DeviceLoginConfirmation(initiation=initiation, user=self.get_user())
			db.session.add(confirmation)
			db.session.commit()
			_session['devicelogin_id'] = initiation.id
			_session['devicelogin_secret'] = initiation.secret
			code = confirmation.code
		self.client.get(path='/')
		ref = url_for('oauth2.authorize', response_type='code', client_id='test', state='teststate', redirect_uri='http://localhost:5009/callback')
		r = self.client.post(path=url_for('session.devicelogin_submit', ref=ref), data={'confirmation-code': code}, follow_redirects=False)
		self.assert_authorization(r)

	def test_authorization_devicelogin_auth_deactivated(self):
		with self.client.session_transaction() as _session:
			initiation = OAuth2DeviceLoginInitiation(client=OAuth2Client.query.filter_by(client_id='test').one())
			db.session.add(initiation)
			confirmation = DeviceLoginConfirmation(initiation=initiation, user=self.get_user())
			db.session.add(confirmation)
			db.session.commit()
			_session['devicelogin_id'] = initiation.id
			_session['devicelogin_secret'] = initiation.secret
			code = confirmation.code
		self.client.get(path='/')
		self.get_user().is_deactivated = True
		db.session.commit()
		ref = url_for('oauth2.authorize', response_type='code', client_id='test', state='teststate', redirect_uri='http://localhost:5009/callback')
		r = self.client.post(path=url_for('session.devicelogin_submit', ref=ref), data={'confirmation-code': code}, follow_redirects=True)
		self.assertIn(b'Device login failed', r.data)

	def get_auth_code(self):
		self.login_as('user')
		r = self.client.get(path=url_for('oauth2.authorize', response_type='code', client_id='test', state='teststate', redirect_uri='http://localhost:5009/callback', scope='profile'), follow_redirects=False)
		while True:
			if r.status_code != 302 or r.location.startswith('http://localhost:5009/callback'):
				break
			r = self.client.get(r.location, follow_redirects=False)
		self.assertEqual(r.status_code, 302)
		self.assertTrue(r.location.startswith('http://localhost:5009/callback'))
		args = parse_qs(urlparse(r.location).query)
		self.assertEqual(args['state'], ['teststate'])
		return args['code'][0]

	def test_token_urlsecret(self):
		r = self.client.post(path=url_for('oauth2.token'),
			data={'grant_type': 'authorization_code', 'code': self.get_auth_code(), 'redirect_uri': 'http://localhost:5009/callback', 'client_id': 'test', 'client_secret': 'testsecret'}, follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.content_type, 'application/json')
		self.assertEqual(r.json['token_type'], 'Bearer')
		self.assertEqual(r.json['scope'], 'profile')

	# Regression test for #114 (OAuth2 token endpoint does not support Basic-Auth)
	def test_token_basicauth(self):
		r = self.client.post(path=url_for('oauth2.token'),
			data={'grant_type': 'authorization_code', 'code': self.get_auth_code(), 'redirect_uri': 'http://localhost:5009/callback'},
			headers={'Authorization': f'Basic dGVzdDp0ZXN0c2VjcmV0'}, follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.content_type, 'application/json')
		self.assertEqual(r.json['token_type'], 'Bearer')
		self.assertEqual(r.json['scope'], 'profile')

	def test_token_invalid_code(self):
		r = self.client.post(path=url_for('oauth2.token'),
			data={'grant_type': 'authorization_code', 'code': 'abcdef', 'redirect_uri': 'http://localhost:5009/callback', 'client_id': 'test', 'client_secret': 'testsecret'}, follow_redirects=True)
		self.assertIn(r.status_code, [400, 401]) # oauthlib behaviour changed between v2.1.0 and v3.1.0
		self.assertEqual(r.content_type, 'application/json')

	def test_token_invalid_client(self):
		r = self.client.post(path=url_for('oauth2.token'),
			data={'grant_type': 'authorization_code', 'code': self.get_auth_code(), 'redirect_uri': 'http://localhost:5009/callback', 'client_id': 'invalid_client', 'client_secret': 'invalid_client_secret'}, follow_redirects=True)
		self.assertEqual(r.status_code, 401)
		self.assertEqual(r.content_type, 'application/json')

	def test_token_unauthorized_client(self):
		r = self.client.post(path=url_for('oauth2.token'),
			data={'grant_type': 'authorization_code', 'code': self.get_auth_code(), 'redirect_uri': 'http://localhost:5009/callback', 'client_id': 'test'}, follow_redirects=True)
		self.assertEqual(r.status_code, 401)
		self.assertEqual(r.content_type, 'application/json')

	def test_token_unsupported_grant_type(self):
		r = self.client.post(path=url_for('oauth2.token'),
			data={'grant_type': 'password', 'code': self.get_auth_code(), 'redirect_uri': 'http://localhost:5009/callback', 'client_id': 'test', 'client_secret': 'testsecret'}, follow_redirects=True)
		self.assertEqual(r.status_code, 400)
		self.assertEqual(r.content_type, 'application/json')
		self.assertEqual(r.json['error'], 'unsupported_grant_type')

	def test_token_deactivated_user(self):
		code = self.get_auth_code()
		self.get_user().is_deactivated = True
		db.session.commit()
		r = self.client.post(path=url_for('oauth2.token'),
			data={'grant_type': 'authorization_code', 'code': code, 'redirect_uri': 'http://localhost:5009/callback', 'client_id': 'test', 'client_secret': 'testsecret'}, follow_redirects=True)
		self.assertIn(r.status_code, [400, 401]) # oauthlib behaviour changed between v2.1.0 and v3.1.0
		self.assertEqual(r.content_type, 'application/json')

	def test_userinfo_invalid_access_token(self):
		token = 'invalidtoken'
		r = self.client.get(path=url_for('oauth2.userinfo'), headers=[('Authorization', 'Bearer %s'%token)], follow_redirects=True)
		self.assertEqual(r.status_code, 401)

	def test_userinfo_invalid_access_token(self):
		r = self.client.post(path=url_for('oauth2.token'),
			data={'grant_type': 'authorization_code', 'code': self.get_auth_code(), 'redirect_uri': 'http://localhost:5009/callback', 'client_id': 'test', 'client_secret': 'testsecret'}, follow_redirects=True)
		token = r.json['access_token']
		self.get_user().is_deactivated = True
		db.session.commit()
		r = self.client.get(path=url_for('oauth2.userinfo'), headers=[('Authorization', 'Bearer %s'%token)], follow_redirects=True)
		self.assertEqual(r.status_code, 401)

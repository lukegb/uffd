import datetime
from urllib.parse import urlparse, parse_qs

from flask import url_for, session

# These imports are required, because otherwise we get circular imports?!
from uffd import ldap, user

from uffd.user.models import User
from uffd.session.models import DeviceLoginConfirmation
from uffd.oauth2.models import OAuth2Client, OAuth2DeviceLoginInitiation
from uffd import create_app, db, ldap

from utils import dump, UffdTestCase


class TestOAuth2Client(UffdTestCase):
	def setUpApp(self):
		self.app.config['OAUTH2_CLIENTS'] = {
			'test': {'client_secret': 'testsecret', 'redirect_uris': ['http://localhost:5009/callback', 'http://localhost:5009/callback2']},
			'test1': {'client_secret': 'testsecret1', 'redirect_uris': ['http://localhost:5008/callback'], 'required_group': 'users'},
		}

	def test_from_id(self):
		client = OAuth2Client.from_id('test')
		self.assertEqual(client.client_id, 'test')
		self.assertEqual(client.client_secret, 'testsecret')
		self.assertEqual(client.redirect_uris, ['http://localhost:5009/callback', 'http://localhost:5009/callback2'])
		self.assertEqual(client.default_redirect_uri, 'http://localhost:5009/callback')
		self.assertEqual(client.default_scopes, ['profile'])
		self.assertEqual(client.client_type, 'confidential')
		client = OAuth2Client.from_id('test1')
		self.assertEqual(client.client_id, 'test1')
		self.assertEqual(client.required_group, 'users')

	def test_access_allowed(self):
		user = self.get_user() # has 'users' and 'uffd_access' group
		admin = self.get_admin() # has 'users', 'uffd_access' and 'uffd_admin' group
		client = OAuth2Client('test', '', [''], ['uffd_admin', ['users', 'notagroup']])
		self.assertFalse(client.access_allowed(user))
		self.assertTrue(client.access_allowed(admin))
		# More required_group values are tested by TestUserModel.test_has_permission

class TestViews(UffdTestCase):
	def setUpApp(self):
		self.app.config['OAUTH2_CLIENTS'] = {
			'test': {'client_secret': 'testsecret', 'redirect_uris': ['http://localhost:5009/callback', 'http://localhost:5009/callback2']},
			'test1': {'client_secret': 'testsecret1', 'redirect_uris': ['http://localhost:5008/callback'], 'required_group': 'uffd_admin'},
		}

	def assert_authorization(self, r):
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
		self.assertEqual(r.json['id'], user.uid)
		self.assertEqual(r.json['name'], user.displayname)
		self.assertEqual(r.json['nickname'], user.loginname)
		self.assertEqual(r.json['email'], user.mail)
		self.assertTrue(r.json.get('groups'))

	def test_authorization(self):
		self.login_as('user')
		r = self.client.get(path=url_for('oauth2.authorize', response_type='code', client_id='test', state='teststate', redirect_uri='http://localhost:5009/callback'), follow_redirects=False)
		self.assert_authorization(r)

	def test_authorization_devicelogin_start(self):
		ref = url_for('oauth2.authorize', response_type='code', client_id='test', state='teststate', redirect_uri='http://localhost:5009/callback')
		r = self.client.get(path=url_for('session.devicelogin_start', ref=ref), follow_redirects=True)
		# check response
		initiation = OAuth2DeviceLoginInitiation.query.filter_by(id=session['devicelogin_id'], secret=session['devicelogin_secret']).one()
		self.assertEqual(r.status_code, 200)
		self.assertFalse(initiation.expired)
		self.assertEqual(initiation.oauth2_client_id, 'test')
		self.assertIsNotNone(initiation.description)

	def test_authorization_devicelogin_auth(self):
		with self.client.session_transaction() as _session:
			initiation = OAuth2DeviceLoginInitiation(oauth2_client_id='test')
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

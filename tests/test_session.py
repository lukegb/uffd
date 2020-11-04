import time
import unittest

from flask import url_for

# These imports are required, because otherwise we get circular imports?!
from uffd import ldap, user

from uffd.session.views import get_current_user, login_required, is_valid_session
from uffd import create_app, db

from utils import dump, UffdTestCase

class TestSession(UffdTestCase):
	def setUpApp(self):
		self.app.config['SESSION_LIFETIME_SECONDS'] = 2

		@self.app.route('/test_login_required')
		@login_required()
		def test_login_required():
			return 'SUCCESS', 200

		@self.app.route('/test_group_required1')
		@login_required(group='users')
		def test_group_required1():
			return 'SUCCESS', 200

		@self.app.route('/test_group_required2')
		@login_required(group='notagroup')
		def test_group_required2():
			return 'SUCCESS', 200

	def setUp(self):
		super().setUp()
		self.assertFalse(is_valid_session())

	def login(self):
		self.client.post(path=url_for('session.login'),
			data={'loginname': 'testuser', 'password': 'userpassword'}, follow_redirects=True)
		self.assertTrue(is_valid_session())

	def assertLogin(self):
		self.assertTrue(is_valid_session())
		self.assertEqual(self.client.get(path=url_for('test_login_required'),
			follow_redirects=True).data, b'SUCCESS')
		self.assertEqual(get_current_user().loginname, 'testuser')

	def assertLogout(self):
		self.assertFalse(is_valid_session())
		self.assertNotEqual(self.client.get(path=url_for('test_login_required'),
			follow_redirects=True).data, b'SUCCESS')
		self.assertEqual(get_current_user(), None)

	def test_login(self):
		self.assertLogout()
		r = self.client.get(path=url_for('session.login'), follow_redirects=True)
		dump('login', r)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('session.login'),
			data={'loginname': 'testuser', 'password': 'userpassword'}, follow_redirects=True)
		dump('login_post', r)
		self.assertEqual(r.status_code, 200)
		self.assertLogin()

	def test_redirect(self):
		r = self.client.post(path=url_for('session.login', ref=url_for('test_login_required')),
			data={'loginname': 'testuser', 'password': 'userpassword'}, follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.data, b'SUCCESS')

	def test_wrong_password(self):
		r = self.client.post(path=url_for('session.login'),
			data={'loginname': 'testuser', 'password': 'wrongpassword'}, follow_redirects=True)
		dump('login_wrong_password', r)
		self.assertEqual(r.status_code, 200)
		self.assertLogout()

	def test_empty_password(self):
		r = self.client.post(path=url_for('session.login'),
			data={'loginname': 'testuser', 'password': ''}, follow_redirects=True)
		dump('login_empty_password', r)
		self.assertEqual(r.status_code, 200)
		self.assertLogout()

	def test_wrong_user(self):
		r = self.client.post(path=url_for('session.login'),
			data={'loginname': 'nouser', 'password': 'userpassword'}, follow_redirects=True)
		dump('login_wrong_user', r)
		self.assertEqual(r.status_code, 200)
		self.assertLogout()

	def test_empty_user(self):
		r = self.client.post(path=url_for('session.login'),
			data={'loginname': '', 'password': 'userpassword'}, follow_redirects=True)
		dump('login_empty_user', r)
		self.assertEqual(r.status_code, 200)
		self.assertLogout()

	def test_no_access(self):
		r = self.client.post(path=url_for('session.login'),
			data={'loginname': 'testservice', 'password': 'servicepassword'}, follow_redirects=True)
		dump('login_no_access', r)
		self.assertEqual(r.status_code, 200)
		self.assertLogout()

	def test_group_required(self):
		self.login()
		self.assertEqual(self.client.get(path=url_for('test_group_required1'),
			follow_redirects=True).data, b'SUCCESS')
		self.assertNotEqual(self.client.get(path=url_for('test_group_required2'),
			follow_redirects=True).data, b'SUCCESS')

	def test_logout(self):
		self.login()
		r = self.client.get(path=url_for('session.logout'), follow_redirects=True)
		dump('logout', r)
		self.assertEqual(r.status_code, 200)
		self.assertLogout()

	@unittest.skip('See #29')
	def test_timeout(self):
		self.login()
		time.sleep(3)
		self.assertLogout()

	def test_ratelimit(self):
		for i in range(20):
			self.client.post(path=url_for('session.login'),
				data={'loginname': 'testuser', 'password': 'wrongpassword_%i'%i}, follow_redirects=True)
		r = self.client.post(path=url_for('session.login'),
			data={'loginname': 'testuser', 'password': 'userpassword'}, follow_redirects=True)
		dump('login_ratelimit', r)
		self.assertEqual(r.status_code, 200)
		self.assertFalse(is_valid_session())

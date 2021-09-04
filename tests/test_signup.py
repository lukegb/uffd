import unittest
import datetime
import time

from flask import url_for, session, request

# These imports are required, because otherwise we get circular imports?!
from uffd import user
from uffd.ldap import ldap

from uffd import create_app, db
from uffd.signup.models import Signup
from uffd.user.models import User
from uffd.role.models import Role, RoleGroup
from uffd.session.views import login_get_user

from utils import dump, UffdTestCase, db_flush

def refetch_signup(signup):
	db.session.add(signup)
	db.session.commit()
	token = signup.token
	db_flush()
	return Signup.query.get(token)

# We assume in all tests that Signup.validate and Signup.check_password do
# not alter any state

class TestSignupModel(UffdTestCase):
	def assert_validate_valid(self, signup):
		valid, msg = signup.validate()
		self.assertTrue(valid)
		self.assertIsInstance(msg, str)

	def assert_validate_invalid(self, signup):
		valid, msg = signup.validate()
		self.assertFalse(valid)
		self.assertIsInstance(msg, str)
		self.assertNotEqual(msg, '')

	def assert_finish_success(self, signup, password):
		self.assertIsNone(signup.user)
		user, msg = signup.finish(password)
		ldap.session.commit()
		self.assertIsNotNone(user)
		self.assertIsInstance(msg, str)
		self.assertIsNotNone(signup.user)

	def assert_finish_failure(self, signup, password):
		prev_dn = signup.user_dn
		user, msg = signup.finish(password)
		self.assertIsNone(user)
		self.assertIsInstance(msg, str)
		self.assertNotEqual(msg, '')
		self.assertEqual(signup.user_dn, prev_dn)

	def test_password(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='test@example.com')
		self.assertFalse(signup.check_password('notsecret'))
		self.assertFalse(signup.check_password(''))
		self.assertFalse(signup.check_password('wrongpassword'))
		signup.password = 'notsecret'
		self.assertTrue(signup.check_password('notsecret'))
		self.assertFalse(signup.check_password('wrongpassword'))

	def test_expired(self):
		# TODO: Find a better way to test this!
		signup = Signup(loginname='newuser', displayname='New User', mail='test@example.com', password='notsecret')
		self.assertFalse(signup.expired)
		signup.created = created=datetime.datetime.now() - datetime.timedelta(hours=49)
		self.assertTrue(signup.expired)

	def test_completed(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='test@example.com', password='notsecret')
		self.assertFalse(signup.completed)
		signup.finish('notsecret')
		ldap.session.commit()
		self.assertTrue(signup.completed)
		signup = refetch_signup(signup)
		self.assertTrue(signup.completed)

	def test_validate(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='test@example.com', password='notsecret')
		self.assert_validate_valid(signup)
		self.assert_validate_valid(refetch_signup(signup))

	def test_validate_completed(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='test@example.com', password='notsecret')
		self.assert_finish_success(signup, 'notsecret')
		self.assert_validate_invalid(signup)
		self.assert_validate_invalid(refetch_signup(signup))

	def test_validate_expired(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='test@example.com',
		                password='notsecret', created=datetime.datetime.now()-datetime.timedelta(hours=49))
		self.assert_validate_invalid(signup)
		self.assert_validate_invalid(refetch_signup(signup))

	def test_validate_loginname(self):
		signup = Signup(loginname='', displayname='New User', mail='test@example.com', password='notsecret')
		self.assert_validate_invalid(signup)
		self.assert_validate_invalid(refetch_signup(signup))

	def test_validate_displayname(self):
		signup = Signup(loginname='newuser', displayname='', mail='test@example.com', password='notsecret')
		self.assert_validate_invalid(signup)
		self.assert_validate_invalid(refetch_signup(signup))

	def test_validate_mail(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='', password='notsecret')
		self.assert_validate_invalid(signup)
		self.assert_validate_invalid(refetch_signup(signup))

	def test_validate_password(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='test@example.com', password='')
		self.assert_validate_invalid(signup)
		self.assert_validate_invalid(refetch_signup(signup))

	def test_validate_exists(self):
		signup = Signup(loginname='testuser', displayname='New User', mail='test@example.com', password='notsecret')
		self.assert_validate_invalid(signup)
		self.assert_validate_invalid(refetch_signup(signup))

	def test_finish(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='test@example.com', password='notsecret')
		if self.use_openldap:
			self.assertIsNone(login_get_user('newuser', 'notsecret'))
		self.assert_finish_success(signup, 'notsecret')
		user = User.query.get('uid=newuser,{}'.format(self.app.config['LDAP_USER_SEARCH_BASE']))
		self.assertEqual(user.loginname, 'newuser')
		self.assertEqual(user.displayname, 'New User')
		self.assertEqual(user.mail, 'test@example.com')
		if self.use_openldap:
			self.assertIsNotNone(login_get_user('newuser', 'notsecret'))

	def test_finish_completed(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='test@example.com', password='notsecret')
		self.assert_finish_success(signup, 'notsecret')
		self.assert_finish_failure(refetch_signup(signup), 'notsecret')

	def test_finish_expired(self):
		# TODO: Find a better way to test this!
		signup = Signup(loginname='newuser', displayname='New User', mail='test@example.com',
		                password='notsecret', created=datetime.datetime.now()-datetime.timedelta(hours=49))
		self.assert_finish_failure(signup, 'notsecret')
		self.assert_finish_failure(refetch_signup(signup), 'notsecret')

	def test_finish_wrongpassword(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='test@example.com')
		self.assert_finish_failure(signup, '')
		self.assert_finish_failure(signup, 'wrongpassword')
		signup = refetch_signup(signup)
		self.assert_finish_failure(signup, '')
		self.assert_finish_failure(signup, 'wrongpassword')
		signup = Signup(loginname='newuser', displayname='New User', mail='test@example.com', password='notsecret')
		self.assert_finish_failure(signup, 'wrongpassword')
		self.assert_finish_failure(refetch_signup(signup), 'wrongpassword')

	def test_finish_ldaperror(self):
		signup = Signup(loginname='testuser', displayname='New User', mail='test@example.com', password='notsecret')
		self.assert_finish_failure(signup, 'notsecret')
		self.assert_finish_failure(refetch_signup(signup), 'notsecret')

	def test_duplicate(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='test1@example.com', password='notsecret')
		self.assert_validate_valid(signup)
		db.session.add(signup)
		db.session.commit()
		signup1_token = signup.token
		signup = Signup(loginname='newuser', displayname='New User', mail='test2@example.com', password='notsecret')
		self.assert_validate_valid(signup)
		db.session.add(signup)
		db.session.commit()
		signup2_token = signup.token
		db_flush()
		signup = Signup.query.get(signup2_token)
		self.assert_finish_success(signup, 'notsecret')
		db.session.commit()
		db_flush()
		signup = Signup.query.get(signup1_token)
		self.assert_finish_failure(signup, 'notsecret')
		user = User.query.get('uid=newuser,{}'.format(self.app.config['LDAP_USER_SEARCH_BASE']))
		self.assertEqual(user.mail, 'test2@example.com')

class TestSignupModelOL(TestSignupModel):
	use_openldap = True

class TestSignupViews(UffdTestCase):
	def setUpApp(self):
		self.app.config['SELF_SIGNUP'] = True
		self.app.last_mail = None

	def test_signup(self):
		r = self.client.get(path=url_for('signup.signup_start'), follow_redirects=True)
		dump('test_signup', r)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(Signup.query.filter_by(loginname='newuser').all(), [])
		r = self.client.post(path=url_for('signup.signup_submit'), follow_redirects=True,
			data={'loginname': 'newuser', 'displayname': 'New User', 'mail': 'test@example.com',
			      'password1': 'notsecret', 'password2': 'notsecret'})
		dump('test_signup_submit', r)
		self.assertEqual(r.status_code, 200)
		db_flush()
		signups = Signup.query.filter_by(loginname='newuser').all()
		self.assertEqual(len(signups), 1)
		signup = signups[0]
		self.assertEqual(signup.loginname, 'newuser')
		self.assertEqual(signup.displayname, 'New User')
		self.assertEqual(signup.mail, 'test@example.com')
		self.assertIn(signup.token, str(self.app.last_mail.get_content()))
		self.assertTrue(signup.check_password('notsecret'))
		self.assertTrue(signup.validate()[0])

	def test_signup_disabled(self):
		self.app.config['SELF_SIGNUP'] = False
		r = self.client.get(path=url_for('signup.signup_start'), follow_redirects=True)
		dump('test_signup_disabled', r)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(Signup.query.filter_by(loginname='newuser').all(), [])
		r = self.client.post(path=url_for('signup.signup_submit'), follow_redirects=True,
			data={'loginname': 'newuser', 'displayname': 'New User', 'mail': 'test@example.com',
			      'password1': 'notsecret', 'password2': 'notsecret'})
		dump('test_signup_submit_disabled', r)
		self.assertEqual(r.status_code, 200)
		db_flush()
		self.assertEqual(Signup.query.filter_by(loginname='newuser').all(), [])

	def test_signup_wrongpassword(self):
		r = self.client.post(path=url_for('signup.signup_submit'), follow_redirects=True,
			data={'loginname': 'newuser', 'displayname': 'New User', 'mail': 'test@example.com',
			      'password1': 'notsecret', 'password2': 'notthesame'})
		dump('test_signup_wrongpassword', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(self.app.last_mail)

	def test_signup_invalid(self):
		r = self.client.post(path=url_for('signup.signup_submit'), follow_redirects=True,
			data={'loginname': '', 'displayname': 'New User', 'mail': 'test@example.com',
			      'password1': 'notsecret', 'password2': 'notsecret'})
		dump('test_signup_invalid', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(self.app.last_mail)

	def test_signup_mailerror(self):
		self.app.config['MAIL_SKIP_SEND'] = 'fail'
		r = self.client.post(path=url_for('signup.signup_submit'), follow_redirects=True,
			data={'loginname': 'newuser', 'displayname': 'New User', 'mail': 'test@example.com',
			      'password1': 'notsecret', 'password2': 'notsecret'})
		dump('test_signup_mailerror', r)
		self.assertEqual(r.status_code, 200)

	def test_signup_hostlimit(self):
		# Each signup_submit request leaks information about the existance of a
		# user with a specific loginname. A host/network-based ratelimit should
		# make enumerations of all user accounts difficult/next to impossible.
		# Additionally each successful requests sends a mail to an
		# attacker-controlled address. The ratelimit limits the applicability for
		# spamming.
		for i in range(20):
			r = self.client.post(path=url_for('signup.signup_submit'), follow_redirects=True,
				data={'loginname': 'newuser%d'%i, 'displayname': 'New User', 'mail': 'test%d@example.com'%i,
				      'password1': 'notsecret', 'password2': 'notsecret'})
			self.assertEqual(r.status_code, 200)
		self.app.last_mail = None
		r = self.client.post(path=url_for('signup.signup_submit'), follow_redirects=True,
			data={'loginname': 'newuser', 'displayname': 'New User', 'mail': 'test@example.com',
			      'password1': 'notsecret', 'password2': 'notsecret'})
		dump('test_signup_hostlimit', r)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(Signup.query.filter_by(loginname='newuser').all(), [])
		self.assertIsNone(self.app.last_mail)

	def test_signup_maillimit(self):
		for i in range(3):
			r = self.client.post(path=url_for('signup.signup_submit'), follow_redirects=True,
				data={'loginname': 'newuser%d'%i, 'displayname': 'New User', 'mail': 'test@example.com',
				      'password1': 'notsecret', 'password2': 'notsecret'})
			self.assertEqual(r.status_code, 200)
		self.app.last_mail = None
		r = self.client.post(path=url_for('signup.signup_submit'), follow_redirects=True,
			data={'loginname': 'newuser', 'displayname': 'New User', 'mail': 'test@example.com',
			      'password1': 'notsecret', 'password2': 'notsecret'})
		dump('test_signup_maillimit', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(self.app.last_mail)
		# Check that we did not hit the host limit
		r = self.client.post(path=url_for('signup.signup_submit'), follow_redirects=True,
			data={'loginname': 'differentuser', 'displayname': 'New User',
			      'mail': 'different@mailaddress.com', 'password1': 'notsecret',
			      'password2': 'notsecret'})
		self.assertIsNotNone(self.app.last_mail)

	def test_signup_check(self):
		r = self.client.post(path=url_for('signup.signup_check'), follow_redirects=True,
		                     data={'loginname': 'newuser'})
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.content_type, 'application/json')
		self.assertEqual(r.json['status'], 'ok')

	def test_signup_check_invalid(self):
		r = self.client.post(path=url_for('signup.signup_check'), follow_redirects=True,
		                     data={'loginname': ''})
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.content_type, 'application/json')
		self.assertEqual(r.json['status'], 'invalid')

	def test_signup_check_exists(self):
		r = self.client.post(path=url_for('signup.signup_check'), follow_redirects=True,
		                     data={'loginname': 'testuser'})
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.content_type, 'application/json')
		self.assertEqual(r.json['status'], 'exists')

	def test_signup_check_ratelimited(self):
		for i in range(20):
			r = self.client.post(path=url_for('signup.signup_check'), follow_redirects=True,
		                       data={'loginname': 'newuser%d'%i})
			self.assertEqual(r.status_code, 200)
			self.assertEqual(r.content_type, 'application/json')
		r = self.client.post(path=url_for('signup.signup_check'), follow_redirects=True,
		                     data={'loginname': 'newuser'})
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.content_type, 'application/json')
		self.assertEqual(r.json['status'], 'ratelimited')

	def test_confirm(self):
		baserole = Role(name='baserole', is_default=True)
		db.session.add(baserole)
		baserole.groups[self.get_access_group()] = RoleGroup()
		db.session.commit()
		signup = Signup(loginname='newuser', displayname='New User', mail='test@example.com', password='notsecret')
		signup = refetch_signup(signup)
		self.assertFalse(signup.completed)
		if self.use_openldap:
			self.assertIsNone(login_get_user('newuser', 'notsecret'))
		r = self.client.get(path=url_for('signup.signup_confirm', token=signup.token), follow_redirects=True)
		dump('test_signup_confirm', r)
		self.assertEqual(r.status_code, 200)
		signup = refetch_signup(signup)
		self.assertFalse(signup.completed)
		if self.use_openldap:
			self.assertIsNone(login_get_user('newuser', 'notsecret'))
		r = self.client.post(path=url_for('signup.signup_confirm_submit', token=signup.token), follow_redirects=True, data={'password': 'notsecret'})
		dump('test_signup_confirm_submit', r)
		self.assertEqual(r.status_code, 200)
		signup = refetch_signup(signup)
		self.assertTrue(signup.completed)
		self.assertEqual(signup.user.loginname, 'newuser')
		self.assertEqual(signup.user.displayname, 'New User')
		self.assertEqual(signup.user.mail, 'test@example.com')
		if self.use_openldap:
			self.assertIsNotNone(login_get_user('newuser', 'notsecret'))
		self.assertIsNotNone(request.user)
		self.assertEqual(request.user.loginname, 'newuser')

	def test_confirm_loggedin(self):
		baserole = Role(name='baserole', is_default=True)
		db.session.add(baserole)
		baserole.groups[self.get_access_group()] = RoleGroup()
		db.session.commit()
		signup = Signup(loginname='newuser', displayname='New User', mail='test@example.com', password='notsecret')
		signup = refetch_signup(signup)
		self.login_as('user')
		self.assertFalse(signup.completed)
		self.assertIsNotNone(request.user)
		self.assertEqual(request.user.loginname, self.get_user().loginname)
		r = self.client.get(path=url_for('signup.signup_confirm', token=signup.token), follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('signup.signup_confirm_submit', token=signup.token), follow_redirects=True, data={'password': 'notsecret'})
		self.assertEqual(r.status_code, 200)
		signup = refetch_signup(signup)
		self.assertTrue(signup.completed)
		self.assertIsNotNone(request.user)
		self.assertEqual(request.user.loginname, 'newuser')

	def test_confirm_notfound(self):
		r = self.client.get(path=url_for('signup.signup_confirm', token='notasignuptoken'), follow_redirects=True)
		dump('test_signup_confirm_notfound', r)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('signup.signup_confirm_submit', token='notasignuptoken'), follow_redirects=True, data={'password': 'notsecret'})
		dump('test_signup_confirm_submit_notfound', r)
		self.assertEqual(r.status_code, 200)

	def test_confirm_expired(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='test@example.com', password='notsecret')
		signup.created = datetime.datetime.now() - datetime.timedelta(hours=49)
		signup = refetch_signup(signup)
		r = self.client.get(path=url_for('signup.signup_confirm', token=signup.token), follow_redirects=True)
		dump('test_signup_confirm_expired', r)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('signup.signup_confirm_submit', token=signup.token), follow_redirects=True, data={'password': 'notsecret'})
		dump('test_signup_confirm_submit_expired', r)
		self.assertEqual(r.status_code, 200)

	def test_confirm_completed(self):
		signup = Signup(loginname=self.get_user().loginname, displayname='New User', mail='test@example.com', password='notsecret')
		signup.user = self.get_user()
		signup = refetch_signup(signup)
		self.assertTrue(signup.completed)
		r = self.client.get(path=url_for('signup.signup_confirm', token=signup.token), follow_redirects=True)
		dump('test_signup_confirm_completed', r)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('signup.signup_confirm_submit', token=signup.token), follow_redirects=True, data={'password': 'notsecret'})
		dump('test_signup_confirm_submit_completed', r)
		self.assertEqual(r.status_code, 200)

	def test_confirm_wrongpassword(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='test@example.com', password='notsecret')
		signup = refetch_signup(signup)
		r = self.client.post(path=url_for('signup.signup_confirm_submit', token=signup.token), follow_redirects=True, data={'password': 'wrongpassword'})
		dump('test_signup_confirm_wrongpassword', r)
		self.assertEqual(r.status_code, 200)
		self.assertFalse(signup.completed)

	def test_confirm_error(self):
		# finish returns None and error message (here: because the user already exists)
		signup = Signup(loginname=self.get_user().loginname, displayname='New User', mail='test@example.com', password='notsecret')
		signup = refetch_signup(signup)
		r = self.client.post(path=url_for('signup.signup_confirm_submit', token=signup.token), follow_redirects=True, data={'password': 'notsecret'})
		dump('test_signup_confirm_error', r)
		self.assertEqual(r.status_code, 200)
		self.assertFalse(signup.completed)

	def test_confirm_hostlimit(self):
		for i in range(20):
			signup = Signup(loginname='newuser', displayname='New User', mail='test@example.com', password='notsecret')
			signup = refetch_signup(signup)
			r = self.client.post(path=url_for('signup.signup_confirm_submit', token=signup.token), follow_redirects=True, data={'password': 'wrongpassword%d'%i})
			self.assertEqual(r.status_code, 200)
		signup = Signup(loginname='newuser', displayname='New User', mail='test@example.com', password='notsecret')
		signup = refetch_signup(signup)
		self.assertFalse(signup.completed)
		r = self.client.post(path=url_for('signup.signup_confirm_submit', token=signup.token), follow_redirects=True, data={'password': 'notsecret'})
		dump('test_signup_confirm_hostlimit', r)
		self.assertEqual(r.status_code, 200)
		self.assertFalse(signup.completed)

	def test_confirm_confirmlimit(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='test@example.com', password='notsecret')
		signup = refetch_signup(signup)
		self.assertFalse(signup.completed)
		for i in range(5):
			r = self.client.post(path=url_for('signup.signup_confirm_submit', token=signup.token), follow_redirects=True, data={'password': 'wrongpassword%d'%i})
			self.assertEqual(r.status_code, 200)
		self.assertFalse(signup.completed)
		r = self.client.post(path=url_for('signup.signup_confirm_submit', token=signup.token), follow_redirects=True, data={'password': 'notsecret'})
		dump('test_signup_confirm_confirmlimit', r)
		self.assertEqual(r.status_code, 200)
		self.assertFalse(signup.completed)

class TestSignupViewsOL(TestSignupViews):
	use_openldap = True

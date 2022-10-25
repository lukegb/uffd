import datetime

from flask import url_for, request

from uffd.database import db
from uffd.models import Signup, Role, RoleGroup, FeatureFlag
from uffd.views.session import login_get_user

from tests.utils import dump, UffdTestCase, db_flush

def refetch_signup(signup):
	db.session.add(signup)
	db.session.commit()
	id = signup.id
	db.session.expunge(signup)
	return Signup.query.get(id)

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
			data={'loginname': 'newuser', 'displayname': 'New User', 'mail': 'new@example.com',
			      'password1': 'notsecret', 'password2': 'notsecret'})
		dump('test_signup_submit', r)
		self.assertEqual(r.status_code, 200)
		db_flush()
		signups = Signup.query.filter_by(loginname='newuser').all()
		self.assertEqual(len(signups), 1)
		signup = signups[0]
		self.assertEqual(signup.loginname, 'newuser')
		self.assertEqual(signup.displayname, 'New User')
		self.assertEqual(signup.mail, 'new@example.com')
		self.assertIn(signup.token, str(self.app.last_mail.get_content()))
		self.assertTrue(signup.password.verify('notsecret'))
		self.assertTrue(signup.validate()[0])

	def test_signup_disabled(self):
		self.app.config['SELF_SIGNUP'] = False
		r = self.client.get(path=url_for('signup.signup_start'), follow_redirects=True)
		dump('test_signup_disabled', r)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(Signup.query.filter_by(loginname='newuser').all(), [])
		r = self.client.post(path=url_for('signup.signup_submit'), follow_redirects=True,
			data={'loginname': 'newuser', 'displayname': 'New User', 'mail': 'new@example.com',
			      'password1': 'notsecret', 'password2': 'notsecret'})
		dump('test_signup_submit_disabled', r)
		self.assertEqual(r.status_code, 200)
		db_flush()
		self.assertEqual(Signup.query.filter_by(loginname='newuser').all(), [])

	def test_signup_wrongpassword(self):
		r = self.client.post(path=url_for('signup.signup_submit'), follow_redirects=True,
			data={'loginname': 'newuser', 'displayname': 'New User', 'mail': 'new@example.com',
			      'password1': 'notsecret', 'password2': 'notthesame'})
		dump('test_signup_wrongpassword', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(self.app.last_mail)

	def test_signup_invalid(self):
		r = self.client.post(path=url_for('signup.signup_submit'), follow_redirects=True,
			data={'loginname': '', 'displayname': 'New User', 'mail': 'new@example.com',
			      'password1': 'notsecret', 'password2': 'notsecret'})
		dump('test_signup_invalid', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(self.app.last_mail)

	def test_signup_mailerror(self):
		self.app.config['MAIL_SKIP_SEND'] = 'fail'
		r = self.client.post(path=url_for('signup.signup_submit'), follow_redirects=True,
			data={'loginname': 'newuser', 'displayname': 'New User', 'mail': 'new@example.com',
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
			data={'loginname': 'newuser', 'displayname': 'New User', 'mail': 'new@example.com',
			      'password1': 'notsecret', 'password2': 'notsecret'})
		dump('test_signup_hostlimit', r)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(Signup.query.filter_by(loginname='newuser').all(), [])
		self.assertIsNone(self.app.last_mail)

	def test_signup_maillimit(self):
		for i in range(3):
			r = self.client.post(path=url_for('signup.signup_submit'), follow_redirects=True,
				data={'loginname': 'newuser%d'%i, 'displayname': 'New User', 'mail': 'new@example.com',
				      'password1': 'notsecret', 'password2': 'notsecret'})
			self.assertEqual(r.status_code, 200)
		self.app.last_mail = None
		r = self.client.post(path=url_for('signup.signup_submit'), follow_redirects=True,
			data={'loginname': 'newuser', 'displayname': 'New User', 'mail': 'new@example.com',
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
		signup = Signup(loginname='newuser', displayname='New User', mail='new@example.com', password='notsecret')
		signup = refetch_signup(signup)
		self.assertFalse(signup.completed)
		self.assertIsNone(login_get_user('newuser', 'notsecret'))
		r = self.client.get(path=url_for('signup.signup_confirm', signup_id=signup.id, token=signup.token), follow_redirects=True)
		dump('test_signup_confirm', r)
		self.assertEqual(r.status_code, 200)
		signup = refetch_signup(signup)
		self.assertFalse(signup.completed)
		self.assertIsNone(login_get_user('newuser', 'notsecret'))
		r = self.client.post(path=url_for('signup.signup_confirm_submit', signup_id=signup.id, token=signup.token), follow_redirects=True, data={'password': 'notsecret'})
		dump('test_signup_confirm_submit', r)
		self.assertEqual(r.status_code, 200)
		signup = refetch_signup(signup)
		self.assertTrue(signup.completed)
		self.assertEqual(signup.user.loginname, 'newuser')
		self.assertEqual(signup.user.displayname, 'New User')
		self.assertEqual(signup.user.primary_email.address, 'new@example.com')
		self.assertIsNotNone(login_get_user('newuser', 'notsecret'))

	def test_confirm_loggedin(self):
		baserole = Role(name='baserole', is_default=True)
		db.session.add(baserole)
		baserole.groups[self.get_access_group()] = RoleGroup()
		db.session.commit()
		self.login_as('user')
		signup = Signup(loginname='newuser', displayname='New User', mail='new@example.com', password='notsecret')
		signup = refetch_signup(signup)
		self.assertFalse(signup.completed)
		self.assertIsNotNone(request.user)
		self.assertEqual(request.user.loginname, self.get_user().loginname)
		r = self.client.get(path=url_for('signup.signup_confirm', signup_id=signup.id, token=signup.token), follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('signup.signup_confirm_submit', signup_id=signup.id, token=signup.token), follow_redirects=True, data={'password': 'notsecret'})
		self.assertEqual(r.status_code, 200)
		signup = refetch_signup(signup)
		self.assertTrue(signup.completed)
		self.assertIsNotNone(request.user)
		self.assertEqual(request.user.loginname, 'newuser')

	def test_confirm_notfound(self):
		r = self.client.get(path=url_for('signup.signup_confirm', signup_id=1, token='notasignuptoken'), follow_redirects=True)
		dump('test_signup_confirm_notfound', r)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('signup.signup_confirm_submit', signup_id=1, token='notasignuptoken'), follow_redirects=True, data={'password': 'notsecret'})
		dump('test_signup_confirm_submit_notfound', r)
		self.assertEqual(r.status_code, 200)

	def test_confirm_expired(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='new@example.com', password='notsecret')
		signup.created = datetime.datetime.utcnow() - datetime.timedelta(hours=49)
		signup = refetch_signup(signup)
		r = self.client.get(path=url_for('signup.signup_confirm', signup_id=signup.id, token=signup.token), follow_redirects=True)
		dump('test_signup_confirm_expired', r)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('signup.signup_confirm_submit', signup_id=signup.id, token=signup.token), follow_redirects=True, data={'password': 'notsecret'})
		dump('test_signup_confirm_submit_expired', r)
		self.assertEqual(r.status_code, 200)

	def test_confirm_completed(self):
		signup = Signup(loginname=self.get_user().loginname, displayname='New User', mail='new@example.com', password='notsecret')
		signup.user = self.get_user()
		signup = refetch_signup(signup)
		self.assertTrue(signup.completed)
		r = self.client.get(path=url_for('signup.signup_confirm', signup_id=signup.id, token=signup.token), follow_redirects=True)
		dump('test_signup_confirm_completed', r)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('signup.signup_confirm_submit', signup_id=signup.id, token=signup.token), follow_redirects=True, data={'password': 'notsecret'})
		dump('test_signup_confirm_submit_completed', r)
		self.assertEqual(r.status_code, 200)

	def test_confirm_wrongpassword(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='new@example.com', password='notsecret')
		signup = refetch_signup(signup)
		r = self.client.post(path=url_for('signup.signup_confirm_submit', signup_id=signup.id, token=signup.token), follow_redirects=True, data={'password': 'wrongpassword'})
		dump('test_signup_confirm_wrongpassword', r)
		signup = refetch_signup(signup)
		self.assertEqual(r.status_code, 200)
		self.assertFalse(signup.completed)

	def test_confirm_error(self):
		# finish returns None and error message (here: because the user already exists)
		signup = Signup(loginname=self.get_user().loginname, displayname='New User', mail='new@example.com', password='notsecret')
		signup = refetch_signup(signup)
		r = self.client.post(path=url_for('signup.signup_confirm_submit', signup_id=signup.id, token=signup.token), follow_redirects=True, data={'password': 'notsecret'})
		dump('test_signup_confirm_error', r)
		signup = refetch_signup(signup)
		self.assertEqual(r.status_code, 200)
		self.assertFalse(signup.completed)

	def test_confirm_error_email_uniqueness(self):
		FeatureFlag.unique_email_addresses.enable()
		db.session.commit()
		# finish returns None and error message (here: because the email address already exists)
		# This case is interesting, because the error also invalidates the ORM session
		signup = Signup(loginname='newuser', displayname='New User', mail='test@example.com', password='notsecret')
		db.session.add(signup)
		db.session.commit()
		signup_id = signup.id
		r = self.client.post(path=url_for('signup.signup_confirm_submit', signup_id=signup.id, token=signup.token), follow_redirects=True, data={'password': 'notsecret'})
		dump('test_signup_confirm_error_email_uniqueness', r)
		self.assertEqual(r.status_code, 200)
		signup = Signup.query.get(signup_id)
		self.assertFalse(signup.completed)

	def test_confirm_hostlimit(self):
		for i in range(20):
			signup = Signup(loginname='newuser', displayname='New User', mail='new@example.com', password='notsecret')
			signup = refetch_signup(signup)
			r = self.client.post(path=url_for('signup.signup_confirm_submit', signup_id=signup.id, token=signup.token), follow_redirects=True, data={'password': 'wrongpassword%d'%i})
			self.assertEqual(r.status_code, 200)
		signup = Signup(loginname='newuser', displayname='New User', mail='new@example.com', password='notsecret')
		signup = refetch_signup(signup)
		self.assertFalse(signup.completed)
		r = self.client.post(path=url_for('signup.signup_confirm_submit', signup_id=signup.id, token=signup.token), follow_redirects=True, data={'password': 'notsecret'})
		dump('test_signup_confirm_hostlimit', r)
		self.assertEqual(r.status_code, 200)
		self.assertFalse(signup.completed)

	def test_confirm_confirmlimit(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='new@example.com', password='notsecret')
		signup = refetch_signup(signup)
		self.assertFalse(signup.completed)
		for i in range(5):
			r = self.client.post(path=url_for('signup.signup_confirm_submit', signup_id=signup.id, token=signup.token), follow_redirects=True, data={'password': 'wrongpassword%d'%i})
			self.assertEqual(r.status_code, 200)
		self.assertFalse(signup.completed)
		r = self.client.post(path=url_for('signup.signup_confirm_submit', signup_id=signup.id, token=signup.token), follow_redirects=True, data={'password': 'notsecret'})
		dump('test_signup_confirm_confirmlimit', r)
		self.assertEqual(r.status_code, 200)
		self.assertFalse(signup.completed)

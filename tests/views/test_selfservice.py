import datetime
import re

from flask import url_for, request

from uffd.database import db
from uffd.models import PasswordToken, UserEmail, Role, RoleGroup, Service, ServiceUser

from tests.utils import dump, UffdTestCase

class TestSelfservice(UffdTestCase):
	def test_index(self):
		self.login_as('user')
		r = self.client.get(path=url_for('selfservice.index'))
		dump('selfservice_index', r)
		self.assertEqual(r.status_code, 200)
		user = request.user
		self.assertIn(user.displayname.encode(), r.data)
		self.assertIn(user.loginname.encode(), r.data)
		self.assertIn(user.primary_email.address.encode(), r.data)

	def test_update_displayname(self):
		self.login_as('user')
		user = request.user
		r = self.client.post(path=url_for('selfservice.update_profile'),
			data={'displayname': 'New Display Name'},
			follow_redirects=True)
		dump('update_displayname', r)
		self.assertEqual(r.status_code, 200)
		_user = request.user
		self.assertEqual(_user.displayname, 'New Display Name')

	def test_update_displayname_invalid(self):
		self.login_as('user')
		user = request.user
		r = self.client.post(path=url_for('selfservice.update_profile'),
			data={'displayname': ''},
			follow_redirects=True)
		dump('update_displayname_invalid', r)
		self.assertEqual(r.status_code, 200)
		_user = request.user
		self.assertNotEqual(_user.displayname, '')

	def test_add_email(self):
		self.login_as('user')
		r = self.client.post(path=url_for('selfservice.add_email'),
			data={'address': 'new@example.com'},
			follow_redirects=True)
		dump('selfservice_add_email', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn('new@example.com', self.app.last_mail['To'])
		m = re.search(r'/email/([0-9]+)/verify/(.*)', str(self.app.last_mail.get_content()))
		email_id, secret = m.groups()
		email = UserEmail.query.get(email_id)
		self.assertEqual(email.user, request.user)
		self.assertEqual(email.address, 'new@example.com')
		self.assertFalse(email.verified)
		self.assertFalse(email.verification_expired)
		self.assertTrue(email.verification_secret.verify(secret))

	def test_add_email_duplicate(self):
		self.login_as('user')
		r = self.client.post(path=url_for('selfservice.add_email'),
			data={'address': 'test@example.com'},
			follow_redirects=True)
		dump('selfservice_add_email_duplicate', r)
		self.assertFalse(hasattr(self.app, 'last_mail'))
		self.assertEqual(len(self.get_user().all_emails), 1)
		self.assertEqual(UserEmail.query.filter_by(user=None).all(), [])

	def test_verify_email(self):
		self.login_as('user')
		email = UserEmail(user=self.get_user(), address='new@example.com')
		secret = email.start_verification()
		db.session.add(email)
		db.session.commit()
		email_id = email.id
		r = self.client.get(path=url_for('selfservice.verify_email', email_id=email_id, secret=secret), follow_redirects=True)
		dump('selfservice_verify_email', r)
		self.assertEqual(r.status_code, 200)
		email = UserEmail.query.get(email_id)
		self.assertTrue(email.verified)
		self.assertEqual(self.get_user().primary_email.address, 'test@example.com')

	def test_verify_email_notfound(self):
		self.login_as('user')
		r = self.client.get(path=url_for('selfservice.verify_email', email_id=2342, secret='invalidsecret'), follow_redirects=True)
		dump('selfservice_verify_email_notfound', r)

	def test_verify_email_wrong_user(self):
		self.login_as('user')
		email = UserEmail(user=self.get_admin(), address='new@example.com')
		secret = email.start_verification()
		db.session.add(email)
		db.session.commit()
		r = self.client.get(path=url_for('selfservice.verify_email', email_id=email.id, secret=secret), follow_redirects=True)
		dump('selfservice_verify_email_wrong_user', r)
		self.assertFalse(email.verified)

	def test_verify_email_wrong_secret(self):
		self.login_as('user')
		email = UserEmail(user=self.get_user(), address='new@example.com')
		secret = email.start_verification()
		db.session.add(email)
		db.session.commit()
		r = self.client.get(path=url_for('selfservice.verify_email', email_id=email.id, secret='invalidsecret'), follow_redirects=True)
		dump('selfservice_verify_email_wrong_secret', r)
		self.assertFalse(email.verified)

	def test_verify_email_expired(self):
		self.login_as('user')
		email = UserEmail(user=self.get_user(), address='new@example.com')
		secret = email.start_verification()
		email.verification_expires = datetime.datetime.utcnow() - datetime.timedelta(days=1)
		db.session.add(email)
		db.session.commit()
		r = self.client.get(path=url_for('selfservice.verify_email', email_id=email.id, secret='invalidsecret'), follow_redirects=True)
		dump('selfservice_verify_email_expired', r)
		self.assertFalse(email.verified)

	def test_verify_email_legacy(self):
		self.login_as('user')
		email = UserEmail(
			user=self.get_user(),
			address='new@example.com',
			verification_legacy_id=1337,
			_verification_secret='{PLAIN}ZgvsUs2bZjr9Whpy1la7Q0PHbhjmpXtNdH1mCmDbQP7',
			verification_expires=datetime.datetime.utcnow()+datetime.timedelta(days=1)
		)
		db.session.add(email)
		db.session.commit()
		email_id = email.id
		r = self.client.get(path=f'/self/token/mail_verification/1337/ZgvsUs2bZjr9Whpy1la7Q0PHbhjmpXtNdH1mCmDbQP7', follow_redirects=True)
		dump('selfservice_verify_email_legacy', r)
		self.assertEqual(r.status_code, 200)
		email = UserEmail.query.get(email_id)
		self.assertTrue(email.verified)
		self.assertEqual(self.get_user().primary_email, email)

	def test_retry_email_verification(self):
		self.login_as('user')
		email = UserEmail(user=self.get_user(), address='new@example.com')
		old_secret = email.start_verification()
		db.session.add(email)
		db.session.commit()
		r = self.client.get(path=url_for('selfservice.retry_email_verification', email_id=email.id), follow_redirects=True)
		dump('selfservice_retry_email_verification', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn('new@example.com', self.app.last_mail['To'])
		m = re.search(r'/email/([0-9]+)/verify/(.*)', str(self.app.last_mail.get_content()))
		email_id, secret = m.groups()
		email = UserEmail.query.get(email_id)
		self.assertEqual(email.user, request.user)
		self.assertEqual(email.address, 'new@example.com')
		self.assertFalse(email.verified)
		self.assertFalse(email.verification_expired)
		self.assertTrue(email.verification_secret.verify(secret))
		self.assertFalse(email.verification_secret.verify(old_secret))

	def test_delete_email(self):
		self.login_as('user')
		email = UserEmail(user=self.get_user(), address='new@example.com', verified=True)
		db.session.add(email)
		self.get_user().recovery_email = email
		db.session.commit()
		r = self.client.post(path=url_for('selfservice.delete_email', email_id=email.id), follow_redirects=True)
		dump('selfservice_delete_email', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(UserEmail.query.filter_by(address='new@example.com').first())
		self.assertIsNone(self.get_user().recovery_email)
		self.assertEqual(self.get_user().primary_email.address, 'test@example.com')

	def test_delete_email_invalid(self):
		self.login_as('user')
		r = self.client.post(path=url_for('selfservice.delete_email', email_id=2324), follow_redirects=True)
		self.assertEqual(r.status_code, 404)

	def test_delete_email_primary(self):
		self.login_as('user')
		r = self.client.post(path=url_for('selfservice.delete_email', email_id=request.user.primary_email.id), follow_redirects=True)
		dump('selfservice_delete_email_primary', r)
		self.assertEqual(self.get_user().primary_email.address, 'test@example.com')

	def test_update_email_preferences(self):
		self.login_as('user')
		user_id = self.get_user().id
		email = UserEmail(user=self.get_user(), address='new@example.com', verified=True)
		db.session.add(email)
		service = Service(name='service', enable_email_preferences=True)
		db.session.add(service)
		db.session.commit()
		email_id = email.id
		service_id = service.id
		old_email_id = self.get_user().primary_email.id
		r = self.client.post(path=url_for('selfservice.update_email_preferences'),
			data={'primary_email': str(email_id), 'recovery_email': 'primary'},
			follow_redirects=True)
		dump('selfservice_update_email_preferences', r)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(self.get_user().primary_email.id, email.id)
		self.assertIsNone(self.get_user().recovery_email)
		r = self.client.post(path=url_for('selfservice.update_email_preferences'),
			data={'primary_email': str(old_email_id), 'recovery_email': str(email_id)},
			follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(self.get_user().primary_email.id, old_email_id)
		self.assertEqual(self.get_user().recovery_email.id, email_id)
		r = self.client.post(path=url_for('selfservice.update_email_preferences'),
			data={'primary_email': str(old_email_id), 'recovery_email': 'primary', f'service_{service_id}_email': 'primary'},
			follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(ServiceUser.query.get((service_id, user_id)).service_email)
		r = self.client.post(path=url_for('selfservice.update_email_preferences'),
			data={'primary_email': str(old_email_id), 'recovery_email': 'primary', f'service_{service_id}_email': str(email_id)},
			follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(ServiceUser.query.get((service_id, user_id)).service_email.id, email_id)

	def test_update_email_preferences_unverified(self):
		self.login_as('user')
		user_id = self.get_user().id
		email = UserEmail(user=self.get_user(), address='new@example.com')
		db.session.add(email)
		service = Service(name='service', enable_email_preferences=True)
		db.session.add(service)
		db.session.commit()
		email_id = email.id
		service_id = service.id
		old_email_id = self.get_user().primary_email.id
		with self.assertRaises(Exception):
			r = self.client.post(path=url_for('selfservice.update_email_preferences'),
				data={'primary_email': str(email_id), 'recovery_email': 'primary'},
				follow_redirects=True)
		self.assertEqual(self.get_user().primary_email.address, 'test@example.com')
		with self.assertRaises(Exception):
			r = self.client.post(path=url_for('selfservice.update_email_preferences'),
				data={'primary_email': str(old_email_id), 'recovery_email': str(email_id)},
				follow_redirects=True)
		self.assertIsNone(self.get_user().recovery_email)
		with self.assertRaises(Exception):
			r = self.client.post(path=url_for('selfservice.update_email_preferences'),
				data={'primary_email': str(old_email_id), 'recovery_email': 'primary', f'service_{service_id}_email': str(email_id)},
				follow_redirects=True)
		self.assertIsNone(ServiceUser.query.get((service_id, user_id)).service_email)

	def test_update_email_preferences_invalid(self):
		self.login_as('user')
		user_id = self.get_user().id
		email = UserEmail(user=self.get_user(), address='new@example.com', verified=True)
		db.session.add(email)
		service = Service(name='service', enable_email_preferences=True)
		db.session.add(service)
		db.session.commit()
		with self.assertRaises(Exception):
			r = self.client.post(path=url_for('selfservice.update_email_preferences'),
				data={'primary_email': str(email.id), 'recovery_email': '2342'},
				follow_redirects=True)
		with self.assertRaises(Exception):
			r = self.client.post(path=url_for('selfservice.update_email_preferences'),
				data={'primary_email': str(email.id), 'recovery_email': 'primary', f'service_{service_id}_email': '2342'},
				follow_redirects=True)
		with self.assertRaises(Exception):
			r = self.client.post(path=url_for('selfservice.update_email_preferences'),
				data={'primary_email': 'primary', 'recovery_email': 'primary'},
				follow_redirects=True)
		with self.assertRaises(Exception):
			r = self.client.post(path=url_for('selfservice.update_email_preferences'),
				data={'primary_email': '2342', 'recovery_email': 'primary'},
				follow_redirects=True)

	def test_change_password(self):
		self.login_as('user')
		user = request.user
		r = self.client.post(path=url_for('selfservice.change_password'),
			data={'password1': 'newpassword', 'password2': 'newpassword'},
			follow_redirects=True)
		dump('change_password', r)
		self.assertEqual(r.status_code, 200)
		_user = request.user
		self.assertTrue(_user.password.verify('newpassword'))

	def test_change_password_invalid(self):
		self.login_as('user')
		user = request.user
		r = self.client.post(path=url_for('selfservice.change_password'),
			data={'password1': 'shortpw', 'password2': 'shortpw'},
			follow_redirects=True)
		dump('change_password_invalid', r)
		self.assertEqual(r.status_code, 200)
		_user = request.user
		self.assertFalse(_user.password.verify('shortpw'))
		self.assertTrue(_user.password.verify('userpassword'))

	# Regression test for #100 (login not possible if password contains character disallowed by SASLprep)
	def test_change_password_samlprep_invalid(self):
		self.login_as('user')
		user = request.user
		r = self.client.post(path=url_for('selfservice.change_password'),
			data={'password1': 'shortpw\n', 'password2': 'shortpw\n'},
			follow_redirects=True)
		dump('change_password_samlprep_invalid', r)
		self.assertEqual(r.status_code, 200)
		_user = request.user
		self.assertFalse(_user.password.verify('shortpw\n'))
		self.assertTrue(_user.password.verify('userpassword'))

	def test_change_password_mismatch(self):
		self.login_as('user')
		user = request.user
		r = self.client.post(path=url_for('selfservice.change_password'),
			data={'password1': 'newpassword1', 'password2': 'newpassword2'},
			follow_redirects=True)
		dump('change_password_mismatch', r)
		self.assertEqual(r.status_code, 200)
		_user = request.user
		self.assertFalse(_user.password.verify('newpassword1'))
		self.assertFalse(_user.password.verify('newpassword2'))
		self.assertTrue(_user.password.verify('userpassword'))

	def test_leave_role(self):
		baserole = Role(name='baserole', is_default=True)
		db.session.add(baserole)
		baserole.groups[self.get_access_group()] = RoleGroup()
		role1 = Role(name='testrole1')
		role2 = Role(name='testrole2')
		db.session.add(role1)
		db.session.add(role2)
		self.get_user().roles = [role1, role2]
		db.session.commit()
		roleid = role1.id
		self.login_as('user')
		r = self.client.post(path=url_for('selfservice.leave_role', roleid=roleid), follow_redirects=True)
		dump('leave_role', r)
		self.assertEqual(r.status_code, 200)
		_user = self.get_user()
		self.assertEqual(len(_user.roles), 1)
		self.assertEqual(list(_user.roles)[0].name, 'testrole2')

	def test_forgot_password(self):
		user = self.get_user()
		r = self.client.get(path=url_for('selfservice.forgot_password'))
		dump('forgot_password', r)
		self.assertEqual(r.status_code, 200)
		user = self.get_user()
		r = self.client.post(path=url_for('selfservice.forgot_password'),
			data={'loginname': user.loginname, 'mail': user.primary_email.address}, follow_redirects=True)
		dump('forgot_password_submit', r)
		self.assertEqual(r.status_code, 200)
		token = PasswordToken.query.filter(PasswordToken.user == user).first()
		self.assertIsNotNone(token)
		self.assertIn(token.token, str(self.app.last_mail.get_content()))

	def test_forgot_password_wrong_user(self):
		user = self.get_user()
		r = self.client.get(path=url_for('selfservice.forgot_password'))
		self.assertEqual(r.status_code, 200)
		user = self.get_user()
		r = self.client.post(path=url_for('selfservice.forgot_password'),
			data={'loginname': 'not_a_user', 'mail': user.primary_email.address}, follow_redirects=True)
		dump('forgot_password_submit_wrong_user', r)
		self.assertEqual(r.status_code, 200)
		self.assertFalse(hasattr(self.app, 'last_mail'))
		self.assertEqual(len(PasswordToken.query.all()), 0)

	def test_forgot_password_wrong_email(self):
		user = self.get_user()
		r = self.client.get(path=url_for('selfservice.forgot_password'), follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('selfservice.forgot_password'),
			data={'loginname': user.loginname, 'mail': 'not_an_email@example.com'}, follow_redirects=True)
		dump('forgot_password_submit_wrong_email', r)
		self.assertEqual(r.status_code, 200)
		self.assertFalse(hasattr(self.app, 'last_mail'))
		self.assertEqual(len(PasswordToken.query.all()), 0)

	# Regression test for #31
	def test_forgot_password_invalid_user(self):
		r = self.client.post(path=url_for('selfservice.forgot_password'),
			data={'loginname': '=', 'mail': 'test@example.com'}, follow_redirects=True)
		dump('forgot_password_submit_invalid_user', r)
		self.assertEqual(r.status_code, 200)
		self.assertFalse(hasattr(self.app, 'last_mail'))
		self.assertEqual(len(PasswordToken.query.all()), 0)

	def test_token_password(self):
		user = self.get_user()
		token = PasswordToken(user=user)
		db.session.add(token)
		db.session.commit()
		self.assertFalse(token.expired)
		r = self.client.get(path=url_for('selfservice.token_password', token_id=token.id, token=token.token), follow_redirects=True)
		dump('token_password', r)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('selfservice.token_password', token_id=token.id, token=token.token),
			data={'password1': 'newpassword', 'password2': 'newpassword'}, follow_redirects=True)
		dump('token_password_submit', r)
		self.assertEqual(r.status_code, 200)
		self.assertTrue(self.get_user().password.verify('newpassword'))

	def test_token_password_emptydb(self):
		user = self.get_user()
		r = self.client.get(path=url_for('selfservice.token_password', token_id=1, token='A'*128), follow_redirects=True)
		dump('token_password_emptydb', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn(b'Link invalid or expired', r.data)
		r = self.client.post(path=url_for('selfservice.token_password', token_id=1, token='A'*128),
			data={'password1': 'newpassword', 'password2': 'newpassword'}, follow_redirects=True)
		dump('token_password_emptydb_submit', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn(b'Link invalid or expired', r.data)
		self.assertTrue(self.get_user().password.verify('userpassword'))

	def test_token_password_invalid(self):
		user = self.get_user()
		token = PasswordToken(user=user)
		db.session.add(token)
		db.session.commit()
		r = self.client.get(path=url_for('selfservice.token_password', token_id=token.id, token='A'*128), follow_redirects=True)
		dump('token_password_invalid', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn(b'Link invalid or expired', r.data)
		r = self.client.post(path=url_for('selfservice.token_password', token_id=token.id, token='A'*128),
			data={'password1': 'newpassword', 'password2': 'newpassword'}, follow_redirects=True)
		dump('token_password_invalid_submit', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn(b'Link invalid or expired', r.data)
		self.assertTrue(self.get_user().password.verify('userpassword'))

	def test_token_password_expired(self):
		user = self.get_user()
		token = PasswordToken(user=user, created=(datetime.datetime.utcnow() - datetime.timedelta(days=10)))
		db.session.add(token)
		db.session.commit()
		self.assertTrue(token.expired)
		r = self.client.get(path=url_for('selfservice.token_password', token_id=token.id, token=token.token), follow_redirects=True)
		dump('token_password_invalid_expired', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn(b'Link invalid or expired', r.data)
		r = self.client.post(path=url_for('selfservice.token_password', token_id=token.id, token=token.token),
			data={'password1': 'newpassword', 'password2': 'newpassword'}, follow_redirects=True)
		dump('token_password_invalid_expired_submit', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn(b'Link invalid or expired', r.data)
		self.assertTrue(self.get_user().password.verify('userpassword'))

	def test_token_password_different_passwords(self):
		user = self.get_user()
		token = PasswordToken(user=user)
		db.session.add(token)
		db.session.commit()
		r = self.client.get(path=url_for('selfservice.token_password', token_id=token.id, token=token.token), follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('selfservice.token_password', token_id=token.id, token=token.token),
			data={'password1': 'newpassword', 'password2': 'differentpassword'}, follow_redirects=True)
		dump('token_password_different_passwords_submit', r)
		self.assertEqual(r.status_code, 200)
		self.assertTrue(self.get_user().password.verify('userpassword'))

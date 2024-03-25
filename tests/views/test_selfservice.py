import datetime
import re
import time

from flask import url_for, request, session

from uffd.database import db
from uffd.models import PasswordToken, UserEmail, Role, RoleGroup, Service, ServiceUser, FeatureFlag, MFAMethod, RecoveryCodeMethod, TOTPMethod, WebauthnMethod
from uffd.models.mfa import _hotp

from tests.utils import dump, UffdTestCase, db_flush

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
		r = self.client.post(path=url_for('selfservice.update_profile'),
			data={'displayname': 'New Display Name'},
			follow_redirects=True)
		dump('update_displayname', r)
		self.assertEqual(r.status_code, 200)
		user = self.get_user()
		self.assertEqual(user.displayname, 'New Display Name')

	def test_update_displayname_invalid(self):
		self.login_as('user')
		r = self.client.post(path=url_for('selfservice.update_profile'),
			data={'displayname': ''},
			follow_redirects=True)
		dump('update_displayname_invalid', r)
		self.assertEqual(r.status_code, 200)
		user = self.get_user()
		self.assertNotEqual(user.displayname, '')

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
		self.assertEqual(email.user.id, request.user.id)
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
		r = self.client.get(path=url_for('selfservice.verify_email', email_id=email.id, secret=secret), follow_redirects=True)
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

	def test_verify_email_duplicate_strict_uniqueness(self):
		FeatureFlag.unique_email_addresses.enable()
		db.session.commit()
		self.login_as('user')
		email = UserEmail(user=self.get_user(), address='admin@example.com')
		secret = email.start_verification()
		db.session.add(email)
		db.session.commit()
		email_id = email.id
		r = self.client.get(path=url_for('selfservice.verify_email', email_id=email.id, secret=secret), follow_redirects=True)
		dump('selfservice_verify_email_duplicate_strict_uniqueness', r)
		email = UserEmail.query.get(email_id)
		self.assertFalse(email.verified)

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
		self.assertEqual(email.user.id, request.user.id)
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
		service = Service(name='service', enable_email_preferences=True, limit_access=False)
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
		service = Service(name='service', enable_email_preferences=True, limit_access=False)
		db.session.add(service)
		db.session.commit()
		email_id = email.id
		service_id = service.id
		old_email_id = self.get_user().primary_email.id
		with self.assertRaises(Exception):
			r = self.client.post(path=url_for('selfservice.update_email_preferences'),
				data={'primary_email': str(email_id), 'recovery_email': 'primary'},
				follow_redirects=True)
		with self.app.test_request_context():
			self.assertEqual(self.get_user().primary_email.address, 'test@example.com')
		with self.assertRaises(Exception):
			r = self.client.post(path=url_for('selfservice.update_email_preferences'),
				data={'primary_email': str(old_email_id), 'recovery_email': str(email_id)},
				follow_redirects=True)
		with self.app.test_request_context():
			self.assertIsNone(self.get_user().recovery_email)
		with self.assertRaises(Exception):
			r = self.client.post(path=url_for('selfservice.update_email_preferences'),
				data={'primary_email': str(old_email_id), 'recovery_email': 'primary', f'service_{service_id}_email': str(email_id)},
				follow_redirects=True)
		with self.app.test_request_context():
			self.assertIsNone(ServiceUser.query.get((service_id, user_id)).service_email)

	def test_update_email_preferences_invalid(self):
		self.login_as('user')
		user_id = self.get_user().id
		email = UserEmail(user=self.get_user(), address='new@example.com', verified=True)
		db.session.add(email)
		service = Service(name='service', enable_email_preferences=True, limit_access=False)
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
		r = self.client.post(path=url_for('selfservice.change_password'),
			data={'password1': 'newpassword', 'password2': 'newpassword'},
			follow_redirects=True)
		dump('change_password', r)
		self.assertEqual(r.status_code, 200)
		self.assertTrue(self.get_user().password.verify('newpassword'))

	def test_change_password_invalid(self):
		self.login_as('user')
		r = self.client.post(path=url_for('selfservice.change_password'),
			data={'password1': 'shortpw', 'password2': 'shortpw'},
			follow_redirects=True)
		dump('change_password_invalid', r)
		self.assertEqual(r.status_code, 200)
		user = self.get_user()
		self.assertFalse(user.password.verify('shortpw'))
		self.assertTrue(user.password.verify('userpassword'))

	# Regression test for #100 (login not possible if password contains character disallowed by SASLprep)
	def test_change_password_samlprep_invalid(self):
		self.login_as('user')
		r = self.client.post(path=url_for('selfservice.change_password'),
			data={'password1': 'shortpw\n', 'password2': 'shortpw\n'},
			follow_redirects=True)
		dump('change_password_samlprep_invalid', r)
		self.assertEqual(r.status_code, 200)
		user = self.get_user()
		self.assertFalse(user.password.verify('shortpw\n'))
		self.assertTrue(user.password.verify('userpassword'))

	def test_change_password_mismatch(self):
		self.login_as('user')
		r = self.client.post(path=url_for('selfservice.change_password'),
			data={'password1': 'newpassword1', 'password2': 'newpassword2'},
			follow_redirects=True)
		dump('change_password_mismatch', r)
		self.assertEqual(r.status_code, 200)
		user = self.get_user()
		self.assertFalse(user.password.verify('newpassword1'))
		self.assertFalse(user.password.verify('newpassword2'))
		self.assertTrue(user.password.verify('userpassword'))

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

	def test_forgot_password_wrong_user(self):
		user = self.get_user()
		r = self.client.get(path=url_for('selfservice.forgot_password'))
		self.assertEqual(r.status_code, 200)
		user = self.get_user()
		user.is_deactivated = True
		db.session.commit()
		r = self.client.post(path=url_for('selfservice.forgot_password'),
			data={'loginname': user.loginname, 'mail': user.primary_email.address}, follow_redirects=True)
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

def get_fido2_test_cred(self):
	try:
		from uffd.fido2_compat import AttestedCredentialData
	except ImportError:
		self.skipTest('fido2 could not be imported')
	# Example public key from webauthn spec 6.5.1.1
	return AttestedCredentialData(bytes.fromhex('00000000000000000000000000000000'+'0040'+'053cbcc9d37a61d3bac87cdcc77ee326256def08ab15775d3a720332e4101d14fae95aeee3bc9698781812e143c0597dc6e180595683d501891e9dd030454c0a'+'A501020326200121582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c'))

class TestMfaViews(UffdTestCase):
	def setUp(self):
		super().setUp()
		db.session.add(RecoveryCodeMethod(user=self.get_admin()))
		db.session.add(TOTPMethod(user=self.get_admin(), name='Admin Phone'))
		# We don't want to skip all tests only because fido2 is not installed!
		#db.session.add(WebauthnMethod(user=get_testadmin(), cred=get_fido2_test_cred(self), name='Admin FIDO2 dongle'))
		db.session.commit()

	def add_recovery_codes(self, count=10):
		user = self.get_user()
		for _ in range(count):
			db.session.add(RecoveryCodeMethod(user=user))
		db.session.commit()

	def add_totp(self):
		db.session.add(TOTPMethod(user=self.get_user(), name='My phone'))
		db.session.commit()

	def add_webauthn(self):
		db.session.add(WebauthnMethod(user=self.get_user(), cred=get_fido2_test_cred(self), name='My FIDO2 dongle'))
		db.session.commit()

	def test_setup_disabled(self):
		self.login_as('user')
		r = self.client.get(path=url_for('selfservice.setup_mfa'), follow_redirects=True)
		dump('mfa_setup_disabled', r)
		self.assertEqual(r.status_code, 200)

	def test_setup_recovery_codes(self):
		self.login_as('user')
		self.add_recovery_codes()
		r = self.client.get(path=url_for('selfservice.setup_mfa'), follow_redirects=True)
		dump('mfa_setup_only_recovery_codes', r)
		self.assertEqual(r.status_code, 200)

	def test_setup_enabled(self):
		self.login_as('user')
		self.add_recovery_codes()
		self.add_totp()
		self.add_webauthn()
		r = self.client.get(path=url_for('selfservice.setup_mfa'), follow_redirects=True)
		dump('mfa_setup_enabled', r)
		self.assertEqual(r.status_code, 200)

	def test_setup_few_recovery_codes(self):
		self.login_as('user')
		self.add_totp()
		self.add_recovery_codes(1)
		r = self.client.get(path=url_for('selfservice.setup_mfa'), follow_redirects=True)
		dump('mfa_setup_few_recovery_codes', r)
		self.assertEqual(r.status_code, 200)

	def test_setup_no_recovery_codes(self):
		self.login_as('user')
		self.add_totp()
		r = self.client.get(path=url_for('selfservice.setup_mfa'), follow_redirects=True)
		dump('mfa_setup_no_recovery_codes', r)
		self.assertEqual(r.status_code, 200)

	def test_disable(self):
		baserole = Role(name='baserole', is_default=True)
		db.session.add(baserole)
		baserole.groups[self.get_access_group()] = RoleGroup()
		db.session.commit()
		self.login_as('user')
		self.add_recovery_codes()
		self.add_totp()
		admin_methods = len(MFAMethod.query.filter_by(user=self.get_admin()).all())
		r = self.client.get(path=url_for('selfservice.disable_mfa'), follow_redirects=True)
		dump('mfa_disable', r)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('selfservice.disable_mfa_confirm'), follow_redirects=True)
		dump('mfa_disable_submit', r)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(len(MFAMethod.query.filter_by(user=request.user).all()), 0)
		self.assertEqual(len(MFAMethod.query.filter_by(user=self.get_admin()).all()), admin_methods)

	def test_disable_recovery_only(self):
		baserole = Role(name='baserole', is_default=True)
		db.session.add(baserole)
		baserole.groups[self.get_access_group()] = RoleGroup()
		db.session.commit()
		self.login_as('user')
		self.add_recovery_codes()
		admin_methods = len(MFAMethod.query.filter_by(user=self.get_admin()).all())
		self.assertNotEqual(len(MFAMethod.query.filter_by(user=request.user).all()), 0)
		r = self.client.get(path=url_for('selfservice.disable_mfa'), follow_redirects=True)
		dump('mfa_disable_recovery_only', r)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('selfservice.disable_mfa_confirm'), follow_redirects=True)
		dump('mfa_disable_recovery_only_submit', r)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(len(MFAMethod.query.filter_by(user=request.user).all()), 0)
		self.assertEqual(len(MFAMethod.query.filter_by(user=self.get_admin()).all()), admin_methods)

	def test_setup_recovery(self):
		self.login_as('user')
		self.assertEqual(len(RecoveryCodeMethod.query.filter_by(user=request.user).all()), 0)
		r = self.client.post(path=url_for('selfservice.setup_mfa_recovery'), follow_redirects=True)
		dump('mfa_setup_recovery', r)
		self.assertEqual(r.status_code, 200)
		methods = RecoveryCodeMethod.query.filter_by(user=request.user).all()
		self.assertNotEqual(len(methods), 0)
		r = self.client.post(path=url_for('selfservice.setup_mfa_recovery'), follow_redirects=True)
		dump('mfa_setup_recovery_reset', r)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(len(RecoveryCodeMethod.query.filter_by(id=methods[0].id).all()), 0)
		self.assertNotEqual(len(methods), 0)

	def test_setup_totp(self):
		self.login_as('user')
		self.add_recovery_codes()
		r = self.client.get(path=url_for('selfservice.setup_mfa_totp', name='My TOTP Authenticator'), follow_redirects=True)
		dump('mfa_setup_totp', r)
		self.assertEqual(r.status_code, 200)
		self.assertNotEqual(len(session.get('mfa_totp_key', '')), 0)

	def test_setup_totp_without_recovery(self):
		self.login_as('user')
		r = self.client.get(path=url_for('selfservice.setup_mfa_totp', name='My TOTP Authenticator'), follow_redirects=True)
		dump('mfa_setup_totp_without_recovery', r)
		self.assertEqual(r.status_code, 200)

	def test_setup_totp_finish(self):
		baserole = Role(name='baserole', is_default=True)
		db.session.add(baserole)
		baserole.groups[self.get_access_group()] = RoleGroup()
		db.session.commit()
		self.login_as('user')
		self.add_recovery_codes()
		self.assertEqual(len(TOTPMethod.query.filter_by(user=request.user).all()), 0)
		r = self.client.get(path=url_for('selfservice.setup_mfa_totp', name='My TOTP Authenticator'), follow_redirects=True)
		method = TOTPMethod(request.user, key=session.get('mfa_totp_key', ''))
		code = _hotp(int(time.time()/30), method.raw_key)
		r = self.client.post(path=url_for('selfservice.setup_mfa_totp_finish', name='My TOTP Authenticator'), data={'code': code}, follow_redirects=True)
		dump('mfa_setup_totp_finish', r)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(len(TOTPMethod.query.filter_by(user=request.user).all()), 1)

	def test_setup_totp_finish_without_recovery(self):
		self.login_as('user')
		self.assertEqual(len(TOTPMethod.query.filter_by(user=request.user).all()), 0)
		r = self.client.get(path=url_for('selfservice.setup_mfa_totp', name='My TOTP Authenticator'), follow_redirects=True)
		method = TOTPMethod(request.user, key=session.get('mfa_totp_key', ''))
		code = _hotp(int(time.time()/30), method.raw_key)
		r = self.client.post(path=url_for('selfservice.setup_mfa_totp_finish', name='My TOTP Authenticator'), data={'code': code}, follow_redirects=True)
		dump('mfa_setup_totp_finish_without_recovery', r)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(len(TOTPMethod.query.filter_by(user=request.user).all()), 0)

	def test_setup_totp_finish_wrong_code(self):
		self.login_as('user')
		self.add_recovery_codes()
		self.assertEqual(len(TOTPMethod.query.filter_by(user=request.user).all()), 0)
		r = self.client.get(path=url_for('selfservice.setup_mfa_totp', name='My TOTP Authenticator'), follow_redirects=True)
		method = TOTPMethod(request.user, key=session.get('mfa_totp_key', ''))
		code = _hotp(int(time.time()/30), method.raw_key)
		code = str(int(code[0])+1)[-1] + code[1:]
		r = self.client.post(path=url_for('selfservice.setup_mfa_totp_finish', name='My TOTP Authenticator'), data={'code': code}, follow_redirects=True)
		dump('mfa_setup_totp_finish_wrong_code', r)
		self.assertEqual(r.status_code, 200)
		db_flush()
		self.assertEqual(len(TOTPMethod.query.filter_by(user=request.user).all()), 0)

	def test_setup_totp_finish_empty_code(self):
		self.login_as('user')
		self.add_recovery_codes()
		self.assertEqual(len(TOTPMethod.query.filter_by(user=request.user).all()), 0)
		r = self.client.get(path=url_for('selfservice.setup_mfa_totp', name='My TOTP Authenticator'), follow_redirects=True)
		r = self.client.post(path=url_for('selfservice.setup_mfa_totp_finish', name='My TOTP Authenticator'), data={'code': ''}, follow_redirects=True)
		dump('mfa_setup_totp_finish_empty_code', r)
		self.assertEqual(r.status_code, 200)
		db_flush()
		self.assertEqual(len(TOTPMethod.query.filter_by(user=request.user).all()), 0)

	def test_delete_totp(self):
		baserole = Role(name='baserole', is_default=True)
		db.session.add(baserole)
		baserole.groups[self.get_access_group()] = RoleGroup()
		db.session.commit()
		self.login_as('user')
		self.add_recovery_codes()
		self.add_totp()
		method = TOTPMethod(request.user, name='test')
		db.session.add(method)
		db.session.commit()
		self.assertEqual(len(TOTPMethod.query.filter_by(user=request.user).all()), 2)
		r = self.client.get(path=url_for('selfservice.delete_mfa_totp', id=method.id), follow_redirects=True)
		dump('mfa_delete_totp', r)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(len(TOTPMethod.query.filter_by(id=method.id).all()), 0)
		self.assertEqual(len(TOTPMethod.query.filter_by(user=request.user).all()), 1)

	# TODO: webauthn setup tests

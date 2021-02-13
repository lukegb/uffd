import datetime
import unittest

from flask import url_for

# These imports are required, because otherwise we get circular imports?!
from uffd import ldap, user

from uffd.session.views import get_current_user
from uffd.selfservice.models import MailToken, PasswordToken
from uffd.user.models import User
from uffd import create_app, db, ldap

from utils import dump, UffdTestCase

def get_ldap_password():
	conn = ldap.get_conn()
	conn.search('uid=testuser,ou=users,dc=example,dc=com', '(objectClass=person)')
	return conn.entries[0]['userPassword']

class TestSelfservice(UffdTestCase):
	def setUpApp(self):
		self.app.config['MAIL_SKIP_SEND'] = True

	def login(self):
		self.client.post(path=url_for('session.login'),
			data={'loginname': 'testuser', 'password': 'userpassword'}, follow_redirects=True)

	def test_index(self):
		self.login()
		r = self.client.get(path=url_for('selfservice.index'))
		dump('selfservice_index', r)
		self.assertEqual(r.status_code, 200)
		user = get_current_user()
		self.assertIn(user.displayname.encode(), r.data)
		self.assertIn(user.loginname.encode(), r.data)
		self.assertIn(user.mail.encode(), r.data)

	def test_update_displayname(self):
		self.login()
		user = get_current_user()
		r = self.client.post(path=url_for('selfservice.update'),
			data={'displayname': 'New Display Name', 'mail': user.mail, 'password': '', 'password1': ''},
			follow_redirects=True)
		dump('update_displayname', r)
		self.assertEqual(r.status_code, 200)
		_user = get_current_user()
		self.assertEqual(_user.displayname, 'New Display Name')

	def test_update_displayname_invalid(self):
		self.login()
		user = get_current_user()
		r = self.client.post(path=url_for('selfservice.update'),
			data={'displayname': '', 'mail': user.mail, 'password': '', 'password1': ''},
			follow_redirects=True)
		dump('update_displayname_invalid', r)
		self.assertEqual(r.status_code, 200)
		_user = get_current_user()
		self.assertNotEqual(_user.displayname, '')

	def test_update_mail(self):
		self.login()
		user = get_current_user()
		r = self.client.post(path=url_for('selfservice.update'),
			data={'displayname': user.displayname, 'mail': 'newemail@example.com', 'password': '', 'password1': ''},
			follow_redirects=True)
		dump('update_mail', r)
		self.assertEqual(r.status_code, 200)
		_user = get_current_user()
		self.assertNotEqual(_user.mail, 'newemail@example.com')
		token = MailToken.query.filter(MailToken.loginname == user.loginname).first()
		self.assertEqual(token.newmail, 'newemail@example.com')
		self.assertIn(token.token, str(self.app.last_mail.get_content()))
		r = self.client.get(path=url_for('selfservice.token_mail', token=token.token), follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		_user = get_current_user()
		self.assertEqual(_user.mail, 'newemail@example.com')

	def test_update_mail_sendfailure(self):
		self.app.config['MAIL_SKIP_SEND'] = 'fail'
		self.login()
		user = get_current_user()
		r = self.client.post(path=url_for('selfservice.update'),
			data={'displayname': user.displayname, 'mail': 'newemail@example.com', 'password': '', 'password1': ''},
			follow_redirects=True)
		dump('update_mail_sendfailure', r)
		self.assertEqual(r.status_code, 200)
		_user = get_current_user()
		self.assertNotEqual(_user.mail, 'newemail@example.com')
		# Maybe also check that there is no new token in the db

	def test_token_mail_emptydb(self):
		self.login()
		user = get_current_user()
		r = self.client.get(path=url_for('selfservice.token_mail', token='A'*128), follow_redirects=True)
		dump('token_mail_emptydb', r)
		self.assertEqual(r.status_code, 200)
		_user = get_current_user()
		self.assertEqual(_user.mail, user.mail)

	def test_token_mail_invalid(self):
		self.login()
		user = get_current_user()
		db.session.add(MailToken(loginname=user.loginname, newmail='newusermail@example.com'))
		db.session.commit()
		r = self.client.get(path=url_for('selfservice.token_mail', token='A'*128), follow_redirects=True)
		dump('token_mail_invalid', r)
		self.assertEqual(r.status_code, 200)
		_user = get_current_user()
		self.assertEqual(_user.mail, user.mail)

	@unittest.skip('See #26')
	def test_token_mail_wrong_user(self):
		self.login()
		user = get_current_user()
		admin_user = User.from_ldap_dn('uid=testadmin,ou=users,dc=example,dc=com')
		db.session.add(MailToken(loginname=user.loginname, newmail='newusermail@example.com'))
		admin_token = MailToken(loginname='testadmin', newmail='newadminmail@example.com')
		db.session.add(admin_token)
		db.session.commit()
		r = self.client.get(path=url_for('selfservice.token_mail', token=admin_token.token), follow_redirects=True)
		dump('token_mail_wrong_user', r)
		self.assertEqual(r.status_code, 200)
		_user = get_current_user()
		_admin_user = User.from_ldap_dn('uid=testadmin,ou=users,dc=example,dc=com')
		self.assertEqual(_user.mail, user.mail)
		self.assertEqual(_admin_user.mail, admin_user.mail)

	def test_token_mail_expired(self):
		self.login()
		user = get_current_user()
		token = MailToken(loginname=user.loginname, newmail='newusermail@example.com',
			created=(datetime.datetime.now() - datetime.timedelta(days=10)))
		db.session.add(token)
		db.session.commit()
		r = self.client.get(path=url_for('selfservice.token_mail', token=token.token), follow_redirects=True)
		dump('token_mail_expired', r)
		self.assertEqual(r.status_code, 200)
		_user = get_current_user()
		self.assertEqual(_user.mail, user.mail)
		tokens = MailToken.query.filter(MailToken.loginname == user.loginname).all()
		self.assertEqual(len(tokens), 0)

	def test_forgot_password(self):
		user = User.from_ldap_dn('uid=testuser,ou=users,dc=example,dc=com')
		r = self.client.get(path=url_for('selfservice.forgot_password'))
		dump('forgot_password', r)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('selfservice.forgot_password'),
			data={'loginname': user.loginname, 'mail': user.mail}, follow_redirects=True)
		dump('forgot_password_submit', r)
		self.assertEqual(r.status_code, 200)
		token = PasswordToken.query.filter(PasswordToken.loginname == user.loginname).first()
		self.assertIsNotNone(token)
		self.assertIn(token.token, str(self.app.last_mail.get_content()))

	def test_forgot_password_wrong_user(self):
		user = User.from_ldap_dn('uid=testuser,ou=users,dc=example,dc=com')
		r = self.client.get(path=url_for('selfservice.forgot_password'))
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('selfservice.forgot_password'),
			data={'loginname': 'not_a_user', 'mail': user.mail}, follow_redirects=True)
		dump('forgot_password_submit_wrong_user', r)
		self.assertEqual(r.status_code, 200)
		self.assertFalse(hasattr(self.app, 'last_mail'))
		self.assertEqual(len(PasswordToken.query.all()), 0)

	def test_forgot_password_wrong_email(self):
		user = User.from_ldap_dn('uid=testuser,ou=users,dc=example,dc=com')
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
		user = User.from_ldap_dn('uid=testuser,ou=users,dc=example,dc=com')
		oldpw = get_ldap_password()
		token = PasswordToken(loginname=user.loginname)
		db.session.add(token)
		db.session.commit()
		r = self.client.get(path=url_for('selfservice.token_password', token=token.token), follow_redirects=True)
		dump('token_password', r)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('selfservice.token_password', token=token.token),
			data={'password1': 'newpassword', 'password2': 'newpassword'}, follow_redirects=True)
		dump('token_password_submit', r)
		self.assertEqual(r.status_code, 200)
		self.assertNotEqual(oldpw, get_ldap_password())
		# TODO: Verify that the new password is actually correct
		self.assertEqual(len(PasswordToken.query.all()), 0)

	def test_token_password_emptydb(self):
		user = User.from_ldap_dn('uid=testuser,ou=users,dc=example,dc=com')
		oldpw = get_ldap_password()
		r = self.client.get(path=url_for('selfservice.token_password', token='A'*128), follow_redirects=True)
		dump('token_password_emptydb', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn(b'Token expired, please try again', r.data)
		r = self.client.post(path=url_for('selfservice.token_password', token='A'*128),
			data={'password1': 'newpassword', 'password2': 'newpassword'}, follow_redirects=True)
		dump('token_password_emptydb_submit', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn(b'Token expired, please try again', r.data)
		self.assertEqual(oldpw, get_ldap_password())

	def test_token_password_invalid(self):
		user = User.from_ldap_dn('uid=testuser,ou=users,dc=example,dc=com')
		oldpw = get_ldap_password()
		token = PasswordToken(loginname=user.loginname)
		db.session.add(token)
		db.session.commit()
		r = self.client.get(path=url_for('selfservice.token_password', token='A'*128), follow_redirects=True)
		dump('token_password_invalid', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn(b'Token expired, please try again', r.data)
		r = self.client.post(path=url_for('selfservice.token_password', token='A'*128),
			data={'password1': 'newpassword', 'password2': 'newpassword'}, follow_redirects=True)
		dump('token_password_invalid_submit', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn(b'Token expired, please try again', r.data)
		self.assertEqual(oldpw, get_ldap_password())

	def test_token_password_expired(self):
		user = User.from_ldap_dn('uid=testuser,ou=users,dc=example,dc=com')
		oldpw = get_ldap_password()
		token = PasswordToken(loginname=user.loginname,
			created=(datetime.datetime.now() - datetime.timedelta(days=10)))
		db.session.add(token)
		db.session.commit()
		r = self.client.get(path=url_for('selfservice.token_password', token=token.token), follow_redirects=True)
		dump('token_password_invalid_expired', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn(b'Token expired, please try again', r.data)
		r = self.client.post(path=url_for('selfservice.token_password', token=token.token),
			data={'password1': 'newpassword', 'password2': 'newpassword'}, follow_redirects=True)
		dump('token_password_invalid_expired_submit', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn(b'Token expired, please try again', r.data)
		self.assertEqual(oldpw, get_ldap_password())

	def test_token_password_different_passwords(self):
		user = User.from_ldap_dn('uid=testuser,ou=users,dc=example,dc=com')
		oldpw = get_ldap_password()
		token = PasswordToken(loginname=user.loginname)
		db.session.add(token)
		db.session.commit()
		r = self.client.get(path=url_for('selfservice.token_password', token=token.token), follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('selfservice.token_password', token=token.token),
			data={'password1': 'newpassword', 'password2': 'differentpassword'}, follow_redirects=True)
		dump('token_password_different_passwords_submit', r)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(oldpw, get_ldap_password())

class TestSelfserviceOL(TestSelfservice):
	use_openldap = True

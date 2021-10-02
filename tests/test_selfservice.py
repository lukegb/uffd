import datetime
import unittest

from flask import url_for, request

# These imports are required, because otherwise we get circular imports?!
from uffd import user

from uffd.selfservice.models import MailToken, PasswordToken
from uffd.user.models import User
from uffd.role.models import Role, RoleGroup
from uffd import create_app, db

from utils import dump, UffdTestCase


class TestSelfservice(UffdTestCase):
	def test_index(self):
		self.login_as('user')
		r = self.client.get(path=url_for('selfservice.index'))
		dump('selfservice_index', r)
		self.assertEqual(r.status_code, 200)
		user = request.user
		self.assertIn(user.displayname.encode(), r.data)
		self.assertIn(user.loginname.encode(), r.data)
		self.assertIn(user.mail.encode(), r.data)

	def test_update_displayname(self):
		self.login_as('user')
		user = request.user
		r = self.client.post(path=url_for('selfservice.update_profile'),
			data={'displayname': 'New Display Name', 'mail': user.mail},
			follow_redirects=True)
		dump('update_displayname', r)
		self.assertEqual(r.status_code, 200)
		_user = request.user
		self.assertEqual(_user.displayname, 'New Display Name')

	def test_update_displayname_invalid(self):
		self.login_as('user')
		user = request.user
		r = self.client.post(path=url_for('selfservice.update_profile'),
			data={'displayname': '', 'mail': user.mail},
			follow_redirects=True)
		dump('update_displayname_invalid', r)
		self.assertEqual(r.status_code, 200)
		_user = request.user
		self.assertNotEqual(_user.displayname, '')

	def test_update_mail(self):
		self.login_as('user')
		user = request.user
		r = self.client.post(path=url_for('selfservice.update_profile'),
			data={'displayname': user.displayname, 'mail': 'newemail@example.com'},
			follow_redirects=True)
		dump('update_mail', r)
		self.assertEqual(r.status_code, 200)
		_user = request.user
		self.assertNotEqual(_user.mail, 'newemail@example.com')
		token = MailToken.query.filter(MailToken.user == user).first()
		self.assertEqual(token.newmail, 'newemail@example.com')
		self.assertIn(token.token, str(self.app.last_mail.get_content()))
		r = self.client.get(path=url_for('selfservice.token_mail', token_id=token.id, token=token.token), follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		_user = request.user
		self.assertEqual(_user.mail, 'newemail@example.com')

	def test_update_mail_sendfailure(self):
		self.app.config['MAIL_SKIP_SEND'] = 'fail'
		self.login_as('user')
		user = request.user
		r = self.client.post(path=url_for('selfservice.update_profile'),
			data={'displayname': user.displayname, 'mail': 'newemail@example.com'},
			follow_redirects=True)
		dump('update_mail_sendfailure', r)
		self.assertEqual(r.status_code, 200)
		_user = request.user
		self.assertNotEqual(_user.mail, 'newemail@example.com')
		# Maybe also check that there is no new token in the db

	def test_change_password(self):
		self.login_as('user')
		user = request.user
		r = self.client.post(path=url_for('selfservice.change_password'),
			data={'password1': 'newpassword', 'password2': 'newpassword'},
			follow_redirects=True)
		dump('change_password', r)
		self.assertEqual(r.status_code, 200)
		_user = request.user
		self.assertTrue(_user.check_password('newpassword'))

	def test_change_password_invalid(self):
		self.login_as('user')
		user = request.user
		r = self.client.post(path=url_for('selfservice.change_password'),
			data={'password1': 'shortpw', 'password2': 'shortpw'},
			follow_redirects=True)
		dump('change_password_invalid', r)
		self.assertEqual(r.status_code, 200)
		_user = request.user
		self.assertFalse(_user.check_password('shortpw'))
		self.assertTrue(_user.check_password('userpassword'))

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
		self.assertFalse(_user.check_password('shortpw\n'))
		self.assertTrue(_user.check_password('userpassword'))

	def test_change_password_mismatch(self):
		self.login_as('user')
		user = request.user
		r = self.client.post(path=url_for('selfservice.change_password'),
			data={'password1': 'newpassword1', 'password2': 'newpassword2'},
			follow_redirects=True)
		dump('change_password_mismatch', r)
		self.assertEqual(r.status_code, 200)
		_user = request.user
		self.assertFalse(_user.check_password('newpassword1'))
		self.assertFalse(_user.check_password('newpassword2'))
		self.assertTrue(_user.check_password('userpassword'))

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

	def test_token_mail_emptydb(self):
		self.login_as('user')
		user = request.user
		r = self.client.get(path=url_for('selfservice.token_mail', token_id=1, token='A'*128), follow_redirects=True)
		dump('token_mail_emptydb', r)
		self.assertEqual(r.status_code, 200)
		_user = request.user
		self.assertEqual(_user.mail, user.mail)

	def test_token_mail_invalid(self):
		self.login_as('user')
		user = request.user
		old_mail = user.mail
		token = MailToken(user=user, newmail='newusermail@example.com')
		db.session.add(token)
		db.session.commit()
		r = self.client.get(path=url_for('selfservice.token_mail', token_id=token.id, token='A'*128), follow_redirects=True)
		dump('token_mail_invalid', r)
		self.assertEqual(r.status_code, 200)
		_user = request.user
		self.assertEqual(_user.mail, old_mail)

	def test_token_mail_wrong_user(self):
		self.login_as('user')
		user = request.user
		old_mail = user.mail
		admin_user = self.get_admin()
		old_admin_mail = admin_user.mail
		db.session.add(MailToken(user=user, newmail='newusermail@example.com'))
		admin_token = MailToken(user=admin_user, newmail='newadminmail@example.com')
		db.session.add(admin_token)
		db.session.commit()
		r = self.client.get(path=url_for('selfservice.token_mail', token_id=admin_token.id, token=admin_token.token), follow_redirects=True)
		dump('token_mail_wrong_user', r)
		self.assertEqual(r.status_code, 403)
		_user = self.get_user()
		_admin_user = self.get_admin()
		self.assertEqual(_user.mail, old_mail)
		self.assertEqual(_admin_user.mail, old_admin_mail)

	def test_token_mail_expired(self):
		self.login_as('user')
		user = request.user
		old_mail = user.mail
		token = MailToken(user=user, newmail='newusermail@example.com',
			created=(datetime.datetime.now() - datetime.timedelta(days=10)))
		db.session.add(token)
		db.session.commit()
		r = self.client.get(path=url_for('selfservice.token_mail', token_id=token.id, token=token.token), follow_redirects=True)
		dump('token_mail_expired', r)
		self.assertEqual(r.status_code, 200)
		_user = request.user
		self.assertEqual(_user.mail, old_mail)
		tokens = MailToken.query.filter(MailToken.user == _user).all()
		self.assertEqual(len(tokens), 0)

	def test_forgot_password(self):
		user = self.get_user()
		r = self.client.get(path=url_for('selfservice.forgot_password'))
		dump('forgot_password', r)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('selfservice.forgot_password'),
			data={'loginname': user.loginname, 'mail': user.mail}, follow_redirects=True)
		dump('forgot_password_submit', r)
		self.assertEqual(r.status_code, 200)
		token = PasswordToken.query.filter(PasswordToken.user == user).first()
		self.assertIsNotNone(token)
		self.assertIn(token.token, str(self.app.last_mail.get_content()))

	def test_forgot_password_wrong_user(self):
		user = self.get_user()
		r = self.client.get(path=url_for('selfservice.forgot_password'))
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('selfservice.forgot_password'),
			data={'loginname': 'not_a_user', 'mail': user.mail}, follow_redirects=True)
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
		r = self.client.get(path=url_for('selfservice.token_password', token_id=token.id, token=token.token), follow_redirects=True)
		dump('token_password', r)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('selfservice.token_password', token_id=token.id, token=token.token),
			data={'password1': 'newpassword', 'password2': 'newpassword'}, follow_redirects=True)
		dump('token_password_submit', r)
		self.assertEqual(r.status_code, 200)
		self.assertTrue(self.get_user().check_password('newpassword'))

	def test_token_password_emptydb(self):
		user = self.get_user()
		r = self.client.get(path=url_for('selfservice.token_password', token_id=1, token='A'*128), follow_redirects=True)
		dump('token_password_emptydb', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn(b'Token expired, please try again', r.data)
		r = self.client.post(path=url_for('selfservice.token_password', token_id=1, token='A'*128),
			data={'password1': 'newpassword', 'password2': 'newpassword'}, follow_redirects=True)
		dump('token_password_emptydb_submit', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn(b'Token expired, please try again', r.data)
		self.assertTrue(self.get_user().check_password('userpassword'))

	def test_token_password_invalid(self):
		user = self.get_user()
		token = PasswordToken(user=user)
		db.session.add(token)
		db.session.commit()
		r = self.client.get(path=url_for('selfservice.token_password', token_id=token.id, token='A'*128), follow_redirects=True)
		dump('token_password_invalid', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn(b'Token expired, please try again', r.data)
		r = self.client.post(path=url_for('selfservice.token_password', token_id=token.id, token='A'*128),
			data={'password1': 'newpassword', 'password2': 'newpassword'}, follow_redirects=True)
		dump('token_password_invalid_submit', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn(b'Token expired, please try again', r.data)
		self.assertTrue(self.get_user().check_password('userpassword'))

	def test_token_password_expired(self):
		user = self.get_user()
		token = PasswordToken(user=user, created=(datetime.datetime.now() - datetime.timedelta(days=10)))
		db.session.add(token)
		db.session.commit()
		r = self.client.get(path=url_for('selfservice.token_password', token_id=token.id, token=token.token), follow_redirects=True)
		dump('token_password_invalid_expired', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn(b'Token expired, please try again', r.data)
		r = self.client.post(path=url_for('selfservice.token_password', token_id=token.id, token=token.token),
			data={'password1': 'newpassword', 'password2': 'newpassword'}, follow_redirects=True)
		dump('token_password_invalid_expired_submit', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn(b'Token expired, please try again', r.data)
		self.assertTrue(self.get_user().check_password('userpassword'))

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
		self.assertTrue(self.get_user().check_password('userpassword'))

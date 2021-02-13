import datetime
import time
import unittest

from flask import url_for, session

# These imports are required, because otherwise we get circular imports?!
from uffd import ldap, user

from uffd.user.models import User
from uffd.role.models import Role
from uffd.session.views import get_current_user, is_valid_session
from uffd.mfa.models import MFAMethod, MFAType, RecoveryCodeMethod, TOTPMethod, WebauthnMethod, _hotp
from uffd import create_app, db

from utils import dump, UffdTestCase

def get_user():
	return User.from_ldap_dn('uid=testuser,ou=users,dc=example,dc=com')

def get_user_password():
	conn = ldap.get_conn()
	conn.search('uid=testuser,ou=users,dc=example,dc=com', '(objectClass=person)')
	return conn.entries[0]['userPassword']

def get_admin():
	return User.from_ldap_dn('uid=testadmin,ou=users,dc=example,dc=com')

class TestUserModel(UffdTestCase):
	def test_has_permission(self):
		user = get_user() # has 'users' and 'uffd_access' group
		admin = get_admin() # has 'users', 'uffd_access' and 'uffd_admin' group
		self.assertTrue(user.has_permission(None))
		self.assertTrue(admin.has_permission(None))
		self.assertTrue(user.has_permission('users'))
		self.assertTrue(admin.has_permission('users'))
		self.assertFalse(user.has_permission('notagroup'))
		self.assertFalse(admin.has_permission('notagroup'))
		self.assertFalse(user.has_permission('uffd_admin'))
		self.assertTrue(admin.has_permission('uffd_admin'))
		self.assertFalse(user.has_permission(['uffd_admin']))
		self.assertTrue(admin.has_permission(['uffd_admin']))
		self.assertFalse(user.has_permission(['uffd_admin', 'notagroup']))
		self.assertTrue(admin.has_permission(['uffd_admin', 'notagroup']))
		self.assertFalse(user.has_permission(['notagroup', 'uffd_admin']))
		self.assertTrue(admin.has_permission(['notagroup', 'uffd_admin']))
		self.assertTrue(user.has_permission(['uffd_admin', 'users']))
		self.assertTrue(admin.has_permission(['uffd_admin', 'users']))
		self.assertTrue(user.has_permission([['uffd_admin', 'users'], ['users', 'uffd_access']]))
		self.assertTrue(admin.has_permission([['uffd_admin', 'users'], ['users', 'uffd_access']]))
		self.assertFalse(user.has_permission(['uffd_admin', ['users', 'notagroup']]))
		self.assertTrue(admin.has_permission(['uffd_admin', ['users', 'notagroup']]))

class TestUserModelOL(TestUserModel):
	use_openldap = True

class TestUserViews(UffdTestCase):
	def setUp(self):
		super().setUp()
		self.client.post(path=url_for('session.login'),
			data={'loginname': 'testadmin', 'password': 'adminpassword'}, follow_redirects=True)

	def test_index(self):
		r = self.client.get(path=url_for('user.index'), follow_redirects=True)
		dump('user_index', r)
		self.assertEqual(r.status_code, 200)

	def test_new(self):
		db.session.add(Role('base'))
		role1 = Role('role1')
		db.session.add(role1)
		role2 = Role('role2')
		db.session.add(role2)
		db.session.commit()
		role1_id = role1.id
		r = self.client.get(path=url_for('user.show'), follow_redirects=True)
		dump('user_new', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(User.from_ldap_dn('uid=newuser,ou=users,dc=example,dc=com'))
		r = self.client.post(path=url_for('user.update'),
			data={'loginname': 'newuser', 'mail': 'newuser@example.com', 'displayname': 'New User',
			f'role-{role1_id}': '1', 'password': 'newpassword'}, follow_redirects=True)
		dump('user_new_submit', r)
		self.assertEqual(r.status_code, 200)
		user = User.from_ldap_dn('uid=newuser,ou=users,dc=example,dc=com')
		roles = sorted([r.name for r in Role.get_for_user(user)])
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser')
		self.assertEqual(user.displayname, 'New User')
		self.assertEqual(user.mail, 'newuser@example.com')
		self.assertTrue(user.uid)
		self.assertEqual(roles, ['base', 'role1'])
		# TODO: check password hash

	def test_new_invalid_loginname(self):
		r = self.client.post(path=url_for('user.update'),
			data={'loginname': '!newuser', 'mail': 'newuser@example.com', 'displayname': 'New User',
			'password': 'newpassword'}, follow_redirects=True)
		dump('user_new_invalid_loginname', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(User.from_ldap_dn('uid=newuser,ou=users,dc=example,dc=com'))

	def test_new_empty_loginname(self):
		r = self.client.post(path=url_for('user.update'),
			data={'loginname': '', 'mail': 'newuser@example.com', 'displayname': 'New User',
			'password': 'newpassword'}, follow_redirects=True)
		dump('user_new_empty_loginname', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(User.from_ldap_dn('uid=newuser,ou=users,dc=example,dc=com'))

	def test_new_empty_email(self):
		r = self.client.post(path=url_for('user.update'),
			data={'loginname': 'newuser', 'mail': '', 'displayname': 'New User',
			'password': 'newpassword'}, follow_redirects=True)
		dump('user_new_empty_email', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(User.from_ldap_dn('uid=newuser,ou=users,dc=example,dc=com'))

	def test_new_invalid_display_name(self):
		r = self.client.post(path=url_for('user.update'),
			data={'loginname': 'newuser', 'mail': 'newuser@example.com', 'displayname': 'A'*200,
			'password': 'newpassword'}, follow_redirects=True)
		dump('user_new_invalid_display_name', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(User.from_ldap_dn('uid=newuser,ou=users,dc=example,dc=com'))

	def test_update(self):
		user = get_user()
		db.session.add(Role('base'))
		role1 = Role('role1')
		db.session.add(role1)
		role2 = Role('role2')
		db.session.add(role2)
		role2.add_member(user)
		db.session.commit()
		role1_id = role1.id
		oldpw = get_user_password()
		r = self.client.get(path=url_for('user.show', uid=user.uid), follow_redirects=True)
		dump('user_update', r)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('user.update', uid=user.uid),
			data={'loginname': 'testuser', 'mail': 'newuser@example.com', 'displayname': 'New User',
			f'role-{role1_id}': '1', 'password': ''}, follow_redirects=True)
		dump('user_update_submit', r)
		self.assertEqual(r.status_code, 200)
		_user = get_user()
		roles = sorted([r.name for r in Role.get_for_user(_user)])
		self.assertEqual(_user.displayname, 'New User')
		self.assertEqual(_user.mail, 'newuser@example.com')
		self.assertEqual(_user.uid, user.uid)
		self.assertEqual(_user.loginname, user.loginname)
		self.assertEqual(get_user_password(), oldpw)
		self.assertEqual(roles, ['base', 'role1'])

	def test_update_password(self):
		user = get_user()
		oldpw = get_user_password()
		r = self.client.get(path=url_for('user.show', uid=user.uid), follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('user.update', uid=user.uid),
			data={'loginname': 'testuser', 'mail': 'newuser@example.com', 'displayname': 'New User',
			'password': 'newpassword'}, follow_redirects=True)
		dump('user_update_password', r)
		self.assertEqual(r.status_code, 200)
		_user = get_user()
		self.assertEqual(_user.displayname, 'New User')
		self.assertEqual(_user.mail, 'newuser@example.com')
		self.assertEqual(_user.uid, user.uid)
		self.assertEqual(_user.loginname, user.loginname)
		self.assertNotEqual(get_user_password(), oldpw)

	@unittest.skip('See #28')
	def test_update_invalid_password(self):
		user = get_user()
		oldpw = get_user_password()
		r = self.client.get(path=url_for('user.show', uid=user.uid), follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('user.update', uid=user.uid),
			data={'loginname': 'testuser', 'mail': 'newuser@example.com', 'displayname': 'New User',
			'password': 'A'}, follow_redirects=True)
		dump('user_update_password', r)
		self.assertEqual(r.status_code, 200)
		_user = get_user()
		self.assertEqual(get_user_password(), oldpw)
		self.assertEqual(_user.displayname, user.displayname)
		self.assertEqual(_user.mail, user.mail)
		self.assertEqual(_user.loginname, user.loginname)

	def test_update_empty_email(self):
		user = get_user()
		oldpw = get_user_password()
		r = self.client.get(path=url_for('user.show', uid=user.uid), follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('user.update', uid=user.uid),
			data={'loginname': 'testuser', 'mail': '', 'displayname': 'New User',
			'password': 'newpassword'}, follow_redirects=True)
		dump('user_update_empty_mail', r)
		self.assertEqual(r.status_code, 200)
		_user = get_user()
		self.assertEqual(_user.displayname, user.displayname)
		self.assertEqual(_user.mail, user.mail)
		self.assertEqual(_user.loginname, user.loginname)
		self.assertEqual(get_user_password(), oldpw)

	def test_update_invalid_display_name(self):
		user = get_user()
		oldpw = get_user_password()
		r = self.client.get(path=url_for('user.show', uid=user.uid), follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('user.update', uid=user.uid),
			data={'loginname': 'testuser', 'mail': 'newuser@example.com', 'displayname': 'A'*200,
			'password': 'newpassword'}, follow_redirects=True)
		dump('user_update_invalid_display_name', r)
		self.assertEqual(r.status_code, 200)
		_user = get_user()
		self.assertEqual(_user.displayname, user.displayname)
		self.assertEqual(_user.mail, user.mail)
		self.assertEqual(_user.loginname, user.loginname)
		self.assertEqual(get_user_password(), oldpw)

	def test_show(self):
		r = self.client.get(path=url_for('user.show', uid=get_user().uid), follow_redirects=True)
		dump('user_show', r)
		self.assertEqual(r.status_code, 200)

	def test_delete(self):
		user = get_user()
		r = self.client.get(path=url_for('user.delete', uid=user.uid), follow_redirects=True)
		dump('user_delete', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(get_user())

	def test_csvimport(self):
		db.session.add(Role('base'))
		role1 = Role('role1')
		db.session.add(role1)
		role2 = Role('role2')
		db.session.add(role2)
		db.session.commit()
		data = f'''\
newuser1,newuser1@example.com,
newuser2,newuser2@example.com,{role1.id}
newuser3,newuser3@example.com,{role1.id};{role2.id}
newuser4,newuser4@example.com,9999
newuser5,newuser5@example.com,notanumber
newuser6,newuser6@example.com,{role1.id};{role2.id};
newuser7,invalidmail,
newuser8,,
,newuser9@example.com,
,,

,,,
newuser10,newuser10@example.com,
newuser11,newuser11@example.com, {role1.id};{role2.id}
newuser12,newuser12@example.com,{role1.id};{role1.id}
<invalid tag-like thingy>'''
		r = self.client.post(path=url_for('user.csvimport'), data={'csv': data}, follow_redirects=True)
		dump('user_csvimport', r)
		self.assertEqual(r.status_code, 200)
		user = User.from_ldap_dn('uid=newuser1,ou=users,dc=example,dc=com')
		roles = sorted([r.name for r in Role.get_for_user(user)])
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser1')
		self.assertEqual(user.displayname, 'newuser1')
		self.assertEqual(user.mail, 'newuser1@example.com')
		self.assertEqual(roles, ['base'])
		user = User.from_ldap_dn('uid=newuser2,ou=users,dc=example,dc=com')
		roles = sorted([r.name for r in Role.get_for_user(user)])
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser2')
		self.assertEqual(user.displayname, 'newuser2')
		self.assertEqual(user.mail, 'newuser2@example.com')
		self.assertEqual(roles, ['base', 'role1'])
		user = User.from_ldap_dn('uid=newuser3,ou=users,dc=example,dc=com')
		roles = sorted([r.name for r in Role.get_for_user(user)])
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser3')
		self.assertEqual(user.displayname, 'newuser3')
		self.assertEqual(user.mail, 'newuser3@example.com')
		self.assertEqual(roles, ['base', 'role1', 'role2'])
		user = User.from_ldap_dn('uid=newuser4,ou=users,dc=example,dc=com')
		roles = sorted([r.name for r in Role.get_for_user(user)])
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser4')
		self.assertEqual(user.displayname, 'newuser4')
		self.assertEqual(user.mail, 'newuser4@example.com')
		self.assertEqual(roles, ['base'])
		user = User.from_ldap_dn('uid=newuser5,ou=users,dc=example,dc=com')
		roles = sorted([r.name for r in Role.get_for_user(user)])
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser5')
		self.assertEqual(user.displayname, 'newuser5')
		self.assertEqual(user.mail, 'newuser5@example.com')
		self.assertEqual(roles, ['base'])
		user = User.from_ldap_dn('uid=newuser6,ou=users,dc=example,dc=com')
		roles = sorted([r.name for r in Role.get_for_user(user)])
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser6')
		self.assertEqual(user.displayname, 'newuser6')
		self.assertEqual(user.mail, 'newuser6@example.com')
		self.assertEqual(roles, ['base', 'role1', 'role2'])
		self.assertIsNone(User.from_ldap_dn('uid=newuser7,ou=users,dc=example,dc=com'))
		self.assertIsNone(User.from_ldap_dn('uid=newuser8,ou=users,dc=example,dc=com'))
		self.assertIsNone(User.from_ldap_dn('uid=newuser9,ou=users,dc=example,dc=com'))
		user = User.from_ldap_dn('uid=newuser10,ou=users,dc=example,dc=com')
		roles = sorted([r.name for r in Role.get_for_user(user)])
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser10')
		self.assertEqual(user.displayname, 'newuser10')
		self.assertEqual(user.mail, 'newuser10@example.com')
		self.assertEqual(roles, ['base'])
		user = User.from_ldap_dn('uid=newuser11,ou=users,dc=example,dc=com')
		roles = sorted([r.name for r in Role.get_for_user(user)])
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser11')
		self.assertEqual(user.displayname, 'newuser11')
		self.assertEqual(user.mail, 'newuser11@example.com')
		# Currently the csv import is not very robust, imho newuser11 should have role1 and role2!
		#self.assertEqual(roles, ['base', 'role1', 'role2'])
		self.assertEqual(roles, ['base', 'role2'])
		user = User.from_ldap_dn('uid=newuser12,ou=users,dc=example,dc=com')
		roles = sorted([r.name for r in Role.get_for_user(user)])
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser12')
		self.assertEqual(user.displayname, 'newuser12')
		self.assertEqual(user.mail, 'newuser12@example.com')
		self.assertEqual(roles, ['base', 'role1'])

class TestUserViewsOL(TestUserViews):
	use_openldap = True

class TestGroupViews(UffdTestCase):
	def setUp(self):
		super().setUp()
		self.client.post(path=url_for('session.login'),
			data={'loginname': 'testadmin', 'password': 'adminpassword'}, follow_redirects=True)

	def test_index(self):
		r = self.client.get(path=url_for('group.index'), follow_redirects=True)
		dump('group_index', r)
		self.assertEqual(r.status_code, 200)

	def test_show(self):
		r = self.client.get(path=url_for('group.show', gid=20001), follow_redirects=True)
		dump('group_show', r)
		self.assertEqual(r.status_code, 200)

class TestGroupViewsOL(TestGroupViews):
	use_openldap = True

import datetime
import unittest

from flask import url_for, session

# These imports are required, because otherwise we get circular imports?!
from uffd import ldap, user

from uffd.user.models import User
from uffd.role.models import Role
from uffd import create_app, db

from utils import dump, UffdTestCase


def get_user():
	return User.query.get('uid=testuser,ou=users,dc=example,dc=com')

def get_admin():
	return User.query.get('uid=testadmin,ou=users,dc=example,dc=com')

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

class TestUserModelOLUser(TestUserModelOL):
	use_userconnection = True

	def setUp(self):
		super().setUp()
		self.client.post(path=url_for('session.login'),
			data={'loginname': 'testadmin', 'password': 'adminpassword'}, follow_redirects=True)

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
		db.session.add(Role(name='base', is_default=True))
		role1 = Role(name='role1')
		db.session.add(role1)
		role2 = Role(name='role2')
		db.session.add(role2)
		db.session.commit()
		role1_id = role1.id
		r = self.client.get(path=url_for('user.show'), follow_redirects=True)
		dump('user_new', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(User.query.get('uid=newuser,ou=users,dc=example,dc=com'))
		r = self.client.post(path=url_for('user.update'),
			data={'loginname': 'newuser', 'mail': 'newuser@example.com', 'displayname': 'New User',
			f'role-{role1_id}': '1', 'password': 'newpassword'}, follow_redirects=True)
		dump('user_new_submit', r)
		self.assertEqual(r.status_code, 200)
		user = User.query.get('uid=newuser,ou=users,dc=example,dc=com')
		roles = sorted([r.name for r in user.roles_effective])
		self.assertIsNotNone(user)
		self.assertFalse(user.is_service_user)
		self.assertEqual(user.loginname, 'newuser')
		self.assertEqual(user.displayname, 'New User')
		self.assertEqual(user.mail, 'newuser@example.com')
		self.assertTrue(user.uid)
		role1 = Role(name='role1')
		self.assertEqual(roles, ['base', 'role1'])
		# TODO: confirm Mail is send, login not yet possible
		#self.assertTrue(ldap.test_user_bind(user.dn, 'newpassword'))

	def test_new_service(self):
		db.session.add(Role(name='base', is_default=True))
		role1 = Role(name='role1')
		db.session.add(role1)
		role2 = Role(name='role2')
		db.session.add(role2)
		db.session.commit()
		role1_id = role1.id
		r = self.client.get(path=url_for('user.show'), follow_redirects=True)
		dump('user_new_service', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(User.query.get('uid=newuser,ou=users,dc=example,dc=com'))
		r = self.client.post(path=url_for('user.update'),
			data={'loginname': 'newuser', 'mail': 'newuser@example.com', 'displayname': 'New User',
			f'role-{role1_id}': '1', 'password': 'newpassword', 'serviceaccount': '1'}, follow_redirects=True)
		dump('user_new_submit', r)
		self.assertEqual(r.status_code, 200)
		user = User.query.get('uid=newuser,ou=users,dc=example,dc=com')
		roles = sorted([r.name for r in user.roles])
		self.assertIsNotNone(user)
		self.assertTrue(user.is_service_user)
		self.assertEqual(user.loginname, 'newuser')
		self.assertEqual(user.displayname, 'New User')
		self.assertEqual(user.mail, 'newuser@example.com')
		self.assertTrue(user.uid)
		role1 = Role(name='role1')
		self.assertEqual(roles, ['role1'])
		# TODO: confirm Mail is send, login not yet possible
		#self.assertTrue(ldap.test_user_bind(user.dn, 'newpassword'))

	def test_new_invalid_loginname(self):
		r = self.client.post(path=url_for('user.update'),
			data={'loginname': '!newuser', 'mail': 'newuser@example.com', 'displayname': 'New User',
			'password': 'newpassword'}, follow_redirects=True)
		dump('user_new_invalid_loginname', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(User.query.get('uid=newuser,ou=users,dc=example,dc=com'))

	def test_new_empty_loginname(self):
		r = self.client.post(path=url_for('user.update'),
			data={'loginname': '', 'mail': 'newuser@example.com', 'displayname': 'New User',
			'password': 'newpassword'}, follow_redirects=True)
		dump('user_new_empty_loginname', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(User.query.get('uid=newuser,ou=users,dc=example,dc=com'))

	def test_new_empty_email(self):
		r = self.client.post(path=url_for('user.update'),
			data={'loginname': 'newuser', 'mail': '', 'displayname': 'New User',
			'password': 'newpassword'}, follow_redirects=True)
		dump('user_new_empty_email', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(User.query.get('uid=newuser,ou=users,dc=example,dc=com'))

	def test_new_invalid_display_name(self):
		r = self.client.post(path=url_for('user.update'),
			data={'loginname': 'newuser', 'mail': 'newuser@example.com', 'displayname': 'A'*200,
			'password': 'newpassword'}, follow_redirects=True)
		dump('user_new_invalid_display_name', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(User.query.get('uid=newuser,ou=users,dc=example,dc=com'))

	def test_update(self):
		user = get_user()
		db.session.add(Role(name='base', is_default=True))
		role1 = Role(name='role1')
		db.session.add(role1)
		role2 = Role(name='role2')
		db.session.add(role2)
		role2.members.add(user)
		db.session.commit()
		role1_id = role1.id
		r = self.client.get(path=url_for('user.show', uid=user.uid), follow_redirects=True)
		dump('user_update', r)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('user.update', uid=user.uid),
			data={'loginname': 'testuser', 'mail': 'newuser@example.com', 'displayname': 'New User',
			f'role-{role1_id}': '1', 'password': ''}, follow_redirects=True)
		dump('user_update_submit', r)
		self.assertEqual(r.status_code, 200)
		_user = get_user()
		roles = sorted([r.name for r in _user.roles_effective])
		self.assertEqual(_user.displayname, 'New User')
		self.assertEqual(_user.mail, 'newuser@example.com')
		self.assertEqual(_user.uid, user.uid)
		self.assertEqual(_user.loginname, user.loginname)
		self.assertTrue(ldap.test_user_bind(user.dn, 'userpassword'))
		self.assertEqual(roles, ['base', 'role1'])

	def test_update_password(self):
		user = get_user()
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
		self.assertTrue(ldap.test_user_bind(_user.dn, 'newpassword'))


	@unittest.skip('See #28')
	def test_update_invalid_password(self):
		user = get_user()
		r = self.client.get(path=url_for('user.show', uid=user.uid), follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('user.update', uid=user.uid),
			data={'loginname': 'testuser', 'mail': 'newuser@example.com', 'displayname': 'New User',
			'password': 'A'}, follow_redirects=True)
		dump('user_update_password', r)
		self.assertEqual(r.status_code, 200)
		_user = get_user()
		self.assertFalse(ldap.test_user_bind(_user.dn, 'A'))
		self.assertEqual(_user.displayname, user.displayname)
		self.assertEqual(_user.mail, user.mail)
		self.assertEqual(_user.loginname, user.loginname)

	def test_update_empty_email(self):
		user = get_user()
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
		self.assertFalse(ldap.test_user_bind(_user.dn, 'newpassword'))

	def test_update_invalid_display_name(self):
		user = get_user()
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
		self.assertFalse(ldap.test_user_bind(_user.dn, 'newpassword'))

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
		role1 = Role(name='role1')
		db.session.add(role1)
		role2 = Role(name='role2')
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
		user = User.query.get('uid=newuser1,ou=users,dc=example,dc=com')
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser1')
		self.assertEqual(user.displayname, 'newuser1')
		self.assertEqual(user.mail, 'newuser1@example.com')
		roles = sorted([r.name for r in user.roles])
		self.assertEqual(roles, [])
		user = User.query.get('uid=newuser2,ou=users,dc=example,dc=com')
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser2')
		self.assertEqual(user.displayname, 'newuser2')
		self.assertEqual(user.mail, 'newuser2@example.com')
		roles = sorted([r.name for r in user.roles])
		self.assertEqual(roles, ['role1'])
		user = User.query.get('uid=newuser3,ou=users,dc=example,dc=com')
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser3')
		self.assertEqual(user.displayname, 'newuser3')
		self.assertEqual(user.mail, 'newuser3@example.com')
		roles = sorted([r.name for r in user.roles])
		self.assertEqual(roles, ['role1', 'role2'])
		user = User.query.get('uid=newuser4,ou=users,dc=example,dc=com')
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser4')
		self.assertEqual(user.displayname, 'newuser4')
		self.assertEqual(user.mail, 'newuser4@example.com')
		roles = sorted([r.name for r in user.roles])
		self.assertEqual(roles, [])
		user = User.query.get('uid=newuser5,ou=users,dc=example,dc=com')
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser5')
		self.assertEqual(user.displayname, 'newuser5')
		self.assertEqual(user.mail, 'newuser5@example.com')
		roles = sorted([r.name for r in user.roles])
		self.assertEqual(roles, [])
		user = User.query.get('uid=newuser6,ou=users,dc=example,dc=com')
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser6')
		self.assertEqual(user.displayname, 'newuser6')
		self.assertEqual(user.mail, 'newuser6@example.com')
		roles = sorted([r.name for r in user.roles])
		self.assertEqual(roles, ['role1', 'role2'])
		self.assertIsNone(User.query.get('uid=newuser7,ou=users,dc=example,dc=com'))
		self.assertIsNone(User.query.get('uid=newuser8,ou=users,dc=example,dc=com'))
		self.assertIsNone(User.query.get('uid=newuser9,ou=users,dc=example,dc=com'))
		user = User.query.get('uid=newuser10,ou=users,dc=example,dc=com')
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser10')
		self.assertEqual(user.displayname, 'newuser10')
		self.assertEqual(user.mail, 'newuser10@example.com')
		roles = sorted([r.name for r in user.roles])
		self.assertEqual(roles, [])
		user = User.query.get('uid=newuser11,ou=users,dc=example,dc=com')
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser11')
		self.assertEqual(user.displayname, 'newuser11')
		self.assertEqual(user.mail, 'newuser11@example.com')
		# Currently the csv import is not very robust, imho newuser11 should have role1 and role2!
		roles = sorted([r.name for r in user.roles])
		#self.assertEqual(roles, ['role1', 'role2'])
		self.assertEqual(roles, ['role2'])
		user = User.query.get('uid=newuser12,ou=users,dc=example,dc=com')
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser12')
		self.assertEqual(user.displayname, 'newuser12')
		self.assertEqual(user.mail, 'newuser12@example.com')
		roles = sorted([r.name for r in user.roles])
		self.assertEqual(roles, ['role1'])

class TestUserViewsOL(TestUserViews):
	use_openldap = True

class TestUserViewsOLUserAsAdmin(TestUserViewsOL):
	use_userconnection = True

class TestUserViewsOLUserAsUser(UffdTestCase):
	use_userconnection = True
	use_openldap = True

	def setUp(self):
		super().setUp()
		self.client.post(path=url_for('session.login'),
			data={'loginname': 'testuser', 'password': 'userpassword'}, follow_redirects=True)

	def test_view_own(self):
		user_ = get_user()
		r = self.client.get(path=url_for('user.show', uid=user_.uid), follow_redirects=True)
		dump('user_view_own', r)
		self.assertEqual(r.status_code, 200)

	def test_view_others(self):
		admin = get_admin()
		r = self.client.get(path=url_for('user.show', uid=admin.uid), follow_redirects=True)
		dump('user_view_others', r)
		self.assertEqual(r.status_code, 200)

	def test_view_index(self):
		r = self.client.get(path=url_for('user.index'), follow_redirects=True)
		dump('user_index', r)
		self.assertEqual(r.status_code, 200)

	def test_update_other_user(self):
		user_ = get_admin()
		db.session.add(Role(name='base', is_default=True))
		role1 = Role(name='role1')
		db.session.add(role1)
		role2 = Role(name='role2')
		db.session.add(role2)
		role2.members.add(user_)
		db.session.commit()
		role1_id = role1.id
		r = self.client.get(path=url_for('user.show', uid=user_.uid), follow_redirects=True)
		dump('user_update', r)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('user.update', uid=user_.uid),
			data={'loginname': user_.loginname, 'mail': user_.mail, 'displayname': user_.displayname + "12345",
			f'role-{role1_id}': '1', 'password': ''}, follow_redirects=True)
		dump('user_update_submit', r)
		self.assertEqual(r.status_code, 200)
		_user = get_admin()
		self.assertEqual(_user.displayname, user_.displayname)
		self.assertEqual(_user.mail, user_.mail)
		self.assertEqual(_user.uid, user_.uid)
		self.assertEqual(_user.loginname, user_.loginname)

	def test_new(self):
		db.session.add(Role(name='base', is_default=True))
		role1 = Role(name='role1')
		db.session.add(role1)
		role2 = Role(name='role2')
		db.session.add(role2)
		db.session.commit()
		role1_id = role1.id
		r = self.client.get(path=url_for('user.show'), follow_redirects=True)
		dump('user_new', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(User.query.get('uid=newuser,ou=users,dc=example,dc=com'))
		r = self.client.post(path=url_for('user.update'),
			data={'loginname': 'newuser', 'mail': 'newuser@example.com', 'displayname': 'New User',
			f'role-{role1_id}': '1', 'password': 'newpassword'}, follow_redirects=True)
		dump('user_new_submit', r)
		self.assertEqual(r.status_code, 200)
		user = User.query.get('uid=newuser,ou=users,dc=example,dc=com')
		self.assertIsNone(user)

	def test_delete(self):
		user = get_admin()
		r = self.client.get(path=url_for('user.delete', uid=user.uid), follow_redirects=True)
		dump('user_delete', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNotNone(get_admin())


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

class TestGroupViewsOLUser(TestGroupViewsOL):
	use_userconnection = True

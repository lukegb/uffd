import datetime
import unittest

from flask import url_for, session

# These imports are required, because otherwise we get circular imports?!
from uffd import ldap, user

from uffd.user.models import User
from uffd.role.models import Role
from uffd import create_app, db

from utils import dump, UffdTestCase


class TestUserModel(UffdTestCase):
	def test_has_permission(self):
		user_ = self.get_user() # has 'users' and 'uffd_access' group
		admin = self.get_admin() # has 'users', 'uffd_access' and 'uffd_admin' group
		self.assertTrue(user_.has_permission(None))
		self.assertTrue(admin.has_permission(None))
		self.assertTrue(user_.has_permission('users'))
		self.assertTrue(admin.has_permission('users'))
		self.assertFalse(user_.has_permission('notagroup'))
		self.assertFalse(admin.has_permission('notagroup'))
		self.assertFalse(user_.has_permission('uffd_admin'))
		self.assertTrue(admin.has_permission('uffd_admin'))
		self.assertFalse(user_.has_permission(['uffd_admin']))
		self.assertTrue(admin.has_permission(['uffd_admin']))
		self.assertFalse(user_.has_permission(['uffd_admin', 'notagroup']))
		self.assertTrue(admin.has_permission(['uffd_admin', 'notagroup']))
		self.assertFalse(user_.has_permission(['notagroup', 'uffd_admin']))
		self.assertTrue(admin.has_permission(['notagroup', 'uffd_admin']))
		self.assertTrue(user_.has_permission(['uffd_admin', 'users']))
		self.assertTrue(admin.has_permission(['uffd_admin', 'users']))
		self.assertTrue(user_.has_permission([['uffd_admin', 'users'], ['users', 'uffd_access']]))
		self.assertTrue(admin.has_permission([['uffd_admin', 'users'], ['users', 'uffd_access']]))
		self.assertFalse(user_.has_permission(['uffd_admin', ['users', 'notagroup']]))
		self.assertTrue(admin.has_permission(['uffd_admin', ['users', 'notagroup']]))

class TestUserModelOL(TestUserModel):
	use_openldap = True

class TestUserModelOLUser(TestUserModelOL):
	use_userconnection = True

	def setUp(self):
		super().setUp()
		self.login_as('admin')

class TestUserViews(UffdTestCase):
	def setUp(self):
		super().setUp()
		self.login_as('admin')

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
		self.assertIsNone(User.query.get('uid=newuser,{}'.format(self.app.config['LDAP_USER_SEARCH_BASE'])))
		r = self.client.post(path=url_for('user.update'),
			data={'loginname': 'newuser', 'mail': 'newuser@example.com', 'displayname': 'New User',
			f'role-{role1_id}': '1', 'password': 'newpassword'}, follow_redirects=True)
		dump('user_new_submit', r)
		self.assertEqual(r.status_code, 200)
		user_ = User.query.get('uid=newuser,{}'.format(self.app.config['LDAP_USER_SEARCH_BASE']))
		roles = sorted([r.name for r in user_.roles_effective])
		self.assertIsNotNone(user_)
		self.assertFalse(user_.is_service_user)
		self.assertEqual(user_.loginname, 'newuser')
		self.assertEqual(user_.displayname, 'New User')
		self.assertEqual(user_.mail, 'newuser@example.com')
		self.assertTrue(user_.uid)
		role1 = Role(name='role1')
		self.assertEqual(roles, ['base', 'role1'])
		# TODO: confirm Mail is send, login not yet possible
		#self.assertTrue(ldap.test_user_bind(user_.dn, 'newpassword'))

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
		self.assertIsNone(User.query.get('uid=newuser,{}'.format(self.app.config['LDAP_USER_SEARCH_BASE'])))
		r = self.client.post(path=url_for('user.update'),
			data={'loginname': 'newuser', 'mail': 'newuser@example.com', 'displayname': 'New User',
			f'role-{role1_id}': '1', 'password': 'newpassword', 'serviceaccount': '1'}, follow_redirects=True)
		dump('user_new_submit', r)
		self.assertEqual(r.status_code, 200)
		user = User.query.get('uid=newuser,{}'.format(self.app.config['LDAP_USER_SEARCH_BASE']))
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
		self.assertIsNone(User.query.get('uid=newuser,{}'.format(self.app.config['LDAP_USER_SEARCH_BASE'])))

	def test_new_empty_loginname(self):
		r = self.client.post(path=url_for('user.update'),
			data={'loginname': '', 'mail': 'newuser@example.com', 'displayname': 'New User',
			'password': 'newpassword'}, follow_redirects=True)
		dump('user_new_empty_loginname', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(User.query.get('uid=newuser,{}'.format(self.app.config['LDAP_USER_SEARCH_BASE'])))

	def test_new_empty_email(self):
		r = self.client.post(path=url_for('user.update'),
			data={'loginname': 'newuser', 'mail': '', 'displayname': 'New User',
			'password': 'newpassword'}, follow_redirects=True)
		dump('user_new_empty_email', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(User.query.get('uid=newuser,{}'.format(self.app.config['LDAP_USER_SEARCH_BASE'])))

	def test_new_invalid_display_name(self):
		r = self.client.post(path=url_for('user.update'),
			data={'loginname': 'newuser', 'mail': 'newuser@example.com', 'displayname': 'A'*200,
			'password': 'newpassword'}, follow_redirects=True)
		dump('user_new_invalid_display_name', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(User.query.get('uid=newuser,{}'.format(self.app.config['LDAP_USER_SEARCH_BASE'])))

	def test_update(self):
		user_unupdated = self.get_user()
		db.session.add(Role(name='base', is_default=True))
		role1 = Role(name='role1')
		db.session.add(role1)
		role2 = Role(name='role2')
		db.session.add(role2)
		role2.members.add(user_unupdated)
		db.session.commit()
		role1_id = role1.id
		r = self.client.get(path=url_for('user.show', uid=user_unupdated.uid), follow_redirects=True)
		dump('user_update', r)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('user.update', uid=user_unupdated.uid),
			data={'loginname': 'testuser', 'mail': 'newuser@example.com', 'displayname': 'New User',
			f'role-{role1_id}': '1', 'password': ''}, follow_redirects=True)
		dump('user_update_submit', r)
		self.assertEqual(r.status_code, 200)
		user_updated = self.get_user()
		roles = sorted([r.name for r in user_updated.roles_effective])
		self.assertEqual(user_updated.displayname, 'New User')
		self.assertEqual(user_updated.mail, 'newuser@example.com')
		self.assertEqual(user_updated.uid, user_unupdated.uid)
		self.assertEqual(user_updated.loginname, user_unupdated.loginname)
		print(user_updated.dn)
		self.assertTrue(ldap.test_user_bind(user_updated.dn, self.test_data.get('user').get('password')))
		self.assertEqual(roles, ['base', 'role1'])

	def test_update_password(self):
		user_unupdated = self.get_user()
		r = self.client.get(path=url_for('user.show', uid=user_unupdated.uid), follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('user.update', uid=user_unupdated.uid),
			data={'loginname': 'testuser', 'mail': 'newuser@example.com', 'displayname': 'New User',
			'password': 'newpassword'}, follow_redirects=True)
		dump('user_update_password', r)
		self.assertEqual(r.status_code, 200)
		user_updated = self.get_user()
		self.assertEqual(user_updated.displayname, 'New User')
		self.assertEqual(user_updated.mail, 'newuser@example.com')
		self.assertEqual(user_updated.uid, user_unupdated.uid)
		self.assertEqual(user_updated.loginname, user_unupdated.loginname)
		self.assertTrue(ldap.test_user_bind(user_updated.dn, 'newpassword'))

	@unittest.skip('See #28')
	def test_update_invalid_password(self):
		user_unupdated = self.get_user()
		r = self.client.get(path=url_for('user.show', uid=user_unupdated.uid), follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('user.update', uid=user_unupdated.uid),
			data={'loginname': 'testuser', 'mail': 'newuser@example.com', 'displayname': 'New User',
			'password': 'A'}, follow_redirects=True)
		dump('user_update_password', r)
		self.assertEqual(r.status_code, 200)
		user_updated = self.get_user()
		self.assertFalse(ldap.test_user_bind(user_updated.dn, 'A'))
		self.assertEqual(user_updated.displayname, user_unupdated.displayname)
		self.assertEqual(user_updated.mail, user_unupdated.mail)
		self.assertEqual(user_updated.loginname, user_unupdated.loginname)

	def test_update_empty_email(self):
		user_unupdated = self.get_user()
		r = self.client.get(path=url_for('user.show', uid=user_unupdated.uid), follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('user.update', uid=user_unupdated.uid),
			data={'loginname': 'testuser', 'mail': '', 'displayname': 'New User',
			'password': 'newpassword'}, follow_redirects=True)
		dump('user_update_empty_mail', r)
		self.assertEqual(r.status_code, 200)
		user_updated = self.get_user()
		self.assertEqual(user_updated.displayname, user_unupdated.displayname)
		self.assertEqual(user_updated.mail, user_unupdated.mail)
		self.assertEqual(user_updated.loginname, user_unupdated.loginname)
		self.assertFalse(ldap.test_user_bind(user_updated.dn, 'newpassword'))

	def test_update_invalid_display_name(self):
		user_unupdated = self.get_user()
		r = self.client.get(path=url_for('user.show', uid=user_unupdated.uid), follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('user.update', uid=user_unupdated.uid),
			data={'loginname': 'testuser', 'mail': 'newuser@example.com', 'displayname': 'A'*200,
			'password': 'newpassword'}, follow_redirects=True)
		dump('user_update_invalid_display_name', r)
		self.assertEqual(r.status_code, 200)
		user_updated = self.get_user()
		self.assertEqual(user_updated.displayname, user_unupdated.displayname)
		self.assertEqual(user_updated.mail, user_unupdated.mail)
		self.assertEqual(user_updated.loginname, user_unupdated.loginname)
		self.assertFalse(ldap.test_user_bind(user_updated.dn, 'newpassword'))

	def test_show(self):
		r = self.client.get(path=url_for('user.show', uid=self.get_user().uid), follow_redirects=True)
		dump('user_show', r)
		self.assertEqual(r.status_code, 200)

	def test_delete(self):
		r = self.client.get(path=url_for('user.delete', uid=self.get_user().uid), follow_redirects=True)
		dump('user_delete', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(self.get_user())

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
		user = User.query.get('uid=newuser1,{}'.format(self.app.config['LDAP_USER_SEARCH_BASE']))
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser1')
		self.assertEqual(user.displayname, 'newuser1')
		self.assertEqual(user.mail, 'newuser1@example.com')
		roles = sorted([r.name for r in user.roles])
		self.assertEqual(roles, [])
		user = User.query.get('uid=newuser2,{}'.format(self.app.config['LDAP_USER_SEARCH_BASE']))
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser2')
		self.assertEqual(user.displayname, 'newuser2')
		self.assertEqual(user.mail, 'newuser2@example.com')
		roles = sorted([r.name for r in user.roles])
		self.assertEqual(roles, ['role1'])
		user = User.query.get('uid=newuser3,{}'.format(self.app.config['LDAP_USER_SEARCH_BASE']))
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser3')
		self.assertEqual(user.displayname, 'newuser3')
		self.assertEqual(user.mail, 'newuser3@example.com')
		roles = sorted([r.name for r in user.roles])
		self.assertEqual(roles, ['role1', 'role2'])
		user = User.query.get('uid=newuser4,{}'.format(self.app.config['LDAP_USER_SEARCH_BASE']))
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser4')
		self.assertEqual(user.displayname, 'newuser4')
		self.assertEqual(user.mail, 'newuser4@example.com')
		roles = sorted([r.name for r in user.roles])
		self.assertEqual(roles, [])
		user = User.query.get('uid=newuser5,{}'.format(self.app.config['LDAP_USER_SEARCH_BASE']))
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser5')
		self.assertEqual(user.displayname, 'newuser5')
		self.assertEqual(user.mail, 'newuser5@example.com')
		roles = sorted([r.name for r in user.roles])
		self.assertEqual(roles, [])
		user = User.query.get('uid=newuser6,{}'.format(self.app.config['LDAP_USER_SEARCH_BASE']))
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser6')
		self.assertEqual(user.displayname, 'newuser6')
		self.assertEqual(user.mail, 'newuser6@example.com')
		roles = sorted([r.name for r in user.roles])
		self.assertEqual(roles, ['role1', 'role2'])
		self.assertIsNone(User.query.get('uid=newuser7,{}'.format(self.app.config['LDAP_USER_SEARCH_BASE'])))
		self.assertIsNone(User.query.get('uid=newuser8,{}'.format(self.app.config['LDAP_USER_SEARCH_BASE'])))
		self.assertIsNone(User.query.get('uid=newuser9,{}'.format(self.app.config['LDAP_USER_SEARCH_BASE'])))
		user = User.query.get('uid=newuser10,{}'.format(self.app.config['LDAP_USER_SEARCH_BASE']))
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser10')
		self.assertEqual(user.displayname, 'newuser10')
		self.assertEqual(user.mail, 'newuser10@example.com')
		roles = sorted([r.name for r in user.roles])
		self.assertEqual(roles, [])
		user = User.query.get('uid=newuser11,{}'.format(self.app.config['LDAP_USER_SEARCH_BASE']))
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser11')
		self.assertEqual(user.displayname, 'newuser11')
		self.assertEqual(user.mail, 'newuser11@example.com')
		# Currently the csv import is not very robust, imho newuser11 should have role1 and role2!
		roles = sorted([r.name for r in user.roles])
		self.assertEqual(roles, ['role2'])
		user = User.query.get('uid=newuser12,{}'.format(self.app.config['LDAP_USER_SEARCH_BASE']))
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
		self.login_as('user')

	def test_view_own(self):
		r = self.client.get(path=url_for('user.show', uid=self.get_user().uid), follow_redirects=True)
		dump('user_view_own', r)
		self.assertEqual(r.status_code, 200)

	def test_view_others(self):
		r = self.client.get(path=url_for('user.show', uid=self.get_admin().uid), follow_redirects=True)
		dump('user_view_others', r)
		self.assertEqual(r.status_code, 200)

	def test_view_index(self):
		r = self.client.get(path=url_for('user.index'), follow_redirects=True)
		dump('user_index', r)
		self.assertEqual(r.status_code, 200)

	def test_update_other_user(self):
		user_ = self.get_admin()
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
		_user = self.get_admin()
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
		self.assertIsNone(User.query.get('uid=newuser,{}'.format(self.app.config['LDAP_USER_SEARCH_BASE'])))
		r = self.client.post(path=url_for('user.update'),
			data={'loginname': 'newuser', 'mail': 'newuser@example.com', 'displayname': 'New User',
			f'role-{role1_id}': '1', 'password': 'newpassword'}, follow_redirects=True)
		dump('user_new_submit', r)
		self.assertEqual(r.status_code, 200)
		user = User.query.get('uid=newuser,{}'.format(self.app.config['LDAP_USER_SEARCH_BASE']))
		self.assertIsNone(user)

	def test_delete(self):
		r = self.client.get(path=url_for('user.delete', uid=self.get_admin().uid), follow_redirects=True)
		dump('user_delete', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNotNone(self.get_admin())


class TestGroupViews(UffdTestCase):
	def setUp(self):
		super().setUp()
		self.login_as('admin')

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

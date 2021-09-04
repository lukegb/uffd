from flask import url_for

from uffd.user.models import User, Group
from uffd.role.models import Role, RoleGroup
from uffd.database import db
from uffd.ldap import ldap

from utils import dump, UffdTestCase

class TestRolemodViewsLoggedOut(UffdTestCase):
	def test_acl_nologin(self):
		r = self.client.get(path=url_for('rolemod.index'), follow_redirects=True)
		dump('rolemod_acl_nologin', r)
		self.assertEqual(r.status_code, 200)

	def test_index(self):
		db.session.add(Role(name='test_role_1', moderator_group=self.get_access_group()))
		db.session.add(Role(name='test_role_2', moderator_group=self.get_admin_group()))
		db.session.add(Role(name='test_role_3'))
		db.session.commit()
		self.login_as('user')
		r = self.client.get(path=url_for('rolemod.index'), follow_redirects=True)
		dump('rolemod_index', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn('test_role_1'.encode(), r.data)
		self.assertNotIn('test_role_2'.encode(), r.data)
		self.assertNotIn('test_role_3'.encode(), r.data)

class TestRolemodViews(UffdTestCase):
	def setUp(self):
		super().setUp()
		self.login_as('user')

	def test_acl_notmod(self):
		db.session.add(Role(name='test', moderator_group=self.get_admin_group()))
		db.session.commit()
		r = self.client.get(path=url_for('rolemod.index'), follow_redirects=True)
		dump('rolemod_acl_notmod', r)
		self.assertEqual(r.status_code, 403)

	def test_show(self):
		role = Role(name='test', moderator_group=self.get_access_group())
		db.session.add(role)
		role.members.add(self.get_admin())
		db.session.commit()
		r = self.client.get(path=url_for('rolemod.show', role_id=role.id), follow_redirects=True)
		dump('rolemod_show', r)
		self.assertEqual(r.status_code, 200)

	def test_show_empty(self):
		role = Role(name='test', moderator_group=self.get_access_group())
		db.session.add(role)
		db.session.commit()
		r = self.client.get(path=url_for('rolemod.show', role_id=role.id), follow_redirects=True)
		dump('rolemod_show_empty', r)
		self.assertEqual(r.status_code, 200)

	def test_show_noperm(self):
		# Make sure we pass the blueprint-wide acl check
		db.session.add(Role(name='other_role', moderator_group=self.get_access_group()))
		role = Role(name='test', moderator_group=self.get_admin_group())
		db.session.add(role)
		db.session.commit()
		r = self.client.get(path=url_for('rolemod.show', role_id=role.id), follow_redirects=True)
		dump('rolemod_show_noperm', r)
		self.assertEqual(r.status_code, 403)

	def test_show_nomod(self):
		# Make sure we pass the blueprint-wide acl check
		db.session.add(Role(name='other_role', moderator_group=self.get_access_group()))
		role = Role(name='test')
		db.session.add(role)
		db.session.commit()
		r = self.client.get(path=url_for('rolemod.show', role_id=role.id), follow_redirects=True)
		dump('rolemod_show_nomod', r)
		self.assertEqual(r.status_code, 403)

	def test_update(self):
		role = Role(name='test', description='old_description', moderator_group=self.get_access_group())
		db.session.add(role)
		db.session.commit()
		r = self.client.post(path=url_for('rolemod.update', role_id=role.id), data={'description': 'new_description'}, follow_redirects=True)
		dump('rolemod_update', r)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(Role.query.get(role.id).description, 'new_description')

	def test_update_descr_too_long(self):
		role = Role(name='test', description='old_description', moderator_group=self.get_access_group())
		db.session.add(role)
		db.session.commit()
		r = self.client.post(path=url_for('rolemod.update', role_id=role.id), data={'description': 'long_description'*300}, follow_redirects=True)
		dump('rolemod_update_descr_too_long', r)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(Role.query.get(role.id).description, 'old_description')

	def test_update_noperm(self):
		# Make sure we pass the blueprint-wide acl check
		db.session.add(Role(name='other_role', moderator_group=self.get_access_group()))
		role = Role(name='test', description='old_description', moderator_group=self.get_admin_group())
		db.session.add(role)
		db.session.commit()
		r = self.client.post(path=url_for('rolemod.update', role_id=role.id), data={'description': 'new_description'}, follow_redirects=True)
		dump('rolemod_update_noperm', r)
		self.assertEqual(r.status_code, 403)
		self.assertEqual(Role.query.get(role.id).description, 'old_description')

	def test_update_nomod(self):
		# Make sure we pass the blueprint-wide acl check
		db.session.add(Role(name='other_role', moderator_group=self.get_access_group()))
		role = Role(name='test', description='old_description')
		db.session.add(role)
		db.session.commit()
		r = self.client.post(path=url_for('rolemod.update', role_id=role.id), data={'description': 'new_description'}, follow_redirects=True)
		dump('rolemod_update_nomod', r)
		self.assertEqual(r.status_code, 403)
		self.assertEqual(Role.query.get(role.id).description, 'old_description')

	def test_delete_member(self):
		role = Role(name='test', moderator_group=self.get_access_group())
		role.groups[self.get_admin_group()] = RoleGroup()
		db.session.add(role)
		role.members.add(self.get_admin())
		db.session.commit()
		role.update_member_groups()
		ldap.session.commit()
		user = self.get_admin()
		group = self.get_admin_group()
		self.assertTrue(user in group.members)
		role = Role.query.get(role.id)
		self.assertTrue(user in role.members)
		r = self.client.get(path=url_for('rolemod.delete_member', role_id=role.id, member_dn=user.dn), follow_redirects=True)
		dump('rolemod_delete_member', r)
		self.assertEqual(r.status_code, 200)
		user_updated = self.get_admin()
		group = self.get_admin_group()
		self.assertFalse(user_updated in group.members)
		role = Role.query.get(role.id)
		self.assertFalse(user_updated in role.members)

	def test_delete_member_nomember(self):
		role = Role(name='test', moderator_group=self.get_access_group())
		role.groups[self.get_admin_group()] = RoleGroup()
		db.session.add(role)
		db.session.commit()
		user = self.get_admin()
		r = self.client.get(path=url_for('rolemod.delete_member', role_id=role.id, member_dn=user.dn), follow_redirects=True)
		dump('rolemod_delete_member_nomember', r)
		self.assertEqual(r.status_code, 200)

	def test_delete_member_noperm(self):
		# Make sure we pass the blueprint-wide acl check
		db.session.add(Role(name='other_role', moderator_group=self.get_access_group()))
		role = Role(name='test', moderator_group=self.get_admin_group())
		db.session.add(role)
		role.members.add(self.get_admin())
		db.session.commit()
		user = self.get_admin()
		role = Role.query.get(role.id)
		self.assertTrue(user in role.members)
		r = self.client.get(path=url_for('rolemod.delete_member', role_id=role.id, member_dn=user.dn), follow_redirects=True)
		dump('rolemod_delete_member_noperm', r)
		self.assertEqual(r.status_code, 403)
		user_updated = self.get_admin()
		role = Role.query.get(role.id)
		self.assertTrue(user_updated in role.members)

	def test_delete_member_nomod(self):
		# Make sure we pass the blueprint-wide acl check
		db.session.add(Role(name='other_role', moderator_group=self.get_access_group()))
		role = Role(name='test')
		db.session.add(role)
		role.members.add(self.get_admin())
		db.session.commit()
		user = self.get_admin()
		role = Role.query.get(role.id)
		self.assertTrue(user in role.members)
		r = self.client.get(path=url_for('rolemod.delete_member', role_id=role.id, member_dn=user.dn), follow_redirects=True)
		dump('rolemod_delete_member_nomod', r)
		self.assertEqual(r.status_code, 403)
		user_updated = self.get_admin()
		role = Role.query.get(role.id)
		self.assertTrue(user_updated in role.members)


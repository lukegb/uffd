from flask import url_for

from uffd.user.models import User, Group
from uffd.role.models import Role
from uffd.database import db
from uffd.ldap import ldap

from utils import dump, UffdTestCase

class TestRolemodViews(UffdTestCase):
	def login(self):
		self.client.post(path=url_for('session.login'),
			data={'loginname': 'testuser', 'password': 'userpassword'}, follow_redirects=True)

	def test_acl_nologin(self):
		r = self.client.get(path=url_for('rolemod.index'), follow_redirects=True)
		dump('rolemod_acl_nologin', r)
		self.assertEqual(r.status_code, 200)

	def test_acl_notmod(self):
		self.login()
		db.session.add(Role(name='test', moderator_group=Group.query.get('cn=uffd_admin,ou=groups,dc=example,dc=com')))
		db.session.commit()
		r = self.client.get(path=url_for('rolemod.index'), follow_redirects=True)
		dump('rolemod_acl_notmod', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn('Access denied'.encode(), r.data)

	def test_index(self):
		db.session.add(Role(name='test_role_1', moderator_group=Group.query.get('cn=uffd_access,ou=groups,dc=example,dc=com')))
		db.session.add(Role(name='test_role_2', moderator_group=Group.query.get('cn=uffd_admin,ou=groups,dc=example,dc=com')))
		db.session.add(Role(name='test_role_3'))
		db.session.commit()
		self.login()
		r = self.client.get(path=url_for('rolemod.index'), follow_redirects=True)
		dump('rolemod_index', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn('test_role_1'.encode(), r.data)
		self.assertNotIn('test_role_2'.encode(), r.data)
		self.assertNotIn('test_role_3'.encode(), r.data)

	def test_show(self):
		self.login()
		role = Role(name='test', moderator_group=Group.query.get('cn=uffd_access,ou=groups,dc=example,dc=com'))
		db.session.add(role)
		role.members.add(User.query.get('uid=testadmin,ou=users,dc=example,dc=com'))
		db.session.commit()
		r = self.client.get(path=url_for('rolemod.show', role_id=role.id), follow_redirects=True)
		dump('rolemod_show', r)
		self.assertEqual(r.status_code, 200)

	def test_show_empty(self):
		self.login()
		role = Role(name='test', moderator_group=Group.query.get('cn=uffd_access,ou=groups,dc=example,dc=com'))
		db.session.add(role)
		db.session.commit()
		r = self.client.get(path=url_for('rolemod.show', role_id=role.id), follow_redirects=True)
		dump('rolemod_show_empty', r)
		self.assertEqual(r.status_code, 200)

	def test_show_noperm(self):
		self.login()
		# Make sure we pass the blueprint-wide acl check
		db.session.add(Role(name='other_role', moderator_group=Group.query.get('cn=uffd_access,ou=groups,dc=example,dc=com')))
		role = Role(name='test', moderator_group=Group.query.get('cn=uffd_admin,ou=groups,dc=example,dc=com'))
		db.session.add(role)
		db.session.commit()
		r = self.client.get(path=url_for('rolemod.show', role_id=role.id), follow_redirects=True)
		dump('rolemod_show_noperm', r)
		self.assertIn('Access denied'.encode(), r.data)

	def test_show_nomod(self):
		self.login()
		# Make sure we pass the blueprint-wide acl check
		db.session.add(Role(name='other_role', moderator_group=Group.query.get('cn=uffd_access,ou=groups,dc=example,dc=com')))
		role = Role(name='test')
		db.session.add(role)
		db.session.commit()
		r = self.client.get(path=url_for('rolemod.show', role_id=role.id), follow_redirects=True)
		dump('rolemod_show_nomod', r)
		self.assertIn('Access denied'.encode(), r.data)

	def test_update(self):
		self.login()
		role = Role(name='test', description='old_description', moderator_group=Group.query.get('cn=uffd_access,ou=groups,dc=example,dc=com'))
		db.session.add(role)
		db.session.commit()
		r = self.client.post(path=url_for('rolemod.update', role_id=role.id), data={'description': 'new_description'}, follow_redirects=True)
		dump('rolemod_update', r)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(Role.query.get(role.id).description, 'new_description')

	def test_update(self):
		self.login()
		role = Role(name='test', description='old_description', moderator_group=Group.query.get('cn=uffd_access,ou=groups,dc=example,dc=com'))
		db.session.add(role)
		db.session.commit()
		r = self.client.post(path=url_for('rolemod.update', role_id=role.id), data={'description': 'new_description'}, follow_redirects=True)
		dump('rolemod_update', r)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(Role.query.get(role.id).description, 'new_description')

	def test_update_descr_too_long(self):
		self.login()
		role = Role(name='test', description='old_description', moderator_group=Group.query.get('cn=uffd_access,ou=groups,dc=example,dc=com'))
		db.session.add(role)
		db.session.commit()
		r = self.client.post(path=url_for('rolemod.update', role_id=role.id), data={'description': 'long_description'*300}, follow_redirects=True)
		dump('rolemod_update_descr_too_long', r)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(Role.query.get(role.id).description, 'old_description')

	def test_update_noperm(self):
		self.login()
		# Make sure we pass the blueprint-wide acl check
		db.session.add(Role(name='other_role', moderator_group=Group.query.get('cn=uffd_access,ou=groups,dc=example,dc=com')))
		role = Role(name='test', description='old_description', moderator_group=Group.query.get('cn=uffd_admin,ou=groups,dc=example,dc=com'))
		db.session.add(role)
		db.session.commit()
		r = self.client.post(path=url_for('rolemod.update', role_id=role.id), data={'description': 'new_description'}, follow_redirects=True)
		dump('rolemod_update_noperm', r)
		self.assertIn('Access denied'.encode(), r.data)
		self.assertEqual(Role.query.get(role.id).description, 'old_description')

	def test_update_nomod(self):
		self.login()
		# Make sure we pass the blueprint-wide acl check
		db.session.add(Role(name='other_role', moderator_group=Group.query.get('cn=uffd_access,ou=groups,dc=example,dc=com')))
		role = Role(name='test', description='old_description')
		db.session.add(role)
		db.session.commit()
		r = self.client.post(path=url_for('rolemod.update', role_id=role.id), data={'description': 'new_description'}, follow_redirects=True)
		dump('rolemod_update_nomod', r)
		self.assertIn('Access denied'.encode(), r.data)
		self.assertEqual(Role.query.get(role.id).description, 'old_description')

	def test_delete_member(self):
		self.login()
		role = Role(name='test', moderator_group=Group.query.get('cn=uffd_access,ou=groups,dc=example,dc=com'), groups=[Group.query.get('cn=uffd_admin,ou=groups,dc=example,dc=com')])
		db.session.add(role)
		role.members.add(User.query.get('uid=testadmin,ou=users,dc=example,dc=com'))
		db.session.commit()
		role.update_member_groups()
		ldap.session.commit()
		user = User.query.get('uid=testadmin,ou=users,dc=example,dc=com')
		group = Group.query.get('cn=uffd_admin,ou=groups,dc=example,dc=com')
		self.assertTrue(user in group.members)
		role = Role.query.get(role.id)
		self.assertTrue(user in role.members)
		r = self.client.get(path=url_for('rolemod.delete_member', role_id=role.id, member_dn=user.dn), follow_redirects=True)
		dump('rolemod_delete_member', r)
		self.assertEqual(r.status_code, 200)
		user = User.query.get('uid=testadmin,ou=users,dc=example,dc=com')
		group = Group.query.get('cn=uffd_admin,ou=groups,dc=example,dc=com')
		self.assertFalse(user in group.members)
		role = Role.query.get(role.id)
		self.assertFalse(user in role.members)

	def test_delete_member_nomember(self):
		self.login()
		role = Role(name='test', moderator_group=Group.query.get('cn=uffd_access,ou=groups,dc=example,dc=com'), groups=[Group.query.get('cn=uffd_admin,ou=groups,dc=example,dc=com')])
		db.session.add(role)
		db.session.commit()
		user = User.query.get('uid=testadmin,ou=users,dc=example,dc=com')
		r = self.client.get(path=url_for('rolemod.delete_member', role_id=role.id, member_dn=user.dn), follow_redirects=True)
		dump('rolemod_delete_member_nomember', r)
		self.assertEqual(r.status_code, 200)

	def test_delete_member_noperm(self):
		self.login()
		# Make sure we pass the blueprint-wide acl check
		db.session.add(Role(name='other_role', moderator_group=Group.query.get('cn=uffd_access,ou=groups,dc=example,dc=com')))
		role = Role(name='test', moderator_group=Group.query.get('cn=uffd_admin,ou=groups,dc=example,dc=com'))
		db.session.add(role)
		role.members.add(User.query.get('uid=testadmin,ou=users,dc=example,dc=com'))
		db.session.commit()
		user = User.query.get('uid=testadmin,ou=users,dc=example,dc=com')
		role = Role.query.get(role.id)
		self.assertTrue(user in role.members)
		r = self.client.get(path=url_for('rolemod.delete_member', role_id=role.id, member_dn=user.dn), follow_redirects=True)
		dump('rolemod_delete_member_noperm', r)
		self.assertIn('Access denied'.encode(), r.data)
		user = User.query.get('uid=testadmin,ou=users,dc=example,dc=com')
		role = Role.query.get(role.id)
		self.assertTrue(user in role.members)

	def test_delete_member_nomod(self):
		self.login()
		# Make sure we pass the blueprint-wide acl check
		db.session.add(Role(name='other_role', moderator_group=Group.query.get('cn=uffd_access,ou=groups,dc=example,dc=com')))
		role = Role(name='test')
		db.session.add(role)
		role.members.add(User.query.get('uid=testadmin,ou=users,dc=example,dc=com'))
		db.session.commit()
		user = User.query.get('uid=testadmin,ou=users,dc=example,dc=com')
		role = Role.query.get(role.id)
		self.assertTrue(user in role.members)
		r = self.client.get(path=url_for('rolemod.delete_member', role_id=role.id, member_dn=user.dn), follow_redirects=True)
		dump('rolemod_delete_member_nomod', r)
		self.assertIn('Access denied'.encode(), r.data)
		user = User.query.get('uid=testadmin,ou=users,dc=example,dc=com')
		role = Role.query.get(role.id)
		self.assertTrue(user in role.members)


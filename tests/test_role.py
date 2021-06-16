import datetime
import time

from flask import url_for, session

# These imports are required, because otherwise we get circular imports?!
from uffd.ldap import ldap
from uffd import user

from uffd.user.models import User, Group
from uffd.role.models import Role
from uffd import create_app, db

from utils import dump, UffdTestCase

class TestUserRoleAttributes(UffdTestCase):
	def test_roles_recursive(self):
		user1 = User.query.get('uid=testuser,ou=users,dc=example,dc=com')
		user1.update_groups()
		included_role = Role(name='included')
		default_role = Role(name='default', is_default=True)
		role1 = Role(name='role1', members=[user1], included_roles=[included_role])
		role2 = Role(name='role2', included_roles=[included_role])
		db.session.add_all([included_role, default_role, role1, role2])
		self.assertSetEqual(user1.roles_recursive, {included_role, default_role, role1})
		included_role.included_roles.append(role2)
		self.assertSetEqual(user1.roles_recursive, {included_role, default_role, role1, role2})

	def test_update_groups(self):
		user1 = User.query.get('uid=testuser,ou=users,dc=example,dc=com')
		user1.update_groups()
		self.assertSetEqual(set(user1.groups), set())
		group1 = Group.query.get('cn=users,ou=groups,dc=example,dc=com')
		group2 = Group.query.get('cn=uffd_access,ou=groups,dc=example,dc=com')
		baserole = Role(name='base', groups=[group1])
		role1 = Role(name='role1', groups=[group2], members=[user1])
		db.session.add_all([baserole, role1])
		user1.update_groups()
		self.assertSetEqual(set(user1.groups), {group2})
		role1.included_roles.append(baserole)
		user1.update_groups()
		self.assertSetEqual(set(user1.groups), {group1, group2})

class TestRoleModel(UffdTestCase):
	def test_indirect_members(self):
		user1 = User.query.get('uid=testuser,ou=users,dc=example,dc=com')
		user2 = User.query.get('uid=testadmin,ou=users,dc=example,dc=com')
		included_role = Role(name='included', members=[user1])
		default_role = Role(name='default', is_default=True)
		role1 = Role(name='role1', included_roles=[included_role], members=[user2])
		self.assertSetEqual(included_role.indirect_members, {user2})
		self.assertSetEqual(default_role.indirect_members, {user1, user2})
		self.assertSetEqual(role1.indirect_members, set())

	def test_included_roles_recursive(self):
		baserole = Role(name='base')
		role1 = Role(name='role1', included_roles=[baserole])
		role2 = Role(name='role2', included_roles=[baserole])
		role3 = Role(name='role3', included_roles=[role1, role2])
		self.assertSetEqual(role1.included_roles_recursive, {baserole})
		self.assertSetEqual(role2.included_roles_recursive, {baserole})
		self.assertSetEqual(role3.included_roles_recursive, {baserole, role1, role2})
		baserole.included_roles.append(role1)
		self.assertSetEqual(role3.included_roles_recursive, {baserole, role1, role2})

	def test_included_groups(self):
		group1 = Group.query.get('cn=users,ou=groups,dc=example,dc=com')
		group2 = Group.query.get('cn=uffd_access,ou=groups,dc=example,dc=com')
		baserole = Role(name='base', groups=[group1])
		role1 = Role(name='role1', groups=[group2], included_roles=[baserole])
		self.assertSetEqual(baserole.included_groups, set())
		self.assertSetEqual(role1.included_groups, {group1})

	def test_update_member_groups(self):
		user1 = User.query.get('uid=testuser,ou=users,dc=example,dc=com')
		user1.update_groups()
		user2 = User.query.get('uid=testadmin,ou=users,dc=example,dc=com')
		user2.update_groups()
		group1 = Group.query.get('cn=users,ou=groups,dc=example,dc=com')
		group2 = Group.query.get('cn=uffd_access,ou=groups,dc=example,dc=com')
		group3 = Group.query.get('cn=uffd_admin,ou=groups,dc=example,dc=com')
		baserole = Role(name='base', members=[user1], groups=[group1])
		role1 = Role(name='role1', members=[user2], groups=[group2], included_roles=[baserole])
		db.session.add_all([baserole, role1])
		baserole.update_member_groups()
		role1.update_member_groups()
		self.assertSetEqual(set(user1.groups), {group1})
		self.assertSetEqual(set(user2.groups), {group1, group2})
		baserole.groups.add(group3)
		baserole.update_member_groups()
		self.assertSetEqual(set(user1.groups), {group1, group3})
		self.assertSetEqual(set(user2.groups), {group1, group2, group3})

class TestRoleViews(UffdTestCase):
	def setUp(self):
		super().setUp()
		self.client.post(path=url_for('session.login'),
			data={'loginname': 'testadmin', 'password': 'adminpassword'}, follow_redirects=True)

	def test_index(self):
		db.session.add(Role(name='base', description='Base role description'))
		db.session.add(Role(name='test1', description='Test1 role description'))
		db.session.commit()
		r = self.client.get(path=url_for('role.index'), follow_redirects=True)
		dump('role_index', r)
		self.assertEqual(r.status_code, 200)

	def test_index_empty(self):
		r = self.client.get(path=url_for('role.index'), follow_redirects=True)
		dump('role_index_empty', r)
		self.assertEqual(r.status_code, 200)

	def test_show(self):
		role = Role(name='base', description='Base role description')
		db.session.add(role)
		db.session.commit()
		r = self.client.get(path=url_for('role.show', roleid=role.id), follow_redirects=True)
		dump('role_show', r)
		self.assertEqual(r.status_code, 200)

	def test_new(self):
		r = self.client.get(path=url_for('role.new'), follow_redirects=True)
		dump('role_new', r)
		self.assertEqual(r.status_code, 200)

	def test_update(self):
		role = Role(name='base', description='Base role description')
		db.session.add(role)
		db.session.commit()
		role.groups.add(Group.query.get('cn=uffd_admin,ou=groups,dc=example,dc=com'))
		db.session.commit()
		self.assertEqual(role.name, 'base')
		self.assertEqual(role.description, 'Base role description')
		self.assertEqual([group.dn for group in role.groups], ['cn=uffd_admin,ou=groups,dc=example,dc=com'])
		r = self.client.post(path=url_for('role.update', roleid=role.id),
			data={'name': 'base1', 'description': 'Base role description1', 'moderator-group': '', 'group-20001': '1', 'group-20002': '1'},
			follow_redirects=True)
		dump('role_update', r)
		self.assertEqual(r.status_code, 200)
		role = Role.query.get(role.id)
		self.assertEqual(role.name, 'base1')
		self.assertEqual(role.description, 'Base role description1')
		self.assertEqual(sorted([group.dn for group in role.groups]), ['cn=uffd_access,ou=groups,dc=example,dc=com',
			'cn=users,ou=groups,dc=example,dc=com'])
		# TODO: verify that group memberships are updated (currently not possible with ldap mock!)

	def test_create(self):
		self.assertIsNone(Role.query.filter_by(name='base').first())
		r = self.client.post(path=url_for('role.update'),
			data={'name': 'base', 'description': 'Base role description', 'moderator-group': '', 'group-20001': '1', 'group-20002': '1'},
			follow_redirects=True)
		dump('role_create', r)
		self.assertEqual(r.status_code, 200)
		role = Role.query.filter_by(name='base').first()
		self.assertIsNotNone(role)
		self.assertEqual(role.name, 'base')
		self.assertEqual(role.description, 'Base role description')
		self.assertEqual(sorted([group.dn for group in role.groups]), ['cn=uffd_access,ou=groups,dc=example,dc=com',
			'cn=users,ou=groups,dc=example,dc=com'])
		# TODO: verify that group memberships are updated (currently not possible with ldap mock!)

	def test_create_with_moderator_group(self):
		self.assertIsNone(Role.query.filter_by(name='base').first())
		r = self.client.post(path=url_for('role.update'),
			data={'name': 'base', 'description': 'Base role description', 'moderator-group': 'cn=uffd_admin,ou=groups,dc=example,dc=com', 'group-20001': '1', 'group-20002': '1'},
			follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		role = Role.query.filter_by(name='base').first()
		self.assertIsNotNone(role)
		self.assertEqual(role.name, 'base')
		self.assertEqual(role.description, 'Base role description')
		self.assertEqual(role.moderator_group.name, 'uffd_admin')
		self.assertEqual(sorted([group.dn for group in role.groups]), ['cn=uffd_access,ou=groups,dc=example,dc=com',
			'cn=users,ou=groups,dc=example,dc=com'])
		# TODO: verify that group memberships are updated (currently not possible with ldap mock!)

	def test_delete(self):
		role = Role(name='base', description='Base role description')
		db.session.add(role)
		db.session.commit()
		role_id = role.id
		self.assertIsNotNone(Role.query.get(role_id))
		r = self.client.get(path=url_for('role.delete', roleid=role.id), follow_redirects=True)
		dump('role_delete', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(Role.query.get(role_id))
		# TODO: verify that group memberships are updated (currently not possible with ldap mock!)

	def test_set_default(self):
		for user in User.query.filter_by(loginname='service').all():
			ldap.session.delete(user)
		ldap.session.add(User(loginname='service', is_service_user=True, mail='service@example.com', displayname='Service'))
		ldap.session.commit()
		role = Role(name='test')
		db.session.add(role)
		user1 = User.query.get('uid=testuser,ou=users,dc=example,dc=com')
		user2 = User.query.get('uid=testadmin,ou=users,dc=example,dc=com')
		service_user = User.query.get('uid=service,ou=users,dc=example,dc=com')
		self.assertSetEqual(set(user1.roles_recursive), set())
		self.assertSetEqual(set(user2.roles_recursive), set())
		self.assertSetEqual(set(service_user.roles_recursive), set())
		role.members.add(user1)
		role.members.add(service_user)
		self.assertSetEqual(set(user1.roles_recursive), {role})
		self.assertSetEqual(set(user2.roles_recursive), set())
		self.assertSetEqual(set(service_user.roles_recursive), {role})
		db.session.commit()
		role_id = role.id
		self.assertSetEqual(set(role.members), {user1, service_user})
		r = self.client.get(path=url_for('role.set_default', roleid=role.id), follow_redirects=True)
		dump('role_set_default', r)
		self.assertEqual(r.status_code, 200)
		role = Role.query.get(role_id)
		service_user = User.query.get('uid=service,ou=users,dc=example,dc=com')
		self.assertSetEqual(set(role.members), {service_user})
		self.assertSetEqual(set(user1.roles_recursive), {role})
		self.assertSetEqual(set(user2.roles_recursive), {role})
		ldap.session.delete(service_user)
		ldap.session.commit()

	def test_unset_default(self):
		for user in User.query.filter_by(loginname='service').all():
			ldap.session.delete(user)
		ldap.session.add(User(loginname='service', is_service_user=True, mail='service@example.com', displayname='Service'))
		ldap.session.commit()
		role = Role(name='test', is_default=True)
		db.session.add(role)
		user1 = User.query.get('uid=testuser,ou=users,dc=example,dc=com')
		user2 = User.query.get('uid=testadmin,ou=users,dc=example,dc=com')
		service_user = User.query.get('uid=service,ou=users,dc=example,dc=com')
		role.members.add(service_user)
		self.assertSetEqual(set(user1.roles_recursive), {role})
		self.assertSetEqual(set(user2.roles_recursive), {role})
		self.assertSetEqual(set(service_user.roles_recursive), {role})
		db.session.commit()
		role_id = role.id
		self.assertSetEqual(set(role.members), {service_user})
		r = self.client.get(path=url_for('role.unset_default', roleid=role.id), follow_redirects=True)
		dump('role_unset_default', r)
		self.assertEqual(r.status_code, 200)
		role = Role.query.get(role_id)
		service_user = User.query.get('uid=service,ou=users,dc=example,dc=com')
		self.assertSetEqual(set(role.members), {service_user})
		self.assertSetEqual(set(user1.roles_recursive), set())
		self.assertSetEqual(set(user2.roles_recursive), set())
		ldap.session.delete(service_user)
		ldap.session.commit()

class TestRoleViewsOL(TestRoleViews):
	use_openldap = True

import datetime
import time
import unittest

from flask import url_for, session

# These imports are required, because otherwise we get circular imports?!
from uffd import user

from uffd.user.models import User, Group
from uffd.role.models import flatten_recursive, Role, RoleGroup
from uffd.mfa.models import TOTPMethod
from uffd import create_app, db

from utils import dump, UffdTestCase

class TestPrimitives(unittest.TestCase):
	def test_flatten_recursive(self):
		class Node:
			def __init__(self, *neighbors):
				self.neighbors = set(neighbors or set())

		cycle = Node()
		cycle.neighbors.add(cycle)
		common = Node(cycle)
		intermediate1 = Node(common)
		intermediate2 = Node(common, intermediate1)
		stub = Node()
		backref = Node()
		start1 = Node(intermediate1, intermediate2, stub, backref)
		backref.neighbors.add(start1)
		start2 = Node()
		self.assertSetEqual(flatten_recursive({start1, start2}, 'neighbors'),
		                    {start1, start2, backref, stub, intermediate1, intermediate2, common, cycle})
		self.assertSetEqual(flatten_recursive(set(), 'neighbors'), set())

class TestUserRoleAttributes(UffdTestCase):
	def test_roles_effective(self):
		db.session.add(User(loginname='service', is_service_user=True, mail='service@example.com', displayname='Service'))
		db.session.commit()
		user = self.get_user()
		service_user = User.query.filter_by(loginname='service').one_or_none()
		included_by_default_role = Role(name='included_by_default')
		default_role = Role(name='default', is_default=True, included_roles=[included_by_default_role])
		included_role = Role(name='included')
		cycle_role = Role(name='cycle')
		direct_role1 = Role(name='role1', members=[user, service_user], included_roles=[included_role, cycle_role])
		direct_role2 = Role(name='role2', members=[user, service_user], included_roles=[included_role])
		cycle_role.included_roles.append(direct_role1)
		db.session.add_all([included_by_default_role, default_role, included_role, cycle_role, direct_role1, direct_role2])
		self.assertSetEqual(user.roles_effective, {direct_role1, direct_role2, cycle_role, included_role, default_role, included_by_default_role})
		self.assertSetEqual(service_user.roles_effective, {direct_role1, direct_role2, cycle_role, included_role})

	def test_compute_groups(self):
		user = self.get_user()
		group1 = self.get_users_group()
		group2 = self.get_access_group()
		role1 = Role(name='role1', groups={group1: RoleGroup(group=group1)})
		role2 = Role(name='role2', groups={group1: RoleGroup(group=group1), group2: RoleGroup(group=group2)})
		db.session.add_all([role1, role2])
		self.assertSetEqual(user.compute_groups(), set())
		role1.members.append(user)
		role2.members.append(user)
		self.assertSetEqual(user.compute_groups(), {group1, group2})
		role2.groups[group2].requires_mfa = True
		self.assertSetEqual(user.compute_groups(), {group1})
		db.session.add(TOTPMethod(user=user))
		self.assertSetEqual(user.compute_groups(), {group1, group2})

	def test_update_groups(self):
		user = self.get_user()
		group1 = self.get_users_group()
		group2 = self.get_access_group()
		role1 = Role(name='role1', members=[user], groups={group1: RoleGroup(group=group1)})
		role2 = Role(name='role2', groups={group2: RoleGroup(group=group2)})
		db.session.add_all([role1, role2])
		user.groups = [group2]
		groups_added, groups_removed = user.update_groups()
		self.assertSetEqual(groups_added, {group1})
		self.assertSetEqual(groups_removed, {group2})
		self.assertSetEqual(set(user.groups), {group1})
		groups_added, groups_removed = user.update_groups()
		self.assertSetEqual(groups_added, set())
		self.assertSetEqual(groups_removed, set())
		self.assertSetEqual(set(user.groups), {group1})

class TestRoleModel(UffdTestCase):
	def test_members_effective(self):
		db.session.add(User(loginname='service', is_service_user=True, mail='service@example.com', displayname='Service'))
		db.session.commit()
		user1 = self.get_user()
		user2 = self.get_admin()
		service = User.query.filter_by(loginname='service').one_or_none()
		included_by_default_role = Role(name='included_by_default')
		default_role = Role(name='default', is_default=True, included_roles=[included_by_default_role])
		included_role = Role(name='included')
		direct_role = Role(name='direct', members=[user1, user2, service], included_roles=[included_role])
		empty_role = Role(name='empty', included_roles=[included_role])
		self.assertSetEqual(included_by_default_role.members_effective, {user1, user2})
		self.assertSetEqual(default_role.members_effective, {user1, user2})
		self.assertSetEqual(included_role.members_effective, {user1, user2, service})
		self.assertSetEqual(direct_role.members_effective, {user1, user2, service})
		self.assertSetEqual(empty_role.members_effective, set())

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

	def test_groups_effective(self):
		group1 = self.get_users_group()
		group2 = self.get_access_group()
		baserole = Role(name='base', groups={group1: RoleGroup(group=group1)})
		role1 = Role(name='role1', groups={group2: RoleGroup(group=group2)}, included_roles=[baserole])
		self.assertSetEqual(baserole.groups_effective, {group1})
		self.assertSetEqual(role1.groups_effective, {group1, group2})

	def test_update_member_groups(self):
		user1 = self.get_user()
		user1.update_groups()
		user2 = self.get_admin()
		user2.update_groups()
		group1 = self.get_users_group()
		group2 = self.get_access_group()
		group3 = self.get_admin_group()
		baserole = Role(name='base', members=[user1], groups={group1: RoleGroup(group=group1)})
		role1 = Role(name='role1', members=[user2], groups={group2: RoleGroup(group=group2)}, included_roles=[baserole])
		db.session.add_all([baserole, role1])
		baserole.update_member_groups()
		role1.update_member_groups()
		self.assertSetEqual(set(user1.groups), {group1})
		self.assertSetEqual(set(user2.groups), {group1, group2})
		baserole.groups[group3] = RoleGroup()
		baserole.update_member_groups()
		self.assertSetEqual(set(user1.groups), {group1, group3})
		self.assertSetEqual(set(user2.groups), {group1, group2, group3})

class TestRoleViews(UffdTestCase):
	def setUp(self):
		super().setUp()
		self.login_as('admin')

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
		role.groups[self.get_admin_group()] = RoleGroup()
		db.session.commit()
		self.assertEqual(role.name, 'base')
		self.assertEqual(role.description, 'Base role description')
		self.assertSetEqual(set(role.groups), {self.get_admin_group()})
		r = self.client.post(path=url_for('role.update', roleid=role.id),
			data={'name': 'base1', 'description': 'Base role description1', 'moderator-group': '', 'group-%d'%self.get_users_group().id: '1', 'group-%d'%self.get_access_group().id: '1'},
			follow_redirects=True)
		dump('role_update', r)
		self.assertEqual(r.status_code, 200)
		role = Role.query.get(role.id)
		self.assertEqual(role.name, 'base1')
		self.assertEqual(role.description, 'Base role description1')
		self.assertSetEqual(set(role.groups), {self.get_access_group(), self.get_users_group()})
		# TODO: verify that group memberships are updated (currently not possible with ldap mock!)

	def test_create(self):
		self.assertIsNone(Role.query.filter_by(name='base').first())
		r = self.client.post(path=url_for('role.update'),
			data={'name': 'base', 'description': 'Base role description', 'moderator-group': '', 'group-%d'%self.get_users_group().id: '1', 'group-%d'%self.get_access_group().id: '1'},
			follow_redirects=True)
		dump('role_create', r)
		self.assertEqual(r.status_code, 200)
		role = Role.query.filter_by(name='base').first()
		self.assertIsNotNone(role)
		self.assertEqual(role.name, 'base')
		self.assertEqual(role.description, 'Base role description')
		self.assertSetEqual(set(role.groups), {self.get_access_group(), self.get_users_group()})
		# TODO: verify that group memberships are updated (currently not possible with ldap mock!)

	def test_create_with_moderator_group(self):
		self.assertIsNone(Role.query.filter_by(name='base').first())
		r = self.client.post(path=url_for('role.update'),
			data={'name': 'base', 'description': 'Base role description', 'moderator-group': self.get_admin_group().id, 'group-%d'%self.get_users_group().id: '1', 'group-%d'%self.get_access_group().id: '1'},
			follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		role = Role.query.filter_by(name='base').first()
		self.assertIsNotNone(role)
		self.assertEqual(role.name, 'base')
		self.assertEqual(role.description, 'Base role description')
		self.assertEqual(role.moderator_group.name, 'uffd_admin')
		self.assertSetEqual(set(role.groups), {self.get_access_group(), self.get_users_group()})
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
		db.session.add(User(loginname='service', is_service_user=True, mail='service@example.com', displayname='Service'))
		db.session.commit()
		role = Role(name='test')
		db.session.add(role)
		role.groups[self.get_admin_group()] = RoleGroup()
		user1 = self.get_user()
		user2 = self.get_admin()
		service_user = User.query.filter_by(loginname='service').one_or_none()
		self.assertSetEqual(set(self.get_user().roles_effective), set())
		self.assertSetEqual(set(self.get_admin().roles_effective), set())
		self.assertSetEqual(set(service_user.roles_effective), set())
		role.members.append(self.get_user())
		role.members.append(service_user)
		self.assertSetEqual(set(self.get_user().roles_effective), {role})
		self.assertSetEqual(set(self.get_admin().roles_effective), set())
		self.assertSetEqual(set(service_user.roles_effective), {role})
		db.session.commit()
		role_id = role.id
		self.assertSetEqual(set(role.members), {self.get_user(), service_user})
		r = self.client.get(path=url_for('role.set_default', roleid=role.id), follow_redirects=True)
		dump('role_set_default', r)
		self.assertEqual(r.status_code, 200)
		role = Role.query.get(role_id)
		service_user = User.query.filter_by(loginname='service').one_or_none()
		self.assertSetEqual(set(role.members), {service_user})
		self.assertSetEqual(set(self.get_user().roles_effective), {role})
		self.assertSetEqual(set(self.get_admin().roles_effective), {role})

	def test_unset_default(self):
		admin_role = Role(name='admin', is_default=True)
		db.session.add(admin_role)
		admin_role.groups[self.get_admin_group()] = RoleGroup()
		db.session.add(User(loginname='service', is_service_user=True, mail='service@example.com', displayname='Service'))
		db.session.commit()
		role = Role(name='test', is_default=True)
		db.session.add(role)
		service_user = User.query.filter_by(loginname='service').one_or_none()
		role.members.append(service_user)
		self.assertSetEqual(set(self.get_user().roles_effective), {role, admin_role})
		self.assertSetEqual(set(self.get_admin().roles_effective), {role, admin_role})
		self.assertSetEqual(set(service_user.roles_effective), {role})
		db.session.commit()
		role_id = role.id
		admin_role_id = admin_role.id
		self.assertSetEqual(set(role.members), {service_user})
		r = self.client.get(path=url_for('role.unset_default', roleid=role.id), follow_redirects=True)
		dump('role_unset_default', r)
		self.assertEqual(r.status_code, 200)
		role = Role.query.get(role_id)
		admin_role = Role.query.get(admin_role_id)
		service_user = User.query.filter_by(loginname='service').one_or_none()
		self.assertSetEqual(set(role.members), {service_user})
		self.assertSetEqual(set(self.get_user().roles_effective), {admin_role})
		self.assertSetEqual(set(self.get_admin().roles_effective), {admin_role})

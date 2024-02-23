import unittest

from uffd.database import db
from uffd.models import User, Role, RoleGroup, TOTPMethod
from uffd.models.role import flatten_recursive

from tests.utils import UffdTestCase

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
		db.session.add(User(loginname='service', is_service_user=True, primary_email_address='service@example.com', displayname='Service'))
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
		db.session.commit()
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
		db.session.add(User(loginname='service', is_service_user=True, primary_email_address='service@example.com', displayname='Service'))
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

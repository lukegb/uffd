from uffd.database import db
from uffd.models import User, Role, RoleGroup

from tests.utils import UffdTestCase

class TestRoleCLI(UffdTestCase):
	def setUp(self):
		super().setUp()
		role = Role(name='admin')
		db.session.add(role)
		role.groups[self.get_admin_group()] = RoleGroup(group=self.get_admin_group())
		role.members.append(self.get_admin())
		role = Role(name='base', is_default=True)
		db.session.add(role)
		role.groups[self.get_access_group()] = RoleGroup(group=self.get_access_group())
		db.session.add(Role(name='test'))
		for user in User.query:
			user.update_groups()
		db.session.commit()
		self.client.__exit__(None, None, None)

	def test_list(self):
		result = self.app.test_cli_runner().invoke(args=['role', 'list'])
		self.assertEqual(result.exit_code, 0)

	def test_show(self):
		result = self.app.test_cli_runner().invoke(args=['role', 'show', 'admin'])
		self.assertEqual(result.exit_code, 0)
		result = self.app.test_cli_runner().invoke(args=['role', 'show', 'doesnotexist'])
		self.assertEqual(result.exit_code, 1)

	def test_create(self):
		result = self.app.test_cli_runner().invoke(args=['role', 'create', 'test']) # conflicting name
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['role', 'create', 'newrole', '--moderator-group', 'doesnotexist']) # invalid mod group
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['role', 'create', 'newrole', '--add-group', 'doesnotexist']) # invalid group
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['role', 'create', 'newrole', '--add-role', 'doesnotexist']) # invalid role
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['role', 'create', 'newrole', '--description', 'Role description',
		                                                 '--moderator-group', 'uffd_admin', '--add-group', 'users',
		                                                 '--add-role', 'admin'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			role = Role.query.filter_by(name='newrole').one()
			self.assertIsNotNone(role)
			self.assertEqual(role.description, 'Role description')
			self.assertEqual(role.moderator_group, self.get_admin_group())
			self.assertEqual(list(role.groups), [self.get_users_group()])
			self.assertEqual(role.included_roles, Role.query.filter_by(name='admin').all())
		with self.app.test_request_context():
			for user in User.query:
				self.assertNotIn(self.get_users_group(), user.groups)
		result = self.app.test_cli_runner().invoke(args=['role', 'create', 'newbase', '--add-group', 'users', '--default'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			for user in User.query:
				self.assertIn(self.get_users_group(), user.groups)

	def test_update(self):
		result = self.app.test_cli_runner().invoke(args=['role', 'update', 'doesnotexist', '--description', 'New description'])
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['role', 'update', 'test', '--add-group', 'doesnotexist'])
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['role', 'update', 'test', '--remove-group', 'doesnotexist'])
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['role', 'update', 'test', '--add-role', 'doesnotexist'])
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['role', 'update', 'test', '--remove-role', 'doesnotexist'])
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['role', 'update', 'test', '--moderator-group', 'doesnotexist'])
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['role', 'update', 'base', '--description', 'New description',
		                                                 '--moderator-group', 'uffd_admin', '--add-group', 'users',
		                                                 '--remove-group', 'uffd_access', '--add-role', 'admin'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			role = Role.query.filter_by(name='base').first()
			self.assertIsNotNone(role)
			self.assertEqual(role.description, 'New description')
			self.assertEqual(role.moderator_group, self.get_admin_group())
			self.assertEqual(list(role.groups), [self.get_users_group()])
			self.assertEqual(role.included_roles, Role.query.filter_by(name='admin').all())
			self.assertEqual(set(self.get_user().groups), {self.get_users_group(), self.get_admin_group()})
		result = self.app.test_cli_runner().invoke(args=['role', 'update', 'base', '--no-moderator-group', '--clear-groups',
		                                                 '--add-group', 'uffd_access', '--remove-role', 'admin',
		                                                 '--add-role', 'test'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			role = Role.query.filter_by(name='base').first()
			self.assertIsNone(role.moderator_group)
			self.assertEqual(list(role.groups), [self.get_access_group()])
			self.assertEqual(role.included_roles, Role.query.filter_by(name='test').all())
			self.assertEqual(set(self.get_user().groups), {self.get_access_group()})
		result = self.app.test_cli_runner().invoke(args=['role', 'update', 'base', '--clear-roles'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			role = Role.query.filter_by(name='base').first()
			self.assertEqual(role.included_roles, [])
			self.assertEqual(role.is_default, True)
			self.assertEqual(set(self.get_user().groups), {self.get_access_group()})
		result = self.app.test_cli_runner().invoke(args=['role', 'update', 'base', '--no-default'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			role = Role.query.filter_by(name='base').first()
			self.assertEqual(role.is_default, False)
			self.assertEqual(set(self.get_user().groups), set())
		result = self.app.test_cli_runner().invoke(args=['role', 'update', 'base', '--default'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			role = Role.query.filter_by(name='base').first()
			self.assertEqual(role.is_default, True)
			self.assertEqual(set(self.get_user().groups), {self.get_access_group()})

	# Regression test for https://git.cccv.de/uffd/uffd/-/issues/156
	def test_update_without_description(self):
		with self.app.test_request_context():
			role = Role.query.filter_by(name='test').first()
			role.description = 'Test description'
			db.session.commit()
		result = self.app.test_cli_runner().invoke(args=['role', 'update', 'test', '--clear-groups'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			role = Role.query.filter_by(name='test').first()
			self.assertEqual(role.description, 'Test description')

	def test_delete(self):
		with self.app.test_request_context():
			self.assertIsNotNone(Role.query.filter_by(name='test').first())
		result = self.app.test_cli_runner().invoke(args=['role', 'delete', 'test'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			self.assertIsNone(Role.query.filter_by(name='test').first())
		result = self.app.test_cli_runner().invoke(args=['role', 'delete', 'doesnotexist'])
		self.assertEqual(result.exit_code, 1)
		with self.app.test_request_context():
			self.assertIn(self.get_admin_group(), self.get_admin().groups)
		result = self.app.test_cli_runner().invoke(args=['role', 'delete', 'admin'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			self.assertNotIn(self.get_admin_group(), self.get_admin().groups)
		with self.app.test_request_context():
			self.assertIn(self.get_access_group(), self.get_user().groups)
		result = self.app.test_cli_runner().invoke(args=['role', 'delete', 'base'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			self.assertNotIn(self.get_access_group(), self.get_user().groups)

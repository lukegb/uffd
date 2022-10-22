from uffd.database import db
from uffd.models import User, Group, Role, RoleGroup

from tests.utils import UffdTestCase

class TestUserCLI(UffdTestCase):
	def setUp(self):
		super().setUp()
		role = Role(name='admin')
		role.groups[self.get_admin_group()] = RoleGroup(group=self.get_admin_group())
		db.session.add(role)
		db.session.add(Role(name='test'))
		db.session.commit()
		self.client.__exit__(None, None, None)

	def test_list(self):
		result = self.app.test_cli_runner().invoke(args=['user', 'list'])
		self.assertEqual(result.exit_code, 0)

	def test_show(self):
		result = self.app.test_cli_runner().invoke(args=['user', 'show', 'testuser'])
		self.assertEqual(result.exit_code, 0)
		result = self.app.test_cli_runner().invoke(args=['user', 'show', 'doesnotexist'])
		self.assertEqual(result.exit_code, 1)

	def test_create(self):
		result = self.app.test_cli_runner().invoke(args=['user', 'create', 'new user', '--mail', 'foobar@example.com']) # invalid login name
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['user', 'create', 'newuser', '--mail', '']) # invalid mail
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['user', 'create', 'newuser', '--mail', 'foobar@example.com', '--password', '']) # invalid password
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['user', 'create', 'newuser', '--mail', 'foobar@example.com', '--displayname', '']) # invalid display name
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['user', 'create', 'newuser', '--mail', 'foobar@example.com', '--add-role', 'doesnotexist']) # unknown role
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['user', 'create', 'testuser', '--mail', 'foobar@example.com']) # conflicting name
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['user', 'create', 'newuser', '--mail', 'newmail@example.com',
		                                                 '--displayname', 'New Display Name', '--password', 'newpassword', '--add-role', 'admin'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			user = User.query.filter_by(loginname='newuser').first()
			self.assertIsNotNone(user)
			self.assertEqual(user.primary_email.address, 'newmail@example.com')
			self.assertEqual(user.displayname, 'New Display Name')
			self.assertTrue(user.password.verify('newpassword'))
			self.assertEqual(user.roles, Role.query.filter_by(name='admin').all())
			self.assertIn(self.get_admin_group(), user.groups)

	def test_update(self):
		result = self.app.test_cli_runner().invoke(args=['user', 'update', 'doesnotexist', '--displayname', 'foo'])
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['user', 'update', 'testuser', '--mail', '']) # invalid mail
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['user', 'update', 'testuser', '--password', '']) # invalid password
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['user', 'update', 'testuser', '--displayname', '']) # invalid display name
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['user', 'update', 'testuser', '--remove-role', 'doesnotexist'])
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['user', 'update', 'testuser', '--mail', 'newmail@example.com',
		                                                 '--displayname', 'New Display Name', '--password', 'newpassword'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			user = User.query.filter_by(loginname='testuser').first()
			self.assertIsNotNone(user)
			self.assertEqual(user.primary_email.address, 'newmail@example.com')
			self.assertEqual(user.displayname, 'New Display Name')
			self.assertTrue(user.password.verify('newpassword'))
		result = self.app.test_cli_runner().invoke(args=['user', 'update', 'testuser', '--add-role', 'admin', '--add-role', 'test'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			user = User.query.filter_by(loginname='testuser').first()
			self.assertEqual(set(user.roles), {Role.query.filter_by(name='admin').one(), Role.query.filter_by(name='test').one()})
			self.assertIn(self.get_admin_group(), user.groups)
		result = self.app.test_cli_runner().invoke(args=['user', 'update', 'testuser', '--remove-role', 'admin'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			user = User.query.filter_by(loginname='testuser').first()
			self.assertEqual(user.roles, Role.query.filter_by(name='test').all())
			self.assertNotIn(self.get_admin_group(), user.groups)
		result = self.app.test_cli_runner().invoke(args=['user', 'update', 'testuser', '--clear-roles', '--add-role', 'admin'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			user = User.query.filter_by(loginname='testuser').first()
			self.assertEqual(user.roles, Role.query.filter_by(name='admin').all())
			self.assertIn(self.get_admin_group(), user.groups)

	def test_delete(self):
		with self.app.test_request_context():
			self.assertIsNotNone(User.query.filter_by(loginname='testuser').first())
		result = self.app.test_cli_runner().invoke(args=['user', 'delete', 'testuser'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			self.assertIsNone(User.query.filter_by(loginname='testuser').first())
		result = self.app.test_cli_runner().invoke(args=['user', 'delete', 'doesnotexist'])
		self.assertEqual(result.exit_code, 1)

class TestGroupCLI(UffdTestCase):
	def setUp(self):
		super().setUp()
		self.client.__exit__(None, None, None)

	def test_list(self):
		result = self.app.test_cli_runner().invoke(args=['group', 'list'])
		self.assertEqual(result.exit_code, 0)

	def test_show(self):
		result = self.app.test_cli_runner().invoke(args=['group', 'show', 'users'])
		self.assertEqual(result.exit_code, 0)
		result = self.app.test_cli_runner().invoke(args=['group', 'show', 'doesnotexist'])
		self.assertEqual(result.exit_code, 1)

	def test_create(self):
		result = self.app.test_cli_runner().invoke(args=['group', 'create', 'users']) # Duplicate name
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['group', 'create', 'new group'])
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['group', 'create', 'newgroup', '--description', 'A new group'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			group = Group.query.filter_by(name='newgroup').first()
			self.assertIsNotNone(group)
			self.assertEqual(group.description, 'A new group')

	def test_update(self):
		result = self.app.test_cli_runner().invoke(args=['group', 'update', 'doesnotexist', '--description', 'foo'])
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['group', 'update', 'users', '--description', 'New description'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			group = Group.query.filter_by(name='users').first()
			self.assertEqual(group.description, 'New description')

	def test_update_without_description(self):
		result = self.app.test_cli_runner().invoke(args=['group', 'update', 'users']) # Should not change anything
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			group = Group.query.filter_by(name='users').first()
			self.assertEqual(group.description, 'Base group for all users')

	def test_delete(self):
		with self.app.test_request_context():
			self.assertIsNotNone(Group.query.filter_by(name='users').first())
		result = self.app.test_cli_runner().invoke(args=['group', 'delete', 'users'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			self.assertIsNone(Group.query.filter_by(name='users').first())
		result = self.app.test_cli_runner().invoke(args=['group', 'delete', 'doesnotexist'])
		self.assertEqual(result.exit_code, 1)

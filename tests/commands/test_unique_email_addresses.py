from uffd.database import db
from uffd.models import User, UserEmail, FeatureFlag

from tests.utils import UffdTestCase

class TestUniqueEmailAddressCommands(UffdTestCase):
	def setUp(self):
		super().setUp()
		self.client.__exit__(None, None, None)

	def test_enable(self):
		result = self.app.test_cli_runner().invoke(args=['unique-email-addresses', 'enable'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			self.assertTrue(FeatureFlag.unique_email_addresses)

	def test_enable_already_enabled(self):
		with self.app.test_request_context():
			FeatureFlag.unique_email_addresses.enable()
			db.session.commit()
		result = self.app.test_cli_runner().invoke(args=['unique-email-addresses', 'enable'])
		self.assertEqual(result.exit_code, 1)

	def test_enable_user_conflict(self):
		with self.app.test_request_context():
			db.session.add(UserEmail(user=self.get_user(), address='foo@example.com'))
			db.session.add(UserEmail(user=self.get_user(), address='FOO@example.com'))
			db.session.commit()
		result = self.app.test_cli_runner().invoke(args=['unique-email-addresses', 'enable'])
		self.assertEqual(result.exit_code, 1)

	def test_enable_global_conflict(self):
		with self.app.test_request_context():
			db.session.add(UserEmail(user=self.get_user(), address='foo@example.com', verified=True))
			db.session.add(UserEmail(user=self.get_admin(), address='FOO@example.com', verified=True))
			db.session.commit()
		result = self.app.test_cli_runner().invoke(args=['unique-email-addresses', 'enable'])
		self.assertEqual(result.exit_code, 1)

	def test_disable(self):
		with self.app.test_request_context():
			FeatureFlag.unique_email_addresses.enable()
			db.session.commit()
		result = self.app.test_cli_runner().invoke(args=['unique-email-addresses', 'disable'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			self.assertFalse(FeatureFlag.unique_email_addresses)

	def test_disable_already_enabled(self):
		result = self.app.test_cli_runner().invoke(args=['unique-email-addresses', 'disable'])
		self.assertEqual(result.exit_code, 1)

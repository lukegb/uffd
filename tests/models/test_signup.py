import datetime

from uffd.database import db
from uffd.models import Signup, User, FeatureFlag

from tests.utils import UffdTestCase, db_flush

def refetch_signup(signup):
	db.session.add(signup)
	db.session.commit()
	id = signup.id
	db.session.expunge(signup)
	return Signup.query.get(id)

# We assume in all tests that Signup.validate and Signup.password.verify do
# not alter any state

class TestSignupModel(UffdTestCase):
	def assert_validate_valid(self, signup):
		valid, msg = signup.validate()
		self.assertTrue(valid)
		self.assertIsInstance(msg, str)

	def assert_validate_invalid(self, signup):
		valid, msg = signup.validate()
		self.assertFalse(valid)
		self.assertIsInstance(msg, str)
		self.assertNotEqual(msg, '')

	def assert_finish_success(self, signup, password):
		self.assertIsNone(signup.user)
		user, msg = signup.finish(password)
		db.session.commit()
		self.assertIsNotNone(user)
		self.assertIsInstance(msg, str)
		self.assertIsNotNone(signup.user)

	def assert_finish_failure(self, signup, password):
		prev_id = signup.user_id
		user, msg = signup.finish(password)
		self.assertIsNone(user)
		self.assertIsInstance(msg, str)
		self.assertNotEqual(msg, '')
		self.assertEqual(signup.user_id, prev_id)

	def test_password(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='new@example.com')
		self.assertFalse(signup.password.verify('notsecret'))
		self.assertFalse(signup.password.verify(''))
		self.assertFalse(signup.password.verify('wrongpassword'))
		self.assertTrue(signup.set_password('notsecret'))
		self.assertTrue(signup.password.verify('notsecret'))
		self.assertFalse(signup.password.verify('wrongpassword'))

	def test_expired(self):
		# TODO: Find a better way to test this!
		signup = Signup(loginname='newuser', displayname='New User', mail='new@example.com', password='notsecret')
		self.assertFalse(signup.expired)
		signup.created = created=datetime.datetime.utcnow() - datetime.timedelta(hours=49)
		self.assertTrue(signup.expired)

	def test_completed(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='new@example.com', password='notsecret')
		self.assertFalse(signup.completed)
		signup.finish('notsecret')
		db.session.commit()
		self.assertTrue(signup.completed)
		signup = refetch_signup(signup)
		self.assertTrue(signup.completed)

	def test_validate(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='new@example.com', password='notsecret')
		self.assert_validate_valid(signup)
		self.assert_validate_valid(refetch_signup(signup))

	def test_validate_completed(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='new@example.com', password='notsecret')
		self.assert_finish_success(signup, 'notsecret')
		self.assert_validate_invalid(signup)
		self.assert_validate_invalid(refetch_signup(signup))

	def test_validate_expired(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='new@example.com',
		                password='notsecret', created=datetime.datetime.utcnow()-datetime.timedelta(hours=49))
		self.assert_validate_invalid(signup)
		self.assert_validate_invalid(refetch_signup(signup))

	def test_validate_loginname(self):
		signup = Signup(loginname='', displayname='New User', mail='new@example.com', password='notsecret')
		self.assert_validate_invalid(signup)
		self.assert_validate_invalid(refetch_signup(signup))

	def test_validate_displayname(self):
		signup = Signup(loginname='newuser', displayname='', mail='new@example.com', password='notsecret')
		self.assert_validate_invalid(signup)
		self.assert_validate_invalid(refetch_signup(signup))

	def test_validate_mail(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='', password='notsecret')
		self.assert_validate_invalid(signup)
		self.assert_validate_invalid(refetch_signup(signup))

	def test_validate_password(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='new@example.com')
		self.assertFalse(signup.set_password(''))
		self.assert_validate_invalid(signup)
		self.assert_validate_invalid(refetch_signup(signup))

	def test_validate_exists(self):
		signup = Signup(loginname='testuser', displayname='New User', mail='new@example.com', password='notsecret')
		self.assert_validate_invalid(signup)
		self.assert_validate_invalid(refetch_signup(signup))

	def test_finish(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='new@example.com', password='notsecret')
		self.assert_finish_success(signup, 'notsecret')
		user = User.query.filter_by(loginname='newuser').one_or_none()
		self.assertEqual(user.loginname, 'newuser')
		self.assertEqual(user.displayname, 'New User')
		self.assertEqual(user.primary_email.address, 'new@example.com')

	def test_finish_completed(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='new@example.com', password='notsecret')
		self.assert_finish_success(signup, 'notsecret')
		self.assert_finish_failure(refetch_signup(signup), 'notsecret')

	def test_finish_expired(self):
		# TODO: Find a better way to test this!
		signup = Signup(loginname='newuser', displayname='New User', mail='new@example.com',
		                password='notsecret', created=datetime.datetime.utcnow()-datetime.timedelta(hours=49))
		self.assert_finish_failure(signup, 'notsecret')
		self.assert_finish_failure(refetch_signup(signup), 'notsecret')

	def test_finish_wrongpassword(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='new@example.com')
		self.assert_finish_failure(signup, '')
		self.assert_finish_failure(signup, 'wrongpassword')
		signup = refetch_signup(signup)
		self.assert_finish_failure(signup, '')
		self.assert_finish_failure(signup, 'wrongpassword')
		signup = Signup(loginname='newuser', displayname='New User', mail='new@example.com', password='notsecret')
		self.assert_finish_failure(signup, 'wrongpassword')
		self.assert_finish_failure(refetch_signup(signup), 'wrongpassword')

	def test_finish_duplicate(self):
		signup = Signup(loginname='testuser', displayname='New User', mail='new@example.com', password='notsecret')
		self.assert_finish_failure(signup, 'notsecret')
		self.assert_finish_failure(refetch_signup(signup), 'notsecret')

	def test_finish_duplicate_email_strict_uniqueness(self):
		FeatureFlag.unique_email_addresses.enable()
		db.session.commit()
		signup = Signup(loginname='newuser', displayname='New User', mail='test@example.com', password='notsecret')
		self.assert_finish_failure(signup, 'notsecret')

	def test_duplicate(self):
		signup = Signup(loginname='newuser', displayname='New User', mail='test1@example.com', password='notsecret')
		self.assert_validate_valid(signup)
		db.session.add(signup)
		db.session.commit()
		signup1_id = signup.id
		signup = Signup(loginname='newuser', displayname='New User', mail='test2@example.com', password='notsecret')
		self.assert_validate_valid(signup)
		db.session.add(signup)
		db.session.commit()
		signup2_id = signup.id
		db_flush()
		signup = Signup.query.get(signup2_id)
		self.assert_finish_success(signup, 'notsecret')
		db.session.commit()
		db_flush()
		signup = Signup.query.get(signup1_id)
		self.assert_finish_failure(signup, 'notsecret')
		user = User.query.filter_by(loginname='newuser').one_or_none()
		self.assertEqual(user.primary_email.address, 'test2@example.com')

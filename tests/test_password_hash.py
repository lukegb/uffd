import unittest

from uffd.password_hash import *

class TestPasswordHashRegistry(unittest.TestCase):
	def test(self):
		registry = PasswordHashRegistry()

		@registry.register
		class TestPasswordHash:
			METHOD_NAME = 'test'
			def __init__(self, value, **kwargs):
				self.value = value
				self.kwargs = kwargs

		@registry.register
		class Test2PasswordHash:
			METHOD_NAME = 'test2'

		result = registry.parse('{test}data', key='value')
		self.assertIsInstance(result, TestPasswordHash)
		self.assertEqual(result.value, '{test}data')
		self.assertEqual(result.kwargs, {'key': 'value'})
		with self.assertRaises(ValueError):
			registry.parse('{invalid}data')
		with self.assertRaises(ValueError):
			registry.parse('invalid')
		with self.assertRaises(ValueError):
			registry.parse('{invalid')

class TestPasswordHash(unittest.TestCase):
	def setUp(self):
		class TestPasswordHash(PasswordHash):
			@classmethod
			def from_password(cls, password):
				cls(build_value(cls.METHOD_NAME, password))

			def verify(self, password):
				return self.data == password

		class TestPasswordHash1(TestPasswordHash):
			METHOD_NAME = 'test1'

		class TestPasswordHash2(TestPasswordHash):
			METHOD_NAME = 'test2'

		self.TestPasswordHash1 = TestPasswordHash1
		self.TestPasswordHash2 = TestPasswordHash2

	def test(self):
		obj = self.TestPasswordHash1('{test1}data')
		self.assertEqual(obj.value, '{test1}data')
		self.assertEqual(obj.data, 'data')
		self.assertIs(obj.target_cls, self.TestPasswordHash1)
		self.assertFalse(obj.needs_rehash)

	def test_invalid(self):
		with self.assertRaises(ValueError):
			self.TestPasswordHash1('invalid')
		with self.assertRaises(ValueError):
			self.TestPasswordHash1('{invalid}data')
		with self.assertRaises(ValueError):
			self.TestPasswordHash1('{test2}data')

	def test_target_cls(self):
		obj = self.TestPasswordHash1('{test1}data', target_cls=self.TestPasswordHash1)
		self.assertEqual(obj.value, '{test1}data')
		self.assertEqual(obj.data, 'data')
		self.assertIs(obj.target_cls, self.TestPasswordHash1)
		self.assertFalse(obj.needs_rehash)
		obj = self.TestPasswordHash1('{test1}data', target_cls=self.TestPasswordHash2)
		self.assertEqual(obj.value, '{test1}data')
		self.assertEqual(obj.data, 'data')
		self.assertIs(obj.target_cls, self.TestPasswordHash2)
		self.assertTrue(obj.needs_rehash)
		obj = self.TestPasswordHash1('{test1}data', target_cls=PasswordHash)
		self.assertEqual(obj.value, '{test1}data')
		self.assertEqual(obj.data, 'data')
		self.assertIs(obj.target_cls, PasswordHash)
		self.assertFalse(obj.needs_rehash)

class TestPlaintextPasswordHash(unittest.TestCase):
	def test_verify(self):
		obj = PlaintextPasswordHash('{plain}password')
		self.assertTrue(obj.verify('password'))
		self.assertFalse(obj.verify('notpassword'))

	def test_from_password(self):
		obj = PlaintextPasswordHash.from_password('password')
		self.assertEqual(obj.value, '{plain}password')
		self.assertTrue(obj.verify('password'))
		self.assertFalse(obj.verify('notpassword'))

class TestHashlibPasswordHash(unittest.TestCase):
	def test_verify(self):
		obj = SHA512PasswordHash('{sha512}sQnzu7wkTrgkQZF+0G1hi5AI3Qmzvv0bXgc5THBqi7mAsdd4Xll27ASbRt9fEyavWi6m0QP9B8lThf+rDKy8hg==')
		self.assertTrue(obj.verify('password'))
		self.assertFalse(obj.verify('notpassword'))

	def test_from_password(self):
		obj = SHA512PasswordHash.from_password('password')
		self.assertIsNotNone(obj.value)
		self.assertTrue(obj.value.startswith('{sha512}'))
		self.assertTrue(obj.verify('password'))
		self.assertFalse(obj.verify('notpassword'))

class TestSaltedHashlibPasswordHash(unittest.TestCase):
	def test_verify(self):
		obj = SaltedSHA512PasswordHash('{ssha512}dOeDLmVpHJThhHeag10Hm2g4T7s3SBE6rGHcXUolXJHVufY4qT782rwZ/0XE6cuLcBZ0KpnwmUzRpAEtZBdv+JYEEtZQs/uC')
		self.assertTrue(obj.verify('password'))
		self.assertFalse(obj.verify('notpassword'))

	def test_from_password(self):
		obj = SaltedSHA512PasswordHash.from_password('password')
		self.assertIsNotNone(obj.value)
		self.assertTrue(obj.value.startswith('{ssha512}'))
		self.assertTrue(obj.verify('password'))
		self.assertFalse(obj.verify('notpassword'))

class TestCryptPasswordHash(unittest.TestCase):
	def test_verify(self):
		obj = CryptPasswordHash('{crypt}$5$UbTTMBH9NRurlQcX$bUiUTyedvmArlVt.62ZLRV80e2v3DjcBp/tSDkP2imD')
		self.assertTrue(obj.verify('password'))
		self.assertFalse(obj.verify('notpassword'))

	def test_from_password(self):
		obj = CryptPasswordHash.from_password('password')
		self.assertIsNotNone(obj.value)
		self.assertTrue(obj.value.startswith('{crypt}'))
		self.assertTrue(obj.verify('password'))
		self.assertFalse(obj.verify('notpassword'))

class TestArgon2PasswordHash(unittest.TestCase):
	def test_verify(self):
		obj = Argon2PasswordHash('{argon2}$argon2id$v=19$m=102400,t=2,p=8$Jc8LpCgPLjwlN/7efHLvwQ$ZqSg3CFb2/hBb3X8hOq4aw')
		self.assertTrue(obj.verify('password'))
		self.assertFalse(obj.verify('notpassword'))
		obj = Argon2PasswordHash('{argon2}$invalid$')
		self.assertFalse(obj.verify('password'))

	def test_from_password(self):
		obj = Argon2PasswordHash.from_password('password')
		self.assertIsNotNone(obj.value)
		self.assertTrue(obj.value.startswith('{argon2}'))
		self.assertTrue(obj.verify('password'))
		self.assertFalse(obj.verify('notpassword'))

	def test_needs_rehash(self):
		obj = Argon2PasswordHash('{argon2}$argon2id$v=19$m=102400,t=2,p=8$Jc8LpCgPLjwlN/7efHLvwQ$ZqSg3CFb2/hBb3X8hOq4aw')
		self.assertFalse(obj.needs_rehash)
		obj = Argon2PasswordHash('{argon2}$argon2id$v=19$m=102400,t=2,p=8$Jc8LpCgPLjwlN/7efHLvwQ$ZqSg3CFb2/hBb3X8hOq4aw', target_cls=PlaintextPasswordHash)
		self.assertTrue(obj.needs_rehash)
		obj = Argon2PasswordHash('{argon2}$argon2d$v=19$m=102400,t=2,p=8$kshPgLU1+h72l/Z8QWh8Ig$tYerKCe/5I2BCPKu8hCl2w')
		self.assertTrue(obj.needs_rehash)
		obj = Argon2PasswordHash('{argon2}$argon2id$v=19$m=102400,t=1,p=8$aa6i4vg/szKX5xHVGFaAeQ$v6j0ltuVqQaZlmuepaVJ1A')
		self.assertTrue(obj.needs_rehash)

class TestInvalidPasswordHash(unittest.TestCase):
	def test(self):
		obj = InvalidPasswordHash('test')
		self.assertEqual(obj.value, 'test')
		self.assertFalse(obj.verify('test'))
		self.assertTrue(obj.needs_rehash)
		self.assertFalse(obj)
		obj = InvalidPasswordHash(None)
		self.assertIsNone(obj.value)
		self.assertFalse(obj.verify('test'))
		self.assertTrue(obj.needs_rehash)
		self.assertFalse(obj)

class TestPasswordWrapper(unittest.TestCase):
	def setUp(self):
		class Test:
			password_hash = None
			password = PasswordHashAttribute('password_hash', PlaintextPasswordHash)

		self.test = Test()

	def test_get_none(self):
		self.test.password_hash = None
		obj = self.test.password
		self.assertIsInstance(obj, InvalidPasswordHash)
		self.assertEqual(obj.value, None)
		self.assertTrue(obj.needs_rehash)

	def test_get_valid(self):
		self.test.password_hash = '{plain}password'
		obj = self.test.password
		self.assertIsInstance(obj, PlaintextPasswordHash)
		self.assertEqual(obj.value, '{plain}password')
		self.assertFalse(obj.needs_rehash)

	def test_get_needs_rehash(self):
		self.test.password_hash = '{ssha512}dOeDLmVpHJThhHeag10Hm2g4T7s3SBE6rGHcXUolXJHVufY4qT782rwZ/0XE6cuLcBZ0KpnwmUzRpAEtZBdv+JYEEtZQs/uC'
		obj = self.test.password
		self.assertIsInstance(obj, SaltedSHA512PasswordHash)
		self.assertEqual(obj.value, '{ssha512}dOeDLmVpHJThhHeag10Hm2g4T7s3SBE6rGHcXUolXJHVufY4qT782rwZ/0XE6cuLcBZ0KpnwmUzRpAEtZBdv+JYEEtZQs/uC')
		self.assertTrue(obj.needs_rehash)

	def test_set(self):
		self.test.password = 'password'
		self.assertEqual(self.test.password_hash, '{plain}password')

	def test_set_none(self):
		self.test.password = None
		self.assertIsNone(self.test.password_hash)

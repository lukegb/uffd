from uffd.remailer import remailer

from utils import UffdTestCase

USER_ID = 1234
SERVICE1_ID = 4223
SERVICE2_ID = 3242

class TestRemailer(UffdTestCase):
	def test_is_remailer_domain(self):
		self.app.config['REMAILER_DOMAIN'] = 'remailer.example.com'
		self.assertTrue(remailer.is_remailer_domain('remailer.example.com'))
		self.assertTrue(remailer.is_remailer_domain('REMAILER.EXAMPLE.COM'))
		self.assertTrue(remailer.is_remailer_domain(' remailer.example.com '))
		self.assertFalse(remailer.is_remailer_domain('other.remailer.example.com'))
		self.assertFalse(remailer.is_remailer_domain('example.com'))
		self.app.config['REMAILER_OLD_DOMAINS'] = [' OTHER.remailer.example.com ']
		self.assertTrue(remailer.is_remailer_domain(' OTHER.remailer.example.com '))
		self.assertTrue(remailer.is_remailer_domain('remailer.example.com'))
		self.assertTrue(remailer.is_remailer_domain('other.remailer.example.com'))
		self.assertFalse(remailer.is_remailer_domain('example.com'))

	def test_build_address(self):
		self.app.config['REMAILER_DOMAIN'] = 'remailer.example.com'
		self.assertTrue(remailer.build_address(SERVICE1_ID, USER_ID).endswith('@remailer.example.com'))
		self.assertTrue(remailer.build_address(SERVICE2_ID, USER_ID).endswith('@remailer.example.com'))
		self.assertLessEqual(len(remailer.build_local_part(SERVICE1_ID, USER_ID)), 64)
		self.assertLessEqual(len(remailer.build_address(SERVICE1_ID, USER_ID)), 256)
		self.assertEqual(remailer.build_address(SERVICE1_ID, USER_ID), remailer.build_address(SERVICE1_ID, USER_ID))
		self.assertNotEqual(remailer.build_address(SERVICE1_ID, USER_ID), remailer.build_address(SERVICE2_ID, USER_ID))
		addr = remailer.build_address(SERVICE1_ID, USER_ID)
		self.app.config['REMAILER_OLD_DOMAINS'] = ['old.remailer.example.com']
		self.assertEqual(remailer.build_address(SERVICE1_ID, USER_ID), addr)
		self.assertTrue(remailer.build_address(SERVICE1_ID, USER_ID).endswith('@remailer.example.com'))
		self.app.config['REMAILER_SECRET_KEY'] = self.app.config['SECRET_KEY']
		self.assertEqual(remailer.build_address(SERVICE1_ID, USER_ID), addr)
		self.app.config['REMAILER_SECRET_KEY'] = 'REMAILER-DEBUGKEY'
		self.assertNotEqual(remailer.build_address(SERVICE1_ID, USER_ID), addr)

	def test_parse_address(self):
		self.app.config['REMAILER_DOMAIN'] = 'remailer.example.com'
		addr = remailer.build_address(SERVICE2_ID, USER_ID)
		# REMAILER_DOMAIN behaviour
		self.app.config['REMAILER_DOMAIN'] = None
		self.assertIsNone(remailer.parse_address(addr))
		self.assertIsNone(remailer.parse_address('foo@example.com'))
		self.app.config['REMAILER_DOMAIN'] = 'remailer.example.com'
		self.assertEqual(remailer.parse_address(addr), (SERVICE2_ID, USER_ID))
		self.assertIsNone(remailer.parse_address('foo@example.com'))
		self.assertIsNone(remailer.parse_address('foo@remailer.example.com'))
		self.assertIsNone(remailer.parse_address('v1-foo@remailer.example.com'))
		self.app.config['REMAILER_DOMAIN'] = 'new-remailer.example.com'
		self.assertIsNone(remailer.parse_address(addr))
		self.app.config['REMAILER_OLD_DOMAINS'] = ['remailer.example.com']
		self.assertEqual(remailer.parse_address(addr), (SERVICE2_ID, USER_ID))
		# REMAILER_SECRET_KEY behaviour
		self.app.config['REMAILER_DOMAIN'] = 'remailer.example.com'
		self.app.config['REMAILER_OLD_DOMAINS'] = []
		self.assertEqual(remailer.parse_address(addr), (SERVICE2_ID, USER_ID))
		self.app.config['REMAILER_SECRET_KEY'] = self.app.config['SECRET_KEY']
		self.assertEqual(remailer.parse_address(addr), (SERVICE2_ID, USER_ID))
		self.app.config['REMAILER_SECRET_KEY'] = 'REMAILER-DEBUGKEY'
		self.assertIsNone(remailer.parse_address(addr))

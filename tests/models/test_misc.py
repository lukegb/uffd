from sqlalchemy.exc import IntegrityError

from uffd.database import db
from uffd.models import FeatureFlag
from uffd.models.misc import feature_flag_table

from tests.utils import UffdTestCase

class TestFeatureFlagModel(UffdTestCase):
	def test_disabled(self):
		flag = FeatureFlag('foo')
		self.assertFalse(flag)
		self.assertFalse(db.session.execute(db.select([flag.expr])).scalar())

	def test_enabled(self):
		db.session.execute(db.insert(feature_flag_table).values(name='foo'))
		flag = FeatureFlag('foo')
		self.assertTrue(flag)
		self.assertTrue(db.session.execute(db.select([flag.expr])).scalar())

	def test_toggle(self):
		flag = FeatureFlag('foo')
		hooks_called = []

		@flag.enable_hook
		def enable_hook1():
			hooks_called.append('enable1')

		@flag.enable_hook
		def enable_hook2():
			hooks_called.append('enable2')

		@flag.disable_hook
		def disable_hook1():
			hooks_called.append('disable1')

		@flag.disable_hook
		def disable_hook2():
			hooks_called.append('disable2')

		hooks_called.clear()
		flag.enable()
		self.assertTrue(flag)
		self.assertEqual(hooks_called, ['enable1', 'enable2'])
		hooks_called.clear()
		flag.disable()
		self.assertFalse(flag)
		self.assertEqual(hooks_called, ['disable1', 'disable2'])
		flag.disable() # does nothing
		self.assertFalse(flag)
		flag.enable()
		self.assertTrue(flag)
		with self.assertRaises(IntegrityError):
			flag.enable()
		self.assertTrue(flag)

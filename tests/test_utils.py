from uffd.utils import nopad_b32decode, nopad_b32encode, nopad_urlsafe_b64decode, nopad_urlsafe_b64encode

from tests.utils import UffdTestCase

class TestUtils(UffdTestCase):
	def test_nopad_b32(self):
		for n in range(0, 32):
			self.assertEqual(b'X'*n, nopad_b32decode(nopad_b32encode(b'X'*n)))

	def test_nopad_b64(self):
		for n in range(0, 32):
			self.assertEqual(b'X'*n, nopad_urlsafe_b64decode(nopad_urlsafe_b64encode(b'X'*n)))

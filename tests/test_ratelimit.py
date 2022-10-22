from uffd.models.ratelimit import get_addrkey, format_delay, Ratelimit

from tests.utils import UffdTestCase

class TestRatelimit(UffdTestCase):
	def test_limiting(self):
		cases = [
			(1*60, 3),
			(1*60*60, 3),
			(1*60*60, 25),
		]
		for index, case in enumerate(cases):
			interval, limit = case
			key = str(index)
			ratelimit = Ratelimit('test', interval, limit)
			for i in range(limit):
				ratelimit.log(key)
			self.assertLessEqual(ratelimit.get_delay(key), interval)
			ratelimit.log(key)
			self.assertGreater(ratelimit.get_delay(key), interval)

	def test_addrkey(self):
		self.assertEqual(get_addrkey('192.168.0.1'), get_addrkey('192.168.0.99'))
		self.assertNotEqual(get_addrkey('192.168.0.1'), get_addrkey('192.168.1.1'))
		self.assertEqual(get_addrkey('fdee:707a:f38a:c369::'), get_addrkey('fdee:707a:f38a:ffff::'))
		self.assertNotEqual(get_addrkey('fdee:707a:f38a:c369::'), get_addrkey('fdee:707a:f38b:c369::'))
		cases = [
			'',
			'192.168.0.',
			':',
			'::',
			'192.168.0.1/24',
			'192.168.0.1/24',
			'host.example.com',
		]
		for case in cases:
			self.assertIsInstance(get_addrkey(case), str)

	def test_format_delay(self):
		self.assertIsInstance(format_delay(0), str)
		self.assertIsInstance(format_delay(1), str)
		self.assertIsInstance(format_delay(30), str)
		self.assertIsInstance(format_delay(60), str)
		self.assertIsInstance(format_delay(120), str)
		self.assertIsInstance(format_delay(3600), str)
		self.assertIsInstance(format_delay(4000), str)

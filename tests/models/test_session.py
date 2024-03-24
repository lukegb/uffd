import unittest
import datetime

from uffd.database import db
from uffd.models.session import Session, USER_AGENT_PARSER_SUPPORTED

from tests.utils import UffdTestCase

class TestSession(UffdTestCase):
	def test_expire(self):
		self.app.config['SESSION_LIFETIME_SECONDS'] = 100
		self.app.config['PERMANENT_SESSION_LIFETIME'] = 10
		user = self.get_user()
		def make_session(created_age, last_used_age):
			return Session(
				user=user,
				created=datetime.datetime.utcnow() - datetime.timedelta(seconds=created_age),
				last_used=datetime.datetime.utcnow() - datetime.timedelta(seconds=last_used_age),
			)
		session1 = Session(user=user)
		self.assertFalse(session1.expired)
		session2 = make_session(0, 0)
		self.assertFalse(session2.expired)
		session3 = make_session(50, 5)
		self.assertFalse(session3.expired)
		session4 = make_session(50, 15)
		self.assertTrue(session4.expired)
		session5 = make_session(105, 5)
		self.assertTrue(session5.expired)
		session6 = make_session(105, 15)
		self.assertTrue(session6.expired)
		db.session.add_all([session1, session2, session3, session4, session5, session6])
		db.session.commit()
		self.assertEqual(set(Session.query.filter_by(expired=False).all()), {session1, session2, session3})
		self.assertEqual(set(Session.query.filter_by(expired=True).all()), {session4, session5, session6})

	def test_useragent_ua_parser(self):
		if not USER_AGENT_PARSER_SUPPORTED:
			self.skipTest('ua_parser not available')
		session = Session(user_agent='Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0')
		self.assertEqual(session.user_agent_browser, 'Firefox')
		self.assertEqual(session.user_agent_platform, 'Windows')

	def test_useragent_no_ua_parser(self):
		session = Session(user_agent='Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0')
		session.DISABLE_USER_AGENT_PARSER = True
		self.assertEqual(session.user_agent_browser, 'Firefox')
		self.assertEqual(session.user_agent_platform, 'Windows')

import datetime
import time

from flask import url_for, session

# These imports are required, because otherwise we get circular imports?!
from uffd import ldap, user

from uffd.ldap import get_conn
from uffd.mail.models import Mail
from uffd import create_app, db

from utils import dump, UffdTestCase

def get_mail():
	return Mail.from_ldap_dn('uid=test,ou=postfix,dc=example,dc=com')

class TestMailViews(UffdTestCase):
	def setUp(self):
		super().setUp()
		self.client.post(path=url_for('session.login'),
			data={'loginname': 'testadmin', 'password': 'adminpassword'}, follow_redirects=True)

	def test_index(self):
		r = self.client.get(path=url_for('mail.index'), follow_redirects=True)
		dump('mail_index', r)
		self.assertEqual(r.status_code, 200)

	def test_index_empty(self):
		conn = get_conn()
		conn.delete(get_mail().dn)
		self.assertIsNone(get_mail())
		r = self.client.get(path=url_for('mail.index'), follow_redirects=True)
		dump('mail_index_empty', r)
		self.assertEqual(r.status_code, 200)

	def test_show(self):
		r = self.client.get(path=url_for('mail.show', uid=get_mail().uid), follow_redirects=True)
		dump('mail_show', r)
		self.assertEqual(r.status_code, 200)

	def test_new(self):
		r = self.client.get(path=url_for('mail.show'), follow_redirects=True)
		dump('mail_new', r)
		self.assertEqual(r.status_code, 200)

	def test_update(self):
		m = get_mail()
		self.assertIsNotNone(m)
		self.assertEqual(m.uid, 'test')
		self.assertEqual(sorted(m.receivers), ['test1@example.com', 'test2@example.com'])
		self.assertEqual(sorted(m.destinations), ['testuser@mail.example.com'])
		r = self.client.post(path=url_for('mail.update', uid=m.uid),
			data={'mail-uid': 'test1', 'mail-receivers': 'foo@bar.com\ntest@bar.com',
			'mail-destinations': 'testuser@mail.example.com\ntestadmin@mail.example.com'}, follow_redirects=True)
		dump('mail_update', r)
		self.assertEqual(r.status_code, 200)
		m = get_mail()
		self.assertIsNotNone(m)
		self.assertEqual(m.uid, 'test')
		self.assertEqual(sorted(m.receivers), ['foo@bar.com', 'test@bar.com'])
		self.assertEqual(sorted(m.destinations), ['testadmin@mail.example.com', 'testuser@mail.example.com'])

	def test_create(self):
		r = self.client.post(path=url_for('mail.update'),
			data={'mail-uid': 'test1', 'mail-receivers': 'foo@bar.com\ntest@bar.com',
			'mail-destinations': 'testuser@mail.example.com\ntestadmin@mail.example.com'}, follow_redirects=True)
		dump('mail_create', r)
		self.assertEqual(r.status_code, 200)
		m = Mail.from_ldap_dn('uid=test1,ou=postfix,dc=example,dc=com')
		self.assertEqual(m.uid, 'test1')
		self.assertEqual(sorted(m.receivers), ['foo@bar.com', 'test@bar.com'])
		self.assertEqual(sorted(m.destinations), ['testadmin@mail.example.com', 'testuser@mail.example.com'])

	def test_create_error(self):
		r = self.client.post(path=url_for('mail.update'),
			data={'mail-uid': 'test', 'mail-receivers': 'foo@bar.com\ntest@bar.com',
			'mail-destinations': 'testuser@mail.example.com\ntestadmin@mail.example.com'}, follow_redirects=True)
		dump('mail_create_error', r)
		self.assertEqual(r.status_code, 200)
		m = get_mail()
		self.assertIsNotNone(m)
		self.assertEqual(m.uid, 'test')
		self.assertEqual(sorted(m.receivers), ['test1@example.com', 'test2@example.com'])
		self.assertEqual(sorted(m.destinations), ['testuser@mail.example.com'])

	def test_delete(self):
		self.assertIsNotNone(get_mail())
		r = self.client.get(path=url_for('mail.delete', uid=get_mail().uid), follow_redirects=True)
		dump('mail_delete', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(get_mail())

class TestMailViewsOL(TestMailViews):
	use_openldap = True

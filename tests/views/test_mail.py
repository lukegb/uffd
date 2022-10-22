import unittest

from flask import url_for

from uffd.database import db
from uffd.models import Mail

from tests.utils import dump, UffdTestCase

class TestMailViews(UffdTestCase):
	def setUp(self):
		super().setUp()
		self.login_as('admin')

	def test_index(self):
		r = self.client.get(path=url_for('mail.index'), follow_redirects=True)
		dump('mail_index', r)
		self.assertEqual(r.status_code, 200)

	def test_index_empty(self):
		db.session.delete(self.get_mail())
		db.session.commit()
		self.assertIsNone(self.get_mail())
		r = self.client.get(path=url_for('mail.index'), follow_redirects=True)
		dump('mail_index_empty', r)
		self.assertEqual(r.status_code, 200)

	def test_show(self):
		r = self.client.get(path=url_for('mail.show', mai_id=self.get_mail().id), follow_redirects=True)
		dump('mail_show', r)
		self.assertEqual(r.status_code, 200)

	def test_new(self):
		r = self.client.get(path=url_for('mail.show'), follow_redirects=True)
		dump('mail_new', r)
		self.assertEqual(r.status_code, 200)

	def test_update(self):
		m = self.get_mail()
		self.assertIsNotNone(m)
		self.assertEqual(m.uid, 'test')
		self.assertEqual(sorted(m.receivers), ['test1@example.com', 'test2@example.com'])
		self.assertEqual(sorted(m.destinations), ['testuser@mail.example.com'])
		r = self.client.post(path=url_for('mail.update', mail_id=m.id),
			data={'mail-uid': 'test1', 'mail-receivers': 'foo@bar.com\ntest@bar.com',
			'mail-destinations': 'testuser@mail.example.com\ntestadmin@mail.example.com'}, follow_redirects=True)
		dump('mail_update', r)
		self.assertEqual(r.status_code, 200)
		m = self.get_mail()
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
		m = Mail.query.filter_by(uid='test1').one()
		self.assertEqual(m.uid, 'test1')
		self.assertEqual(sorted(m.receivers), ['foo@bar.com', 'test@bar.com'])
		self.assertEqual(sorted(m.destinations), ['testadmin@mail.example.com', 'testuser@mail.example.com'])

	@unittest.skip('We do not catch DB errors at the moment!') # TODO
	def test_create_error(self):
		r = self.client.post(path=url_for('mail.update'),
			data={'mail-uid': 'test', 'mail-receivers': 'foo@bar.com\ntest@bar.com',
			'mail-destinations': 'testuser@mail.example.com\ntestadmin@mail.example.com'}, follow_redirects=True)
		dump('mail_create_error', r)
		self.assertEqual(r.status_code, 200)
		m = self.get_mail()
		self.assertIsNotNone(m)
		self.assertEqual(m.uid, 'test')
		self.assertEqual(sorted(m.receivers), ['test1@example.com', 'test2@example.com'])
		self.assertEqual(sorted(m.destinations), ['testuser@mail.example.com'])

	def test_delete(self):
		self.assertIsNotNone(self.get_mail())
		r = self.client.get(path=url_for('mail.delete', mail_id=self.get_mail().id), follow_redirects=True)
		dump('mail_delete', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(self.get_mail())

import datetime
import unittest

from flask import url_for

# These imports are required, because otherwise we get circular imports?!
from uffd import user

from utils import dump, UffdTestCase

class TestServices(UffdTestCase):
	def setUpApp(self):
		self.app.config['SERVICES'] = [
			{
				'title': 'Service Title',
				'subtitle': 'Service Subtitle',
				'description': 'Short description of the service as plain text',
				'url': 'https://example.com/',
				'logo_url': '/static/fairy-dust-color.png',
				'required_group': 'users',
				'permission_levels': [
					{'name': 'Moderator', 'required_group': 'moderators'},
					{'name': 'Admin', 'required_group': 'uffd_admin'},
				],
				'confidential': True,
				'groups': [
					{'name': 'Group "crew_crew"', 'required_group': 'users'},
					{'name': 'Group "crew_logistik"', 'required_group': 'uffd_admin'},
				],
				'infos': [
					{'title': 'Documentation', 'html': '<p>Some information about the service as html</p>', 'required_group': 'users'},
				],
				'links': [
					{'title': 'Link to an external site', 'url': '#', 'required_group': 'users'},
				],
			},
			{
				'title': 'Minimal Service Title',
			}
		]
		self.app.config['SERVICES_PUBLIC'] = True

	def test_overview(self):
		r = self.client.get(path=url_for('service.overview'))
		dump('service_overview_guest', r)
		self.assertEqual(r.status_code, 200)
		self.assertNotIn(b'https://example.com/', r.data)
		self.login_as('user')
		r = self.client.get(path=url_for('service.overview'))
		dump('service_overview_user', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn(b'https://example.com/', r.data)

	def test_overview_disabled(self):
		self.app.config['SERVICES'] = []
		# Should return login page
		r = self.client.get(path=url_for('service.overview'), follow_redirects=True)
		dump('service_overview_disabled_guest', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn(b'name="password"', r.data)
		self.login_as('user')
		# Should return access denied page
		r = self.client.get(path=url_for('service.overview'), follow_redirects=True)
		dump('service_overview_disabled_user', r)
		self.assertEqual(r.status_code, 403)
		self.login_as('admin')
		# Should return (empty) overview page
		r = self.client.get(path=url_for('service.overview'), follow_redirects=True)
		dump('service_overview_disabled_admin', r)
		self.assertEqual(r.status_code, 200)

	def test_overview_nonpublic(self):
		self.app.config['SERVICES_PUBLIC'] = False
		# Should return login page
		r = self.client.get(path=url_for('service.overview'), follow_redirects=True)
		dump('service_overview_nonpublic_guest', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn(b'name="password"', r.data)
		self.login_as('user')
		# Should return overview page
		r = self.client.get(path=url_for('service.overview'), follow_redirects=True)
		dump('service_overview_nonpublic_user', r)
		self.assertEqual(r.status_code, 200)
		self.login_as('admin')
		# Should return overview page
		r = self.client.get(path=url_for('service.overview'), follow_redirects=True)
		dump('service_overview_nonpublic_admin', r)
		self.assertEqual(r.status_code, 200)

	def test_overview_public(self):
		# Should return overview page
		r = self.client.get(path=url_for('service.overview'), follow_redirects=True)
		dump('service_overview_public_guest', r)
		self.assertEqual(r.status_code, 200)
		self.login_as('user')
		# Should return overview page
		r = self.client.get(path=url_for('service.overview'), follow_redirects=True)
		dump('service_overview_public_user', r)
		self.assertEqual(r.status_code, 200)
		self.login_as('admin')
		# Should return overview page
		r = self.client.get(path=url_for('service.overview'), follow_redirects=True)
		dump('service_overview_public_admin', r)
		self.assertEqual(r.status_code, 200)

import datetime
import unittest

from flask import url_for

# These imports are required, because otherwise we get circular imports?!
from uffd import ldap, user

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

	def test_index(self):
		r = self.client.get(path=url_for('services.index'))
		dump('services_index_public', r)
		self.assertEqual(r.status_code, 200)
		self.assertNotIn(b'https://example.com/', r.data)
		self.login_as('user')
		r = self.client.get(path=url_for('services.index'))
		dump('services_index', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn(b'https://example.com/', r.data)


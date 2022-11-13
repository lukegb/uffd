from flask import url_for

from uffd.database import db
from uffd.models import Service, ServiceUser, OAuth2Client, APIClient, RemailerMode
from tests.utils import dump, UffdTestCase

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

class TestServiceAdminViews(UffdTestCase):
	def setUpDB(self):
		db.session.add(Service(
			name='test1',
			oauth2_clients=[OAuth2Client(client_id='test1_oauth2_client1', client_secret='test'), OAuth2Client(client_id='test1_oauth2_client2', client_secret='test')],
			api_clients=[APIClient(auth_username='test1_api_client1', auth_password='test'), APIClient(auth_username='test1_api_client2', auth_password='test')],
		))
		db.session.add(Service(name='test2'))
		db.session.add(Service(name='test3'))
		db.session.commit()
		self.service_id = Service.query.filter_by(name='test1').one().id

	def test_index(self):
		self.login_as('admin')
		r = self.client.get(path=url_for('service.index'), follow_redirects=True)
		dump('service_index', r)
		self.assertEqual(r.status_code, 200)

	def test_show(self):
		self.login_as('admin')
		r = self.client.get(path=url_for('service.show', id=self.service_id), follow_redirects=True)
		dump('service_show', r)
		self.assertEqual(r.status_code, 200)

	def test_new(self):
		self.login_as('admin')
		r = self.client.get(path=url_for('service.show'), follow_redirects=True)
		dump('service_new', r)
		self.assertEqual(r.status_code, 200)

	def test_new_submit(self):
		self.login_as('admin')
		r = self.client.post(
			path=url_for('service.edit_submit'),
			follow_redirects=True,
			data={
				'name': 'new-service',
				'access-group': '',
				'remailer-mode': 'DISABLED',
				'remailer-overwrite-mode': 'ENABLED_V2',
				'remailer-overwrite-users': '',
			},
		)
		dump('service_new_submit', r)
		self.assertEqual(r.status_code, 200)
		service = Service.query.filter_by(name='new-service').one_or_none()
		self.assertIsNotNone(service)
		self.assertEqual(service.limit_access, True)
		self.assertEqual(service.access_group, None)
		self.assertEqual(service.remailer_mode, RemailerMode.DISABLED)
		self.assertEqual(service.enable_email_preferences, False)

	def test_edit(self):
		self.login_as('admin')
		r = self.client.post(
			path=url_for('service.edit_submit', id=self.service_id),
			follow_redirects=True,
			data={
				'name': 'new-name',
				'access-group': '',
				'remailer-mode': 'DISABLED',
				'remailer-overwrite-mode': 'ENABLED_V2',
				'remailer-overwrite-users': '',
			},
		)
		dump('service_edit_submit', r)
		self.assertEqual(r.status_code, 200)
		service = Service.query.get(self.service_id)
		self.assertEqual(service.name, 'new-name')
		self.assertEqual(service.limit_access, True)
		self.assertEqual(service.access_group, None)
		self.assertEqual(service.remailer_mode, RemailerMode.DISABLED)
		self.assertEqual(service.enable_email_preferences, False)
		self.assertEqual(service.hide_deactivated_users, False)

	def test_edit_access_all(self):
		self.login_as('admin')
		r = self.client.post(
			path=url_for('service.edit_submit', id=self.service_id),
			follow_redirects=True,
			data={
				'name': 'test1',
				'access-group': 'all',
				'remailer-mode': 'DISABLED',
				'remailer-overwrite-mode': 'ENABLED_V2',
				'remailer-overwrite-users': '',
			},
		)
		self.assertEqual(r.status_code, 200)
		service = Service.query.get(self.service_id)
		self.assertEqual(service.limit_access, False)
		self.assertEqual(service.access_group, None)

	def test_edit_access_group(self):
		self.login_as('admin')
		r = self.client.post(
			path=url_for('service.edit_submit', id=self.service_id),
			follow_redirects=True,
			data={
				'name': 'test1',
				'access-group': str(self.get_users_group().id),
				'remailer-mode': 'DISABLED',
				'remailer-overwrite-mode': 'ENABLED_V2',
				'remailer-overwrite-users': '',
			},
		)
		self.assertEqual(r.status_code, 200)
		service = Service.query.get(self.service_id)
		self.assertEqual(service.limit_access, True)
		self.assertEqual(service.access_group, self.get_users_group())

	def test_edit_hide_deactivated_users(self):
		self.login_as('admin')
		r = self.client.post(
			path=url_for('service.edit_submit', id=self.service_id),
			follow_redirects=True,
			data={
				'name': 'test1',
				'access-group': '',
				'remailer-mode': 'DISABLED',
				'remailer-overwrite-mode': 'ENABLED_V2',
				'remailer-overwrite-users': '',
				'hide_deactivated_users': '1',
			},
		)
		self.assertEqual(r.status_code, 200)
		service = Service.query.get(self.service_id)
		self.assertEqual(service.hide_deactivated_users, True)

	def test_edit_email_preferences(self):
		self.login_as('admin')
		r = self.client.post(
			path=url_for('service.edit_submit', id=self.service_id),
			follow_redirects=True,
			data={
				'name': 'test1',
				'access-group': '',
				'remailer-mode': 'DISABLED',
				'remailer-overwrite-mode': 'ENABLED_V2',
				'remailer-overwrite-users': '',
				'enable_email_preferences': '1',
			},
		)
		self.assertEqual(r.status_code, 200)
		service = Service.query.get(self.service_id)
		self.assertEqual(service.enable_email_preferences, True)

	def test_edit_remailer_mode(self):
		self.login_as('admin')
		r = self.client.post(
			path=url_for('service.edit_submit', id=self.service_id),
			follow_redirects=True,
			data={
				'name': 'test1',
				'access-group': '',
				'remailer-mode': 'ENABLED_V2',
				'remailer-overwrite-mode': 'ENABLED_V2',
				'remailer-overwrite-users': '',
			},
		)
		self.assertEqual(r.status_code, 200)
		service = Service.query.get(self.service_id)
		self.assertEqual(service.remailer_mode, RemailerMode.ENABLED_V2)

	def test_edit_remailer_overwrite_enable(self):
		self.login_as('admin')
		r = self.client.post(
			path=url_for('service.edit_submit', id=self.service_id),
			follow_redirects=True,
			data={
				'name': 'test1',
				'access-group': '',
				'remailer-mode': 'DISABLED',
				'remailer-overwrite-mode': 'ENABLED_V2',
				'remailer-overwrite-users': 'testuser, testadmin',
			},
		)
		self.assertEqual(r.status_code, 200)
		service_user1 = ServiceUser.query.get((self.service_id, self.get_user().id))
		service_user2 = ServiceUser.query.get((self.service_id, self.get_admin().id))
		self.assertEqual(service_user1.remailer_overwrite_mode, RemailerMode.ENABLED_V2)
		self.assertEqual(service_user2.remailer_overwrite_mode, RemailerMode.ENABLED_V2)
		self.assertEqual(
			set(ServiceUser.query.filter(
				ServiceUser.service_id == self.service_id,
				ServiceUser.remailer_overwrite_mode != None
			).all()),
			{service_user1, service_user2}
		)

	def test_edit_remailer_overwrite_change(self):
		service_user = ServiceUser.query.get((self.service_id, self.get_user().id))
		service_user.remailer_overwrite_mode = RemailerMode.ENABLED_V2
		db.session.commit()
		self.login_as('admin')
		r = self.client.post(
			path=url_for('service.edit_submit', id=self.service_id),
			follow_redirects=True,
			data={
				'name': 'test1',
				'access-group': '',
				'remailer-mode': 'DISABLED',
				'remailer-overwrite-mode': 'ENABLED_V1',
				'remailer-overwrite-users': ', testadmin',
			},
		)
		self.assertEqual(r.status_code, 200)
		service_user = ServiceUser.query.get((self.service_id, self.get_admin().id))
		self.assertEqual(service_user.remailer_overwrite_mode, RemailerMode.ENABLED_V1)
		self.assertEqual(
			ServiceUser.query.filter(
				ServiceUser.service_id == self.service_id,
				ServiceUser.remailer_overwrite_mode != None
			).all(),
			[service_user]
		)

	def test_edit_remailer_overwrite_disable(self):
		service_user = ServiceUser.query.get((self.service_id, self.get_user().id))
		service_user.remailer_overwrite_mode = RemailerMode.ENABLED_V2
		db.session.commit()
		self.login_as('admin')
		r = self.client.post(
			path=url_for('service.edit_submit', id=self.service_id),
			follow_redirects=True,
			data={
				'name': 'test1',
				'access-group': '',
				'remailer-mode': 'DISABLED',
				'remailer-overwrite-mode': 'ENABLED_V2',
				'remailer-overwrite-users': '',
			},
		)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(
			ServiceUser.query.filter(
				ServiceUser.service_id == self.service_id,
				ServiceUser.remailer_overwrite_mode != None
			).all(),
			[]
		)

	def test_delete(self):
		self.login_as('admin')
		r = self.client.get(path=url_for('service.delete', id=self.service_id), follow_redirects=True)
		dump('service_delete', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(Service.query.get(self.service_id))

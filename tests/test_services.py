import datetime
import unittest

from flask import url_for

from utils import dump, UffdTestCase
from uffd.remailer import remailer
from uffd.tasks import cleanup_task
from uffd.database import db
from uffd.models import Service, ServiceUser, User

class TestServiceUser(UffdTestCase):
	def setUp(self):
		super().setUp()
		db.session.add_all([Service(name='service1'), Service(name='service2', use_remailer=True)])
		db.session.commit()

	def test_auto_create(self):
		service_count = Service.query.count()
		user_count = User.query.count()
		self.assertEqual(ServiceUser.query.count(), service_count * user_count)
		db.session.add(User(loginname='newuser1', displayname='New User', primary_email_address='new1@example.com'))
		db.session.commit()
		self.assertEqual(ServiceUser.query.count(), service_count * (user_count + 1))
		db.session.add(Service(name='service3'))
		db.session.commit()
		self.assertEqual(ServiceUser.query.count(), (service_count + 1) * (user_count + 1))
		db.session.add(User(loginname='newuser2', displayname='New User', primary_email_address='new2@example.com'))
		db.session.add(User(loginname='newuser3', displayname='New User', primary_email_address='new3@example.com'))
		db.session.add(Service(name='service4'))
		db.session.add(Service(name='service5'))
		db.session.commit()
		self.assertEqual(ServiceUser.query.count(), (service_count + 3) * (user_count + 3))

	def test_create_missing(self):
		service_count = Service.query.count()
		user_count = User.query.count()
		self.assertEqual(ServiceUser.query.count(), service_count * user_count)
		db.session.delete(ServiceUser.query.first())
		db.session.commit()
		self.assertEqual(ServiceUser.query.count(), service_count * user_count - 1)
		cleanup_task.run()
		db.session.commit()
		self.assertEqual(ServiceUser.query.count(), service_count  * user_count)

	def test_real_email(self):
		user = self.get_user()
		service = Service.query.filter_by(name='service1').first()
		service_user = ServiceUser.query.get((service.id, user.id))
		self.assertEqual(service_user.real_email, user.primary_email.address)

	def test_remailer_email(self):
		user = self.get_user()
		service = Service.query.filter_by(name='service1').first()
		service_user = ServiceUser.query.get((service.id, user.id))
		with self.assertRaises(Exception):
			service_user.remailer_email
		self.app.config['REMAILER_DOMAIN'] = 'remailer.example.com'
		self.assertEqual(service_user.remailer_email, remailer.build_address(service.id, user.id))

	def test_get_by_remailer_email(self):
		user = self.get_user()
		service = Service.query.filter_by(name='service1').first()
		service_user = ServiceUser.query.get((service.id, user.id))
		self.app.config['REMAILER_DOMAIN'] = 'remailer.example.com'
		remailer_email = remailer.build_address(service.id, user.id)
		# 1. remailer not setup
		self.app.config['REMAILER_DOMAIN'] = ''
		self.assertIsNone(ServiceUser.get_by_remailer_email(user.primary_email.address))
		self.assertIsNone(ServiceUser.get_by_remailer_email(remailer_email))
		self.assertIsNone(ServiceUser.get_by_remailer_email('invalid'))
		# 2. remailer setup
		self.app.config['REMAILER_DOMAIN'] = 'remailer.example.com'
		self.assertIsNone(ServiceUser.get_by_remailer_email(user.primary_email.address))
		self.assertEqual(ServiceUser.get_by_remailer_email(remailer_email), service_user)
		self.assertIsNone(ServiceUser.get_by_remailer_email('invalid'))

	def test_email(self):
		user = self.get_user()
		service = Service.query.filter_by(name='service1').first()
		service_user = ServiceUser.query.get((service.id, user.id))
		self.app.config['REMAILER_DOMAIN'] = 'remailer.example.com'
		remailer_email = remailer.build_address(service.id, user.id)
		# 1. remailer not setup
		self.app.config['REMAILER_DOMAIN'] = ''
		self.assertEqual(service_user.email, user.primary_email.address)
		# 2. remailer setup + service.use_remailer disabled
		self.app.config['REMAILER_DOMAIN'] = 'remailer.example.com'
		self.assertEqual(service_user.email, user.primary_email.address)
		# 3. remailer setup + service.use_remailer enabled + REMAILER_LIMIT_TO_USERS unset
		service.use_remailer = True
		db.session.commit()
		self.assertEqual(service_user.email, remailer_email)
		# 4. remailer setup + service.use_remailer enabled + REMAILER_LIMIT_TO_USERS does not include user
		self.app.config['REMAILER_LIMIT_TO_USERS'] = ['testadmin']
		self.assertEqual(service_user.email, user.primary_email.address)
		# 5. remailer setup + service.use_remailer enabled + REMAILER_LIMIT_TO_USERS includes user
		self.app.config['REMAILER_LIMIT_TO_USERS'] = ['testuser']
		self.assertEqual(service_user.email, remailer_email)

	def test_filter_query_by_email(self):
		def run_query(value):
			return {(su.service_id, su.user_id) for su in ServiceUser.filter_query_by_email(ServiceUser.query, value)}

		user1 = self.get_user()
		user2 = User(loginname='user2', primary_email_address=user1.primary_email.address, displayname='User 2')
		db.session.add(user2)
		db.session.commit()
		service1 = Service.query.filter_by(name='service1').first() # use_remailer=False
		service2 = Service.query.filter_by(name='service2').first() # use_remailer=True
		self.app.config['REMAILER_DOMAIN'] = 'remailer.example.com'
		remailer_email1_1 = remailer.build_address(service1.id, user1.id)
		remailer_email2_1 = remailer.build_address(service2.id, user1.id)
		remailer_email1_2 = remailer.build_address(service1.id, user2.id)
		remailer_email2_2 = remailer.build_address(service2.id, user2.id)

		# 1. remailer disabled
		self.app.config['REMAILER_DOMAIN'] = ''
		self.assertEqual(run_query(user1.primary_email.address), {
			(service1.id, user1.id), (service1.id, user2.id),
			(service2.id, user1.id), (service2.id, user2.id),
		})
		self.assertEqual(run_query(remailer_email1_1), set())
		self.assertEqual(run_query(remailer_email2_1), set())
		self.assertEqual(run_query('invalid'), set())

		# 2. remailer enabled + REMAILER_LIMIT_TO_USERS unset
		self.app.config['REMAILER_DOMAIN'] = 'remailer.example.com'
		self.assertEqual(run_query(user1.primary_email.address), {
			(service1.id, user1.id), (service1.id, user2.id),
		})
		self.assertEqual(run_query(remailer_email1_1), set())
		self.assertEqual(run_query(remailer_email2_1), {
			(service2.id, user1.id),
		})
		self.assertEqual(run_query(remailer_email2_1 + ' '), set())
		self.assertEqual(run_query('invalid'), set())

		# 3. remailer enabled + REMAILER_LIMIT_TO_USERS includes testuser
		self.app.config['REMAILER_LIMIT_TO_USERS'] = ['testuser']
		self.assertEqual(run_query(user1.primary_email.address), {
			(service1.id, user1.id), (service1.id, user2.id),
			(service2.id, user2.id),
		})
		self.assertEqual(run_query(remailer_email1_1), set())
		self.assertEqual(run_query(remailer_email2_1), {
			(service2.id, user1.id),
		})
		self.assertEqual(run_query(remailer_email2_1 + ' '), set())
		self.assertEqual(run_query(remailer_email1_2), set())
		self.assertEqual(run_query(remailer_email2_2), set())
		self.assertEqual(run_query('invalid'), set())

		# 4. remailer enabled + REMAILER_LIMIT_TO_USERS does not include user (should behave the same as 1.)
		self.app.config['REMAILER_LIMIT_TO_USERS'] = ['testadmin']
		self.assertEqual(run_query(user1.primary_email.address), {
			(service1.id, user1.id), (service1.id, user2.id),
			(service2.id, user1.id), (service2.id, user2.id),
		})
		self.assertEqual(run_query(remailer_email1_1), set())
		self.assertEqual(run_query(remailer_email2_1), set())
		self.assertEqual(run_query('invalid'), set())

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

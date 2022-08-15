import datetime
import unittest

from flask import url_for, session
import sqlalchemy

from uffd import create_app, db
from uffd.models import User, remailer, RemailerAddress, Group, Role, RoleGroup, Service

from utils import dump, UffdTestCase

class TestUserModel(UffdTestCase):
	def test_has_permission(self):
		user_ = self.get_user() # has 'users' and 'uffd_access' group
		admin = self.get_admin() # has 'users', 'uffd_access' and 'uffd_admin' group
		self.assertTrue(user_.has_permission(None))
		self.assertTrue(admin.has_permission(None))
		self.assertTrue(user_.has_permission('users'))
		self.assertTrue(admin.has_permission('users'))
		self.assertFalse(user_.has_permission('notagroup'))
		self.assertFalse(admin.has_permission('notagroup'))
		self.assertFalse(user_.has_permission('uffd_admin'))
		self.assertTrue(admin.has_permission('uffd_admin'))
		self.assertFalse(user_.has_permission(['uffd_admin']))
		self.assertTrue(admin.has_permission(['uffd_admin']))
		self.assertFalse(user_.has_permission(['uffd_admin', 'notagroup']))
		self.assertTrue(admin.has_permission(['uffd_admin', 'notagroup']))
		self.assertFalse(user_.has_permission(['notagroup', 'uffd_admin']))
		self.assertTrue(admin.has_permission(['notagroup', 'uffd_admin']))
		self.assertTrue(user_.has_permission(['uffd_admin', 'users']))
		self.assertTrue(admin.has_permission(['uffd_admin', 'users']))
		self.assertTrue(user_.has_permission([['uffd_admin', 'users'], ['users', 'uffd_access']]))
		self.assertTrue(admin.has_permission([['uffd_admin', 'users'], ['users', 'uffd_access']]))
		self.assertFalse(user_.has_permission(['uffd_admin', ['users', 'notagroup']]))
		self.assertTrue(admin.has_permission(['uffd_admin', ['users', 'notagroup']]))

	def test_unix_uid_generation(self):
		self.app.config['USER_MIN_UID'] = 10000
		self.app.config['USER_MAX_UID'] = 18999
		self.app.config['USER_SERVICE_MIN_UID'] = 19000
		self.app.config['USER_SERVICE_MAX_UID'] =19999
		User.query.delete()
		db.session.commit()
		user0 = User(loginname='user0', displayname='user0', mail='user0@example.com')
		user1 = User(loginname='user1', displayname='user1', mail='user1@example.com')
		user2 = User(loginname='user2', displayname='user2', mail='user2@example.com')
		db.session.add_all([user0, user1, user2])
		db.session.commit()
		self.assertEqual(user0.unix_uid, 10000)
		self.assertEqual(user1.unix_uid, 10001)
		self.assertEqual(user2.unix_uid, 10002)
		db.session.delete(user1)
		db.session.commit()
		user3 = User(loginname='user3', displayname='user3', mail='user3@example.com')
		db.session.add(user3)
		db.session.commit()
		self.assertEqual(user3.unix_uid, 10003)
		service0 = User(loginname='service0', displayname='service0', mail='service0@example.com', is_service_user=True)
		service1 = User(loginname='service1', displayname='service1', mail='service1@example.com', is_service_user=True)
		db.session.add_all([service0, service1])
		db.session.commit()
		self.assertEqual(service0.unix_uid, 19000)
		self.assertEqual(service1.unix_uid, 19001)

	def test_unix_uid_generation_overlapping(self):
		self.app.config['USER_MIN_UID'] = 10000
		self.app.config['USER_MAX_UID'] = 19999
		self.app.config['USER_SERVICE_MIN_UID'] = 10000
		self.app.config['USER_SERVICE_MAX_UID'] = 19999
		User.query.delete()
		db.session.commit()
		user0 = User(loginname='user0', displayname='user0', mail='user0@example.com')
		service0 = User(loginname='service0', displayname='service0', mail='service0@example.com', is_service_user=True)
		user1 = User(loginname='user1', displayname='user1', mail='user1@example.com')
		db.session.add_all([user0, service0, user1])
		db.session.commit()
		self.assertEqual(user0.unix_uid, 10000)
		self.assertEqual(service0.unix_uid, 10001)
		self.assertEqual(user1.unix_uid, 10002)

	def test_unix_uid_generation_overflow(self):
		self.app.config['USER_MIN_UID'] = 10000
		self.app.config['USER_MAX_UID'] = 10001
		User.query.delete()
		db.session.commit()
		user0 = User(loginname='user0', displayname='user0', mail='user0@example.com')
		user1 = User(loginname='user1', displayname='user1', mail='user1@example.com')
		db.session.add_all([user0, user1])
		db.session.commit()
		self.assertEqual(user0.unix_uid, 10000)
		self.assertEqual(user1.unix_uid, 10001)
		with self.assertRaises(sqlalchemy.exc.IntegrityError):
			user2 = User(loginname='user2', displayname='user2', mail='user2@example.com')
			db.session.add(user2)
			db.session.commit()

	def test_set_mail(self):
		user = User()
		self.assertTrue(user.set_mail('foobar@example.com'))
		self.assertEqual(user.mail, 'foobar@example.com')
		self.assertFalse(user.set_mail(''))
		self.assertEqual(user.mail, 'foobar@example.com')
		self.assertFalse(user.set_mail('foobar'))
		self.assertFalse(user.set_mail('@'))
		self.app.config['REMAILER_DOMAIN'] = 'remailer.example.com'
		self.assertFalse(user.set_mail('foobar@remailer.example.com'))
		self.assertFalse(user.set_mail('v1-1-testuser@remailer.example.com'))
		self.assertFalse(user.set_mail('v1-1-testuser @ remailer.example.com'))
		self.assertFalse(user.set_mail('v1-1-testuser@REMAILER.example.com'))
		self.assertFalse(user.set_mail('v1-1-testuser@foobar@remailer.example.com'))

	def test_get_service_mail(self):
		service1 = Service(name='service1')
		service2 = Service(name='service2', use_remailer=True)
		db.session.add_all([service1, service2])
		db.session.commit()
		user = self.get_user()
		self.assertEqual(user.get_service_mail(service1), user.mail)
		self.assertEqual(user.get_service_mail(service2), user.mail)
		self.app.config['REMAILER_DOMAIN'] = 'remailer.example.com'
		self.assertEqual(user.get_service_mail(service1), user.mail)
		self.assertEqual(user.get_service_mail(service2), remailer.build_address(user, service2))
		self.app.config['REMAILER_LIMIT_TO_USERS'] = ['testadmin']
		self.assertEqual(user.get_service_mail(service1), user.mail)
		self.assertEqual(user.get_service_mail(service2), user.mail)
		self.app.config['REMAILER_LIMIT_TO_USERS'] = ['testadmin', 'testuser']
		self.assertEqual(user.get_service_mail(service1), user.mail)
		self.assertEqual(user.get_service_mail(service2), remailer.build_address(user, service2))

	def test_filter_by_service_mail(self):
		service1 = Service(name='service1')
		service2 = Service(name='service2', use_remailer=True)
		db.session.add_all([service1, service2])
		db.session.commit()
		user = self.get_user()
		self.assertEqual(User.query.filter(User.filter_by_service_mail(service1, user.mail)).all(), [user])
		self.assertEqual(User.query.filter(User.filter_by_service_mail(service1, remailer.build_address(user, service1))).all(), [])
		self.assertEqual(User.query.filter(User.filter_by_service_mail(service1, remailer.build_address(user, service2))).all(), [])
		self.assertEqual(User.query.filter(User.filter_by_service_mail(service2, user.mail)).all(), [user])
		self.assertEqual(User.query.filter(User.filter_by_service_mail(service2, remailer.build_address(user, service1))).all(), [])
		self.assertEqual(User.query.filter(User.filter_by_service_mail(service2, remailer.build_address(user, service2))).all(), [])
		self.app.config['REMAILER_DOMAIN'] = 'remailer.example.com'
		self.assertEqual(User.query.filter(User.filter_by_service_mail(service1, user.mail)).all(), [user])
		self.assertEqual(User.query.filter(User.filter_by_service_mail(service1, remailer.build_address(user, service1))).all(), [])
		self.assertEqual(User.query.filter(User.filter_by_service_mail(service1, remailer.build_address(user, service2))).all(), [])
		self.assertEqual(User.query.filter(User.filter_by_service_mail(service2, user.mail)).all(), [])
		self.assertEqual(User.query.filter(User.filter_by_service_mail(service2, remailer.build_address(user, service2))).all(), [user])
		self.assertEqual(User.query.filter(User.filter_by_service_mail(service2, remailer.build_address(user, service1))).all(), [])
		self.app.config['REMAILER_LIMIT_TO_USERS'] = ['testadmin']
		self.assertEqual(User.query.filter(User.filter_by_service_mail(service1, user.mail)).all(), [user])
		self.assertEqual(User.query.filter(User.filter_by_service_mail(service1, remailer.build_address(user, service1))).all(), [])
		self.assertEqual(User.query.filter(User.filter_by_service_mail(service1, remailer.build_address(user, service2))).all(), [])
		self.assertEqual(User.query.filter(User.filter_by_service_mail(service2, user.mail)).all(), [user])
		self.assertEqual(User.query.filter(User.filter_by_service_mail(service2, remailer.build_address(user, service1))).all(), [])
		self.assertEqual(User.query.filter(User.filter_by_service_mail(service2, remailer.build_address(user, service2))).all(), [])
		self.app.config['REMAILER_LIMIT_TO_USERS'] = ['testadmin', 'testuser']
		self.assertEqual(User.query.filter(User.filter_by_service_mail(service1, user.mail)).all(), [user])
		self.assertEqual(User.query.filter(User.filter_by_service_mail(service1, remailer.build_address(user, service1))).all(), [])
		self.assertEqual(User.query.filter(User.filter_by_service_mail(service1, remailer.build_address(user, service2))).all(), [])
		self.assertEqual(User.query.filter(User.filter_by_service_mail(service2, user.mail)).all(), [])
		self.assertEqual(User.query.filter(User.filter_by_service_mail(service2, remailer.build_address(user, service1))).all(), [])
		self.assertEqual(User.query.filter(User.filter_by_service_mail(service2, remailer.build_address(user, service2))).all(), [user])

class TestRemailer(UffdTestCase):
	def setUpDB(self):
		self.service1 = Service(name='service1')
		self.service2 = Service(name='service2', use_remailer=True)
		db.session.add_all([self.service1, self.service2])

	def test_is_remailer_domain(self):
		self.app.config['REMAILER_DOMAIN'] = 'remailer.example.com'
		self.assertTrue(remailer.is_remailer_domain('remailer.example.com'))
		self.assertTrue(remailer.is_remailer_domain('REMAILER.EXAMPLE.COM'))
		self.assertTrue(remailer.is_remailer_domain(' remailer.example.com '))
		self.assertFalse(remailer.is_remailer_domain('other.remailer.example.com'))
		self.assertFalse(remailer.is_remailer_domain('example.com'))
		self.app.config['REMAILER_OLD_DOMAINS'] = [' OTHER.remailer.example.com ']
		self.assertTrue(remailer.is_remailer_domain(' OTHER.remailer.example.com '))
		self.assertTrue(remailer.is_remailer_domain('remailer.example.com'))
		self.assertTrue(remailer.is_remailer_domain('other.remailer.example.com'))
		self.assertFalse(remailer.is_remailer_domain('example.com'))

	def test_build_address(self):
		self.app.config['REMAILER_DOMAIN'] = 'remailer.example.com'
		user = self.get_user()
		self.assertTrue(remailer.build_address(user, self.service1).endswith('@remailer.example.com'))
		self.assertTrue(remailer.build_address(user, self.service2).endswith('@remailer.example.com'))
		self.assertLessEqual(len(remailer.build_local_part(user, self.service1)), 64)
		self.assertLessEqual(len(remailer.build_address(user, self.service1)), 256)
		self.assertEqual(remailer.build_address(user, self.service1), remailer.build_address(user, self.service1))
		self.assertNotEqual(remailer.build_address(user, self.service1), remailer.build_address(user, self.service2))
		addr = remailer.build_address(user, self.service1)
		self.app.config['REMAILER_OLD_DOMAINS'] = ['old.remailer.example.com']
		self.assertEqual(remailer.build_address(user, self.service1), addr)
		self.assertTrue(remailer.build_address(user, self.service1).endswith('@remailer.example.com'))
		self.app.config['REMAILER_SECRET_KEY'] = self.app.config['SECRET_KEY']
		self.assertEqual(remailer.build_address(user, self.service1), addr)
		self.app.config['REMAILER_SECRET_KEY'] = 'REMAILER-DEBUGKEY'
		self.assertNotEqual(remailer.build_address(user, self.service1), addr)

	def test_parse_address(self):
		self.app.config['REMAILER_DOMAIN'] = 'remailer.example.com'
		user = self.get_user()
		addr = remailer.build_address(user, self.service2)
		# REMAILER_DOMAIN behaviour
		self.app.config['REMAILER_DOMAIN'] = None
		self.assertIsNone(remailer.parse_address(addr))
		self.assertIsNone(remailer.parse_address('foo@example.com'))
		self.app.config['REMAILER_DOMAIN'] = 'remailer.example.com'
		self.assertEqual(remailer.parse_address(addr), RemailerAddress(user, self.service2))
		self.assertIsNone(remailer.parse_address('foo@example.com'))
		self.assertIsNone(remailer.parse_address('foo@remailer.example.com'))
		self.assertIsNone(remailer.parse_address('v1-foo@remailer.example.com'))
		self.app.config['REMAILER_DOMAIN'] = 'new-remailer.example.com'
		self.assertIsNone(remailer.parse_address(addr))
		self.app.config['REMAILER_OLD_DOMAINS'] = ['remailer.example.com']
		self.assertEqual(remailer.parse_address(addr), RemailerAddress(user, self.service2))
		# REMAILER_SECRET_KEY behaviour
		self.app.config['REMAILER_DOMAIN'] = 'remailer.example.com'
		self.app.config['REMAILER_OLD_DOMAINS'] = []
		self.assertEqual(remailer.parse_address(addr), RemailerAddress(user, self.service2))
		self.app.config['REMAILER_SECRET_KEY'] = self.app.config['SECRET_KEY']
		self.assertEqual(remailer.parse_address(addr), RemailerAddress(user, self.service2))
		self.app.config['REMAILER_SECRET_KEY'] = 'REMAILER-DEBUGKEY'
		self.assertIsNone(remailer.parse_address(addr))

class TestUserViews(UffdTestCase):
	def setUp(self):
		super().setUp()
		self.login_as('admin')

	def test_index(self):
		r = self.client.get(path=url_for('user.index'), follow_redirects=True)
		dump('user_index', r)
		self.assertEqual(r.status_code, 200)

	def test_new(self):
		db.session.add(Role(name='base', is_default=True))
		role1 = Role(name='role1')
		db.session.add(role1)
		role2 = Role(name='role2')
		db.session.add(role2)
		db.session.commit()
		role1_id = role1.id
		r = self.client.get(path=url_for('user.show'), follow_redirects=True)
		dump('user_new', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(User.query.filter_by(loginname='newuser').one_or_none())
		r = self.client.post(path=url_for('user.update'),
			data={'loginname': 'newuser', 'mail': 'newuser@example.com', 'displayname': 'New User',
			f'role-{role1_id}': '1', 'password': 'newpassword'}, follow_redirects=True)
		dump('user_new_submit', r)
		self.assertEqual(r.status_code, 200)
		user_ = User.query.filter_by(loginname='newuser').one_or_none()
		roles = sorted([r.name for r in user_.roles_effective])
		self.assertIsNotNone(user_)
		self.assertFalse(user_.is_service_user)
		self.assertEqual(user_.loginname, 'newuser')
		self.assertEqual(user_.displayname, 'New User')
		self.assertEqual(user_.mail, 'newuser@example.com')
		self.assertGreaterEqual(user_.unix_uid, self.app.config['USER_MIN_UID'])
		self.assertLessEqual(user_.unix_uid, self.app.config['USER_MAX_UID'])
		role1 = Role(name='role1')
		self.assertEqual(roles, ['base', 'role1'])
		# TODO: confirm Mail is send, login not yet possible

	def test_new_service(self):
		db.session.add(Role(name='base', is_default=True))
		role1 = Role(name='role1')
		db.session.add(role1)
		role2 = Role(name='role2')
		db.session.add(role2)
		db.session.commit()
		role1_id = role1.id
		r = self.client.get(path=url_for('user.show'), follow_redirects=True)
		dump('user_new_service', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(User.query.filter_by(loginname='newuser').one_or_none())
		r = self.client.post(path=url_for('user.update'),
			data={'loginname': 'newuser', 'mail': 'newuser@example.com', 'displayname': 'New User',
			f'role-{role1_id}': '1', 'password': 'newpassword', 'serviceaccount': '1'}, follow_redirects=True)
		dump('user_new_submit', r)
		self.assertEqual(r.status_code, 200)
		user = User.query.filter_by(loginname='newuser').one_or_none()
		roles = sorted([r.name for r in user.roles])
		self.assertIsNotNone(user)
		self.assertTrue(user.is_service_user)
		self.assertEqual(user.loginname, 'newuser')
		self.assertEqual(user.displayname, 'New User')
		self.assertEqual(user.mail, 'newuser@example.com')
		self.assertTrue(user.unix_uid)
		role1 = Role(name='role1')
		self.assertEqual(roles, ['role1'])
		# TODO: confirm Mail is send, login not yet possible

	def test_new_invalid_loginname(self):
		r = self.client.post(path=url_for('user.update'),
			data={'loginname': '!newuser', 'mail': 'newuser@example.com', 'displayname': 'New User',
			'password': 'newpassword'}, follow_redirects=True)
		dump('user_new_invalid_loginname', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(User.query.filter_by(loginname='newuser').one_or_none())

	def test_new_empty_loginname(self):
		r = self.client.post(path=url_for('user.update'),
			data={'loginname': '', 'mail': 'newuser@example.com', 'displayname': 'New User',
			'password': 'newpassword'}, follow_redirects=True)
		dump('user_new_empty_loginname', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(User.query.filter_by(loginname='newuser').one_or_none())

	def test_new_empty_email(self):
		r = self.client.post(path=url_for('user.update'),
			data={'loginname': 'newuser', 'mail': '', 'displayname': 'New User',
			'password': 'newpassword'}, follow_redirects=True)
		dump('user_new_empty_email', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(User.query.filter_by(loginname='newuser').one_or_none())

	def test_new_invalid_display_name(self):
		r = self.client.post(path=url_for('user.update'),
			data={'loginname': 'newuser', 'mail': 'newuser@example.com', 'displayname': 'A'*200,
			'password': 'newpassword'}, follow_redirects=True)
		dump('user_new_invalid_display_name', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(User.query.filter_by(loginname='newuser').one_or_none())

	def test_update(self):
		user_unupdated = self.get_user()
		db.session.add(Role(name='base', is_default=True))
		role1 = Role(name='role1')
		db.session.add(role1)
		role2 = Role(name='role2')
		db.session.add(role2)
		role2.members.append(user_unupdated)
		db.session.commit()
		role1_id = role1.id
		r = self.client.get(path=url_for('user.show', id=user_unupdated.id), follow_redirects=True)
		dump('user_update', r)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('user.update', id=user_unupdated.id),
			data={'loginname': 'testuser', 'mail': 'newuser@example.com', 'displayname': 'New User',
			f'role-{role1_id}': '1', 'password': ''}, follow_redirects=True)
		dump('user_update_submit', r)
		self.assertEqual(r.status_code, 200)
		user_updated = self.get_user()
		roles = sorted([r.name for r in user_updated.roles_effective])
		self.assertEqual(user_updated.displayname, 'New User')
		self.assertEqual(user_updated.mail, 'newuser@example.com')
		self.assertEqual(user_updated.unix_uid, user_unupdated.unix_uid)
		self.assertEqual(user_updated.loginname, user_unupdated.loginname)
		self.assertTrue(user_updated.password.verify('userpassword'))
		self.assertEqual(roles, ['base', 'role1'])

	def test_update_password(self):
		user_unupdated = self.get_user()
		r = self.client.get(path=url_for('user.show', id=user_unupdated.id), follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('user.update', id=user_unupdated.id),
			data={'loginname': 'testuser', 'mail': 'newuser@example.com', 'displayname': 'New User',
			'password': 'newpassword'}, follow_redirects=True)
		dump('user_update_password', r)
		self.assertEqual(r.status_code, 200)
		user_updated = self.get_user()
		self.assertEqual(user_updated.displayname, 'New User')
		self.assertEqual(user_updated.mail, 'newuser@example.com')
		self.assertEqual(user_updated.unix_uid, user_unupdated.unix_uid)
		self.assertEqual(user_updated.loginname, user_unupdated.loginname)
		self.assertTrue(user_updated.password.verify('newpassword'))
		self.assertFalse(user_updated.password.verify('userpassword'))

	def test_update_invalid_password(self):
		user_unupdated = self.get_user()
		r = self.client.get(path=url_for('user.show', id=user_unupdated.id), follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('user.update', id=user_unupdated.id),
			data={'loginname': 'testuser', 'mail': 'newuser@example.com', 'displayname': 'New User',
			'password': 'A'}, follow_redirects=True)
		dump('user_update_invalid_password', r)
		self.assertEqual(r.status_code, 200)
		user_updated = self.get_user()
		self.assertFalse(user_updated.password.verify('A'))
		self.assertTrue(user_updated.password.verify('userpassword'))
		self.assertEqual(user_updated.displayname, user_unupdated.displayname)
		self.assertEqual(user_updated.mail, user_unupdated.mail)
		self.assertEqual(user_updated.loginname, user_unupdated.loginname)

	# Regression test for #100 (login not possible if password contains character disallowed by SASLprep)
	def test_update_saslprep_invalid_password(self):
		user_unupdated = self.get_user()
		r = self.client.get(path=url_for('user.show', id=user_unupdated.id), follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('user.update', id=user_unupdated.id),
			data={'loginname': 'testuser', 'mail': 'newuser@example.com', 'displayname': 'New User',
			'password': 'newpassword\n'}, follow_redirects=True)
		dump('user_update_invalid_password', r)
		self.assertEqual(r.status_code, 200)
		user_updated = self.get_user()
		self.assertFalse(user_updated.password.verify('newpassword\n'))
		self.assertTrue(user_updated.password.verify('userpassword'))
		self.assertEqual(user_updated.displayname, user_unupdated.displayname)
		self.assertEqual(user_updated.mail, user_unupdated.mail)
		self.assertEqual(user_updated.loginname, user_unupdated.loginname)

	def test_update_empty_email(self):
		user_unupdated = self.get_user()
		r = self.client.get(path=url_for('user.show', id=user_unupdated.id), follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('user.update', id=user_unupdated.id),
			data={'loginname': 'testuser', 'mail': '', 'displayname': 'New User',
			'password': 'newpassword'}, follow_redirects=True)
		dump('user_update_empty_mail', r)
		self.assertEqual(r.status_code, 200)
		user_updated = self.get_user()
		self.assertEqual(user_updated.displayname, user_unupdated.displayname)
		self.assertEqual(user_updated.mail, user_unupdated.mail)
		self.assertEqual(user_updated.loginname, user_unupdated.loginname)
		self.assertFalse(user_updated.password.verify('newpassword'))
		self.assertTrue(user_updated.password.verify('userpassword'))

	def test_update_invalid_display_name(self):
		user_unupdated = self.get_user()
		r = self.client.get(path=url_for('user.show', id=user_unupdated.id), follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('user.update', id=user_unupdated.id),
			data={'loginname': 'testuser', 'mail': 'newuser@example.com', 'displayname': 'A'*200,
			'password': 'newpassword'}, follow_redirects=True)
		dump('user_update_invalid_display_name', r)
		self.assertEqual(r.status_code, 200)
		user_updated = self.get_user()
		self.assertEqual(user_updated.displayname, user_unupdated.displayname)
		self.assertEqual(user_updated.mail, user_unupdated.mail)
		self.assertEqual(user_updated.loginname, user_unupdated.loginname)
		self.assertFalse(user_updated.password.verify('newpassword'))
		self.assertTrue(user_updated.password.verify('userpassword'))

	def test_show(self):
		r = self.client.get(path=url_for('user.show', id=self.get_user().id), follow_redirects=True)
		dump('user_show', r)
		self.assertEqual(r.status_code, 200)

	def test_delete(self):
		r = self.client.get(path=url_for('user.delete', id=self.get_user().id), follow_redirects=True)
		dump('user_delete', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(self.get_user())

	def test_csvimport(self):
		role1 = Role(name='role1')
		db.session.add(role1)
		role2 = Role(name='role2')
		db.session.add(role2)
		db.session.commit()
		data = f'''\
newuser1,newuser1@example.com,
newuser2,newuser2@example.com,{role1.id}
newuser3,newuser3@example.com,{role1.id};{role2.id}
newuser4,newuser4@example.com,9999
newuser5,newuser5@example.com,notanumber
newuser6,newuser6@example.com,{role1.id};{role2.id};
newuser7,invalidmail,
newuser8,,
,newuser9@example.com,
,,

,,,
newuser10,newuser10@example.com,
newuser11,newuser11@example.com, {role1.id};{role2.id}
newuser12,newuser12@example.com,{role1.id};{role1.id}
<invalid tag-like thingy>'''
		r = self.client.post(path=url_for('user.csvimport'), data={'csv': data}, follow_redirects=True)
		dump('user_csvimport', r)
		self.assertEqual(r.status_code, 200)
		user = User.query.filter_by(loginname='newuser1').one_or_none()
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser1')
		self.assertEqual(user.displayname, 'newuser1')
		self.assertEqual(user.mail, 'newuser1@example.com')
		roles = sorted([r.name for r in user.roles])
		self.assertEqual(roles, [])
		user = User.query.filter_by(loginname='newuser2').one_or_none()
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser2')
		self.assertEqual(user.displayname, 'newuser2')
		self.assertEqual(user.mail, 'newuser2@example.com')
		roles = sorted([r.name for r in user.roles])
		self.assertEqual(roles, ['role1'])
		user = User.query.filter_by(loginname='newuser3').one_or_none()
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser3')
		self.assertEqual(user.displayname, 'newuser3')
		self.assertEqual(user.mail, 'newuser3@example.com')
		roles = sorted([r.name for r in user.roles])
		self.assertEqual(roles, ['role1', 'role2'])
		user = User.query.filter_by(loginname='newuser4').one_or_none()
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser4')
		self.assertEqual(user.displayname, 'newuser4')
		self.assertEqual(user.mail, 'newuser4@example.com')
		roles = sorted([r.name for r in user.roles])
		self.assertEqual(roles, [])
		user = User.query.filter_by(loginname='newuser5').one_or_none()
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser5')
		self.assertEqual(user.displayname, 'newuser5')
		self.assertEqual(user.mail, 'newuser5@example.com')
		roles = sorted([r.name for r in user.roles])
		self.assertEqual(roles, [])
		user = User.query.filter_by(loginname='newuser6').one_or_none()
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser6')
		self.assertEqual(user.displayname, 'newuser6')
		self.assertEqual(user.mail, 'newuser6@example.com')
		roles = sorted([r.name for r in user.roles])
		self.assertEqual(roles, ['role1', 'role2'])
		self.assertIsNone(User.query.filter_by(loginname='newuser7').one_or_none())
		self.assertIsNone(User.query.filter_by(loginname='newuser8').one_or_none())
		self.assertIsNone(User.query.filter_by(loginname='newuser9').one_or_none())
		user = User.query.filter_by(loginname='newuser10').one_or_none()
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser10')
		self.assertEqual(user.displayname, 'newuser10')
		self.assertEqual(user.mail, 'newuser10@example.com')
		roles = sorted([r.name for r in user.roles])
		self.assertEqual(roles, [])
		user = User.query.filter_by(loginname='newuser11').one_or_none()
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser11')
		self.assertEqual(user.displayname, 'newuser11')
		self.assertEqual(user.mail, 'newuser11@example.com')
		# Currently the csv import is not very robust, imho newuser11 should have role1 and role2!
		roles = sorted([r.name for r in user.roles])
		self.assertEqual(roles, ['role2'])
		user = User.query.filter_by(loginname='newuser12').one_or_none()
		self.assertIsNotNone(user)
		self.assertEqual(user.loginname, 'newuser12')
		self.assertEqual(user.displayname, 'newuser12')
		self.assertEqual(user.mail, 'newuser12@example.com')
		roles = sorted([r.name for r in user.roles])
		self.assertEqual(roles, ['role1'])

class TestUserCLI(UffdTestCase):
	def setUp(self):
		super().setUp()
		role = Role(name='admin')
		role.groups[self.get_admin_group()] = RoleGroup(group=self.get_admin_group())
		db.session.add(role)
		db.session.add(Role(name='test'))
		db.session.commit()
		self.client.__exit__(None, None, None)

	def test_list(self):
		result = self.app.test_cli_runner().invoke(args=['user', 'list'])
		self.assertEqual(result.exit_code, 0)

	def test_show(self):
		result = self.app.test_cli_runner().invoke(args=['user', 'show', 'testuser'])
		self.assertEqual(result.exit_code, 0)
		result = self.app.test_cli_runner().invoke(args=['user', 'show', 'doesnotexist'])
		self.assertEqual(result.exit_code, 1)

	def test_create(self):
		result = self.app.test_cli_runner().invoke(args=['user', 'create', 'new user', '--mail', 'foobar@example.com']) # invalid login name
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['user', 'create', 'newuser', '--mail', '']) # invalid mail
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['user', 'create', 'newuser', '--mail', 'foobar@example.com', '--password', '']) # invalid password
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['user', 'create', 'newuser', '--mail', 'foobar@example.com', '--displayname', '']) # invalid display name
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['user', 'create', 'newuser', '--mail', 'foobar@example.com', '--add-role', 'doesnotexist']) # unknown role
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['user', 'create', 'testuser', '--mail', 'foobar@example.com']) # conflicting name
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['user', 'create', 'newuser', '--mail', 'newmail@example.com',
		                                                 '--displayname', 'New Display Name', '--password', 'newpassword', '--add-role', 'admin'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			user = User.query.filter_by(loginname='newuser').first()
			self.assertIsNotNone(user)
			self.assertEqual(user.mail, 'newmail@example.com')
			self.assertEqual(user.displayname, 'New Display Name')
			self.assertTrue(user.password.verify('newpassword'))
			self.assertEqual(user.roles, Role.query.filter_by(name='admin').all())
			self.assertIn(self.get_admin_group(), user.groups)

	def test_update(self):
		result = self.app.test_cli_runner().invoke(args=['user', 'update', 'doesnotexist', '--displayname', 'foo'])
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['user', 'update', 'testuser', '--mail', '']) # invalid mail
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['user', 'update', 'testuser', '--password', '']) # invalid password
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['user', 'update', 'testuser', '--displayname', '']) # invalid display name
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['user', 'update', 'testuser', '--remove-role', 'doesnotexist'])
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['user', 'update', 'testuser', '--mail', 'newmail@example.com',
		                                                 '--displayname', 'New Display Name', '--password', 'newpassword'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			user = User.query.filter_by(loginname='testuser').first()
			self.assertIsNotNone(user)
			self.assertEqual(user.mail, 'newmail@example.com')
			self.assertEqual(user.displayname, 'New Display Name')
			self.assertTrue(user.password.verify('newpassword'))
		result = self.app.test_cli_runner().invoke(args=['user', 'update', 'testuser', '--add-role', 'admin', '--add-role', 'test'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			user = User.query.filter_by(loginname='testuser').first()
			self.assertEqual(set(user.roles), {Role.query.filter_by(name='admin').one(), Role.query.filter_by(name='test').one()})
			self.assertIn(self.get_admin_group(), user.groups)
		result = self.app.test_cli_runner().invoke(args=['user', 'update', 'testuser', '--remove-role', 'admin'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			user = User.query.filter_by(loginname='testuser').first()
			self.assertEqual(user.roles, Role.query.filter_by(name='test').all())
			self.assertNotIn(self.get_admin_group(), user.groups)
		result = self.app.test_cli_runner().invoke(args=['user', 'update', 'testuser', '--clear-roles', '--add-role', 'admin'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			user = User.query.filter_by(loginname='testuser').first()
			self.assertEqual(user.roles, Role.query.filter_by(name='admin').all())
			self.assertIn(self.get_admin_group(), user.groups)

	def test_delete(self):
		with self.app.test_request_context():
			self.assertIsNotNone(User.query.filter_by(loginname='testuser').first())
		result = self.app.test_cli_runner().invoke(args=['user', 'delete', 'testuser'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			self.assertIsNone(User.query.filter_by(loginname='testuser').first())
		result = self.app.test_cli_runner().invoke(args=['user', 'delete', 'doesnotexist'])
		self.assertEqual(result.exit_code, 1)

class TestGroupModel(UffdTestCase):
	def test_unix_gid_generation(self):
		self.app.config['GROUP_MIN_GID'] = 20000
		self.app.config['GROUP_MAX_GID'] = 49999
		Group.query.delete()
		db.session.commit()
		group0 = Group(name='group0', description='group0')
		group1 = Group(name='group1', description='group1')
		group2 = Group(name='group2', description='group2')
		db.session.add_all([group0, group1, group2])
		db.session.commit()
		self.assertEqual(group0.unix_gid, 20000)
		self.assertEqual(group1.unix_gid, 20001)
		self.assertEqual(group2.unix_gid, 20002)
		db.session.delete(group1)
		db.session.commit()
		group3 = Group(name='group3', description='group3')
		db.session.add(group3)
		db.session.commit()
		self.assertEqual(group3.unix_gid, 20003)

	def test_unix_gid_generation(self):
		self.app.config['GROUP_MIN_GID'] = 20000
		self.app.config['GROUP_MAX_GID'] = 20001
		Group.query.delete()
		db.session.commit()
		group0 = Group(name='group0', description='group0')
		group1 = Group(name='group1', description='group1')
		db.session.add_all([group0, group1])
		db.session.commit()
		self.assertEqual(group0.unix_gid, 20000)
		self.assertEqual(group1.unix_gid, 20001)
		db.session.commit()
		with self.assertRaises(sqlalchemy.exc.IntegrityError):
			group2 = Group(name='group2', description='group2')
			db.session.add(group2)
			db.session.commit()

class TestGroupViews(UffdTestCase):
	def setUp(self):
		super().setUp()
		self.login_as('admin')

	def test_index(self):
		r = self.client.get(path=url_for('group.index'), follow_redirects=True)
		dump('group_index', r)
		self.assertEqual(r.status_code, 200)

	def test_show(self):
		r = self.client.get(path=url_for('group.show', gid=20001), follow_redirects=True)
		dump('group_show', r)
		self.assertEqual(r.status_code, 200)

	def test_new(self):
		r = self.client.get(path=url_for('group.show'), follow_redirects=True)
		dump('group_new', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(Group.query.filter_by(name='newgroup').one_or_none())
		r = self.client.post(path=url_for('group.update'),
			data={'unix_gid': '', 'name': 'newgroup', 'description': 'Test description'},
			follow_redirects=True)
		dump('group_new_submit', r)
		self.assertEqual(r.status_code, 200)
		group = Group.query.filter_by(name='newgroup').one_or_none()
		self.assertIsNotNone(group)
		self.assertEqual(group.name, 'newgroup')
		self.assertEqual(group.description, 'Test description')
		self.assertGreaterEqual(group.unix_gid, self.app.config['GROUP_MIN_GID'])
		self.assertLessEqual(group.unix_gid, self.app.config['GROUP_MAX_GID'])

	def test_new_fixed_gid(self):
		gid = self.app.config['GROUP_MAX_GID'] - 1
		r = self.client.post(path=url_for('group.update'),
			data={'unix_gid': str(gid), 'name': 'newgroup', 'description': 'Test description'},
			follow_redirects=True)
		dump('group_new_fixed_gid', r)
		self.assertEqual(r.status_code, 200)
		group = Group.query.filter_by(name='newgroup').one_or_none()
		self.assertIsNotNone(group)
		self.assertEqual(group.name, 'newgroup')
		self.assertEqual(group.description, 'Test description')
		self.assertEqual(group.unix_gid, gid)

	def test_new_existing_name(self):
		gid = self.app.config['GROUP_MAX_GID'] - 1
		db.session.add(Group(name='newgroup', description='Original description', unix_gid=gid))
		db.session.commit()
		r = self.client.post(path=url_for('group.update'),
			data={'unix_gid': '', 'name': 'newgroup', 'description': 'New description'},
			follow_redirects=True)
		dump('group_new_existing_name', r)
		self.assertEqual(r.status_code, 400)
		group = Group.query.filter_by(name='newgroup').one_or_none()
		self.assertIsNotNone(group)
		self.assertEqual(group.name, 'newgroup')
		self.assertEqual(group.description, 'Original description')
		self.assertEqual(group.unix_gid, gid)

	def test_new_name_too_long(self):
		r = self.client.post(path=url_for('group.update'),
			data={'unix_gid': '', 'name': 'a'*33, 'description': 'New description'},
			follow_redirects=True)
		dump('group_new_name_too_long', r)
		self.assertEqual(r.status_code, 400)
		group = Group.query.filter_by(name='a'*33).one_or_none()
		self.assertIsNone(group)

	def test_new_name_too_short(self):
		r = self.client.post(path=url_for('group.update'),
			data={'unix_gid': '', 'name': '', 'description': 'New description'},
			follow_redirects=True)
		dump('group_new_name_too_short', r)
		self.assertEqual(r.status_code, 400)
		group = Group.query.filter_by(name='').one_or_none()
		self.assertIsNone(group)

	def test_new_name_invalid(self):
		r = self.client.post(path=url_for('group.update'),
			data={'unix_gid': '', 'name': 'foo bar', 'description': 'New description'},
			follow_redirects=True)
		dump('group_new_name_invalid', r)
		self.assertEqual(r.status_code, 400)
		group = Group.query.filter_by(name='foo bar').one_or_none()
		self.assertIsNone(group)

	def test_new_existing_gid(self):
		gid = self.app.config['GROUP_MAX_GID'] - 1
		db.session.add(Group(name='newgroup', description='Original description', unix_gid=gid))
		db.session.commit()
		r = self.client.post(path=url_for('group.update'),
			data={'unix_gid': str(gid), 'name': 'newgroup2', 'description': 'New description'},
			follow_redirects=True)
		dump('group_new_existing_gid', r)
		self.assertEqual(r.status_code, 400)
		group = Group.query.filter_by(name='newgroup').one_or_none()
		self.assertIsNotNone(group)
		self.assertEqual(group.name, 'newgroup')
		self.assertEqual(group.description, 'Original description')
		self.assertEqual(group.unix_gid, gid)
		self.assertIsNone(Group.query.filter_by(name='newgroup2').one_or_none())

	def test_update(self):
		group = Group(name='newgroup', description='Original description')
		db.session.add(group)
		db.session.commit()
		group_id = group.id
		group_gid = group.unix_gid
		new_gid = self.app.config['GROUP_MAX_GID'] - 1
		r = self.client.post(path=url_for('group.update', id=group_id),
			data={'unix_gid': str(new_gid), 'name': 'newgroup_changed', 'description': 'New description'},
			follow_redirects=True)
		dump('group_update', r)
		self.assertEqual(r.status_code, 200)
		group = Group.query.get(group_id)
		self.assertEqual(group.name, 'newgroup') # Not changed
		self.assertEqual(group.description, 'New description') # Changed
		self.assertEqual(group.unix_gid, group_gid) # Not changed

	def test_delete(self):
		group1 = Group(name='newgroup1', description='Original description1')
		group2 = Group(name='newgroup2', description='Original description2')
		db.session.add(group1)
		db.session.add(group2)
		db.session.commit()
		group1_id = group1.id
		group2_id = group2.id
		r = self.client.get(path=url_for('group.delete', id=group1_id), follow_redirects=True)
		dump('group_delete', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(Group.query.get(group1_id))
		self.assertIsNotNone(Group.query.get(group2_id))

class TestGroupCLI(UffdTestCase):
	def setUp(self):
		super().setUp()
		self.client.__exit__(None, None, None)

	def test_list(self):
		result = self.app.test_cli_runner().invoke(args=['group', 'list'])
		self.assertEqual(result.exit_code, 0)

	def test_show(self):
		result = self.app.test_cli_runner().invoke(args=['group', 'show', 'users'])
		self.assertEqual(result.exit_code, 0)
		result = self.app.test_cli_runner().invoke(args=['group', 'show', 'doesnotexist'])
		self.assertEqual(result.exit_code, 1)

	def test_create(self):
		result = self.app.test_cli_runner().invoke(args=['group', 'create', 'users']) # Duplicate name
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['group', 'create', 'new group'])
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['group', 'create', 'newgroup', '--description', 'A new group'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			group = Group.query.filter_by(name='newgroup').first()
			self.assertIsNotNone(group)
			self.assertEqual(group.description, 'A new group')

	def test_update(self):
		result = self.app.test_cli_runner().invoke(args=['group', 'update', 'doesnotexist', '--description', 'foo'])
		self.assertEqual(result.exit_code, 1)
		result = self.app.test_cli_runner().invoke(args=['group', 'update', 'users', '--description', 'New description'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			group = Group.query.filter_by(name='users').first()
			self.assertEqual(group.description, 'New description')

	def test_update_without_description(self):
		result = self.app.test_cli_runner().invoke(args=['group', 'update', 'users']) # Should not change anything
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			group = Group.query.filter_by(name='users').first()
			self.assertEqual(group.description, 'Base group for all users')

	def test_delete(self):
		with self.app.test_request_context():
			self.assertIsNotNone(Group.query.filter_by(name='users').first())
		result = self.app.test_cli_runner().invoke(args=['group', 'delete', 'users'])
		self.assertEqual(result.exit_code, 0)
		with self.app.test_request_context():
			self.assertIsNone(Group.query.filter_by(name='users').first())
		result = self.app.test_cli_runner().invoke(args=['group', 'delete', 'doesnotexist'])
		self.assertEqual(result.exit_code, 1)

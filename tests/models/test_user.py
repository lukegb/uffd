import datetime

import sqlalchemy

from uffd.database import db
from uffd.models import User, UserEmail, Group

from tests.utils import UffdTestCase

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
		user0 = User(loginname='user0', displayname='user0', primary_email_address='user0@example.com')
		user1 = User(loginname='user1', displayname='user1', primary_email_address='user1@example.com')
		user2 = User(loginname='user2', displayname='user2', primary_email_address='user2@example.com')
		db.session.add_all([user0, user1, user2])
		db.session.commit()
		self.assertEqual(user0.unix_uid, 10000)
		self.assertEqual(user1.unix_uid, 10001)
		self.assertEqual(user2.unix_uid, 10002)
		db.session.delete(user1)
		db.session.commit()
		user3 = User(loginname='user3', displayname='user3', primary_email_address='user3@example.com')
		db.session.add(user3)
		db.session.commit()
		self.assertEqual(user3.unix_uid, 10003)
		service0 = User(loginname='service0', displayname='service0', primary_email_address='service0@example.com', is_service_user=True)
		service1 = User(loginname='service1', displayname='service1', primary_email_address='service1@example.com', is_service_user=True)
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
		user0 = User(loginname='user0', displayname='user0', primary_email_address='user0@example.com')
		service0 = User(loginname='service0', displayname='service0', primary_email_address='service0@example.com', is_service_user=True)
		user1 = User(loginname='user1', displayname='user1', primary_email_address='user1@example.com')
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
		user0 = User(loginname='user0', displayname='user0', primary_email_address='user0@example.com')
		user1 = User(loginname='user1', displayname='user1', primary_email_address='user1@example.com')
		db.session.add_all([user0, user1])
		db.session.commit()
		self.assertEqual(user0.unix_uid, 10000)
		self.assertEqual(user1.unix_uid, 10001)
		with self.assertRaises(sqlalchemy.exc.IntegrityError):
			user2 = User(loginname='user2', displayname='user2', primary_email_address='user2@example.com')
			db.session.add(user2)
			db.session.commit()

	def test_init_primary_email_address(self):
		user = User(primary_email_address='foobar@example.com')
		self.assertEqual(user.primary_email.address, 'foobar@example.com')
		self.assertEqual(user.primary_email.verified, True)
		self.assertEqual(user.primary_email.user, user)
		user = User(primary_email_address='invalid')
		self.assertEqual(user.primary_email.address, 'invalid')
		self.assertEqual(user.primary_email.verified, True)
		self.assertEqual(user.primary_email.user, user)

	def test_set_primary_email_address(self):
		user = User()
		self.assertFalse(user.set_primary_email_address('invalid'))
		self.assertIsNone(user.primary_email)
		self.assertEqual(len(user.all_emails), 0)
		self.assertTrue(user.set_primary_email_address('foobar@example.com'))
		self.assertEqual(user.primary_email.address, 'foobar@example.com')
		self.assertEqual(len(user.all_emails), 1)
		self.assertFalse(user.set_primary_email_address('invalid'))
		self.assertEqual(user.primary_email.address, 'foobar@example.com')
		self.assertEqual(len(user.all_emails), 1)
		self.assertTrue(user.set_primary_email_address('other@example.com'))
		self.assertEqual(user.primary_email.address, 'other@example.com')
		self.assertEqual(len(user.all_emails), 2)
		self.assertEqual({user.all_emails[0].address, user.all_emails[1].address}, {'foobar@example.com', 'other@example.com'})

class TestUserEmailModel(UffdTestCase):
	def test_set_address(self):
		email = UserEmail()
		self.assertFalse(email.set_address('invalid'))
		self.assertIsNone(email.address)
		self.assertFalse(email.set_address(''))
		self.assertFalse(email.set_address('@'))
		self.app.config['REMAILER_DOMAIN'] = 'remailer.example.com'
		self.assertFalse(email.set_address('foobar@remailer.example.com'))
		self.assertFalse(email.set_address('v1-1-testuser@remailer.example.com'))
		self.assertFalse(email.set_address('v1-1-testuser @ remailer.example.com'))
		self.assertFalse(email.set_address('v1-1-testuser@REMAILER.example.com'))
		self.assertFalse(email.set_address('v1-1-testuser@foobar@remailer.example.com'))
		self.assertTrue(email.set_address('foobar@example.com'))
		self.assertEqual(email.address, 'foobar@example.com')

	def test_verification(self):
		email = UserEmail(address='foo@example.com')
		self.assertFalse(email.finish_verification('test'))
		secret = email.start_verification()
		self.assertTrue(email.verification_secret)
		self.assertTrue(email.verification_secret.verify(secret))
		self.assertFalse(email.verification_expired)
		self.assertFalse(email.finish_verification('test'))
		orig_expires = email.verification_expires
		email.verification_expires = datetime.datetime.utcnow() - datetime.timedelta(days=1)
		self.assertFalse(email.finish_verification(secret))
		email.verification_expires = orig_expires
		self.assertTrue(email.finish_verification(secret))
		self.assertFalse(email.verification_secret)
		self.assertTrue(email.verification_expired)

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

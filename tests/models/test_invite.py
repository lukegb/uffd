import datetime

from flask import current_app

from uffd.database import db
from uffd.models import Invite, InviteGrant, InviteSignup, User, Role, RoleGroup

from tests.utils import UffdTestCase, db_flush

class TestInviteModel(UffdTestCase):
	def test_expire(self):
		invite = Invite(valid_until=datetime.datetime.utcnow() + datetime.timedelta(seconds=60), creator=self.get_admin())
		self.assertFalse(invite.expired)
		self.assertTrue(invite.active)
		invite.valid_until = datetime.datetime.utcnow() - datetime.timedelta(seconds=60)
		self.assertTrue(invite.expired)
		self.assertFalse(invite.active)

	def test_void(self):
		invite = Invite(valid_until=datetime.datetime.utcnow() + datetime.timedelta(seconds=60), single_use=False, creator=self.get_admin())
		self.assertFalse(invite.voided)
		self.assertTrue(invite.active)
		invite.used = True
		self.assertFalse(invite.voided)
		self.assertTrue(invite.active)
		invite = Invite(valid_until=datetime.datetime.utcnow() + datetime.timedelta(seconds=60), single_use=True, creator=self.get_admin())
		self.assertFalse(invite.voided)
		self.assertTrue(invite.active)
		invite.used = True
		self.assertTrue(invite.voided)
		self.assertFalse(invite.active)

	def test_permitted(self):
		role = Role(name='testrole')
		invite = Invite(valid_until=datetime.datetime.utcnow() + datetime.timedelta(seconds=60), allow_signup=True, roles=[role])
		self.assertFalse(invite.permitted)
		self.assertFalse(invite.active)
		invite.creator = self.get_admin()
		self.assertTrue(invite.permitted)
		self.assertTrue(invite.active)
		invite.creator.is_deactivated = True
		self.assertFalse(invite.permitted)
		self.assertFalse(invite.active)
		invite.creator = self.get_user()
		self.assertFalse(invite.permitted)
		self.assertFalse(invite.active)
		role.moderator_group = self.get_access_group()
		current_app.config['ACL_SIGNUP_GROUP'] = 'uffd_access'
		self.assertTrue(invite.permitted)
		self.assertTrue(invite.active)
		role.moderator_group = None
		self.assertFalse(invite.permitted)
		self.assertFalse(invite.active)
		role.moderator_group = self.get_access_group()
		current_app.config['ACL_SIGNUP_GROUP'] = 'uffd_admin'
		self.assertFalse(invite.permitted)
		self.assertFalse(invite.active)

	def test_disable(self):
		invite = Invite(valid_until=datetime.datetime.utcnow() + datetime.timedelta(seconds=60), creator=self.get_admin())
		self.assertTrue(invite.active)
		invite.disable()
		self.assertFalse(invite.active)

	def test_reset_disabled(self):
		invite = Invite(valid_until=datetime.datetime.utcnow() + datetime.timedelta(seconds=60), creator=self.get_admin())
		invite.disable()
		self.assertFalse(invite.active)
		invite.reset()
		self.assertTrue(invite.active)

	def test_reset_expired(self):
		invite = Invite(valid_until=datetime.datetime.utcnow() - datetime.timedelta(seconds=60), creator=self.get_admin())
		self.assertFalse(invite.active)
		invite.reset()
		self.assertFalse(invite.active)

	def test_reset_single_use(self):
		invite = Invite(valid_until=datetime.datetime.utcnow() + datetime.timedelta(seconds=60), single_use=False, creator=self.get_admin())
		invite.used = True
		invite.disable()
		self.assertFalse(invite.active)
		invite.reset()
		self.assertTrue(invite.active)

	def test_short_token(self):
		invite = Invite(valid_until=datetime.datetime.utcnow() + datetime.timedelta(seconds=60), creator=self.get_admin())
		db.session.add(invite)
		db.session.commit()
		self.assertTrue(len(invite.short_token) <= len(invite.token)/3)

class TestInviteGrantModel(UffdTestCase):
	def test_success(self):
		user = self.get_user()
		group0 = self.get_access_group()
		role0 = Role(name='baserole', groups={group0: RoleGroup(group=group0)})
		db.session.add(role0)
		user.roles.append(role0)
		user.update_groups()
		group1 = self.get_admin_group()
		role1 = Role(name='testrole1', groups={group1: RoleGroup(group=group1)})
		db.session.add(role1)
		role2 = Role(name='testrole2')
		db.session.add(role2)
		invite = Invite(valid_until=datetime.datetime.utcnow() + datetime.timedelta(seconds=60), roles=[role1, role2], creator=self.get_admin())
		self.assertIn(role0, user.roles)
		self.assertNotIn(role1, user.roles)
		self.assertNotIn(role2, user.roles)
		self.assertIn(group0, user.groups)
		self.assertNotIn(group1, user.groups)
		self.assertFalse(invite.used)
		grant = InviteGrant(invite=invite, user=user)
		success, msg = grant.apply()
		self.assertTrue(success)
		self.assertIn(role0, user.roles)
		self.assertIn(role1, user.roles)
		self.assertIn(role2, user.roles)
		self.assertIn(group0, user.groups)
		self.assertIn(group1, user.groups)
		self.assertTrue(invite.used)
		db.session.commit()
		db_flush()
		user = self.get_user()
		self.assertIn('baserole', [role.name for role in user.roles_effective])
		self.assertIn('testrole1', [role.name for role in user.roles])
		self.assertIn('testrole2', [role.name for role in user.roles])
		self.assertIn(self.get_access_group(), user.groups)
		self.assertIn(self.get_admin_group(), user.groups)

	def test_inactive(self):
		user = self.get_user()
		group = self.get_admin_group()
		role = Role(name='testrole1', groups={group: RoleGroup(group=group)})
		db.session.add(role)
		invite = Invite(valid_until=datetime.datetime.utcnow() + datetime.timedelta(seconds=60), roles=[role], single_use=True, used=True, creator=self.get_admin())
		self.assertFalse(invite.active)
		grant = InviteGrant(invite=invite, user=user)
		success, msg = grant.apply()
		self.assertFalse(success)
		self.assertIsInstance(msg, str)
		self.assertNotIn(role, user.roles)
		self.assertNotIn(group, user.groups)

	def test_no_roles(self):
		user = self.get_user()
		invite = Invite(valid_until=datetime.datetime.utcnow() + datetime.timedelta(seconds=60), creator=self.get_admin())
		self.assertTrue(invite.active)
		grant = InviteGrant(invite=invite, user=user)
		success, msg = grant.apply()
		self.assertFalse(success)
		self.assertIsInstance(msg, str)

	def test_no_new_roles(self):
		user = self.get_user()
		role = Role(name='testrole1')
		db.session.add(role)
		user.roles.append(role)
		invite = Invite(valid_until=datetime.datetime.utcnow() + datetime.timedelta(seconds=60), roles=[role], creator=self.get_admin())
		self.assertTrue(invite.active)
		grant = InviteGrant(invite=invite, user=user)
		success, msg = grant.apply()
		self.assertFalse(success)
		self.assertIsInstance(msg, str)

class TestInviteSignupModel(UffdTestCase):
	def create_base_roles(self):
		baserole = Role(name='base', is_default=True)
		baserole.groups[self.get_access_group()] = RoleGroup()
		baserole.groups[self.get_users_group()] = RoleGroup()
		db.session.add(baserole)
		db.session.commit()

	def test_success(self):
		self.create_base_roles()
		base_role = Role.query.filter_by(name='base').one()
		base_group1 = self.get_access_group()
		base_group2 = self.get_users_group()
		group = self.get_admin_group()
		role1 = Role(name='testrole1', groups={group: RoleGroup(group=group)})
		db.session.add(role1)
		role2 = Role(name='testrole2')
		db.session.add(role2)
		invite = Invite(valid_until=datetime.datetime.utcnow() + datetime.timedelta(seconds=60), roles=[role1, role2], allow_signup=True, creator=self.get_admin())
		signup = InviteSignup(invite=invite, loginname='newuser', displayname='New User', mail='test@example.com', password='notsecret')
		self.assertFalse(invite.used)
		valid, msg = signup.validate()
		self.assertTrue(valid)
		self.assertFalse(invite.used)
		user, msg = signup.finish('notsecret')
		self.assertIsInstance(user, User)
		self.assertTrue(invite.used)
		self.assertEqual(user.loginname, 'newuser')
		self.assertEqual(user.displayname, 'New User')
		self.assertEqual(user.primary_email.address, 'test@example.com')
		self.assertEqual(signup.user, user)
		self.assertIn(base_role, user.roles_effective)
		self.assertIn(role1, user.roles)
		self.assertIn(role2, user.roles)
		self.assertIn(base_group1, user.groups)
		self.assertIn(base_group2, user.groups)
		self.assertIn(group, user.groups)
		db.session.commit()
		db_flush()
		self.assertEqual(len(User.query.filter_by(loginname='newuser').all()), 1)

	def test_success_no_roles(self):
		self.create_base_roles()
		base_role = Role.query.filter_by(name='base').one()
		base_group1 = self.get_access_group()
		base_group2 = self.get_users_group()
		invite = Invite(valid_until=datetime.datetime.utcnow() + datetime.timedelta(seconds=60), allow_signup=True, creator=self.get_admin())
		signup = InviteSignup(invite=invite, loginname='newuser', displayname='New User', mail='test@example.com', password='notsecret')
		self.assertFalse(invite.used)
		valid, msg = signup.validate()
		self.assertTrue(valid)
		self.assertFalse(invite.used)
		user, msg = signup.finish('notsecret')
		self.assertIsInstance(user, User)
		self.assertTrue(invite.used)
		self.assertEqual(user.loginname, 'newuser')
		self.assertEqual(user.displayname, 'New User')
		self.assertEqual(user.primary_email.address, 'test@example.com')
		self.assertEqual(signup.user, user)
		self.assertIn(base_role, user.roles_effective)
		self.assertEqual(len(user.roles_effective), 1)
		self.assertIn(base_group1, user.groups)
		self.assertIn(base_group2, user.groups)
		self.assertEqual(len(user.groups), 2)
		db.session.commit()
		db_flush()
		self.assertEqual(len(User.query.filter_by(loginname='newuser').all()), 1)

	def test_inactive(self):
		invite = Invite(valid_until=datetime.datetime.utcnow() + datetime.timedelta(seconds=60), allow_signup=True, single_use=True, used=True, creator=self.get_admin())
		self.assertFalse(invite.active)
		signup = InviteSignup(invite=invite, loginname='newuser', displayname='New User', mail='test@example.com', password='notsecret')
		valid, msg = signup.validate()
		self.assertFalse(valid)
		self.assertIsInstance(msg, str)
		user, msg = signup.finish('notsecret')
		self.assertIsNone(user)
		self.assertIsInstance(msg, str)

	def test_invalid(self):
		invite = Invite(valid_until=datetime.datetime.utcnow() + datetime.timedelta(seconds=60), allow_signup=True, creator=self.get_admin())
		self.assertTrue(invite.active)
		signup = InviteSignup(invite=invite, loginname='', displayname='New User', mail='test@example.com', password='notsecret')
		valid, msg = signup.validate()
		self.assertFalse(valid)
		self.assertIsInstance(msg, str)

	def test_invalid2(self):
		invite = Invite(valid_until=datetime.datetime.utcnow() + datetime.timedelta(seconds=60), allow_signup=True, creator=self.get_admin())
		self.assertTrue(invite.active)
		signup = InviteSignup(invite=invite, loginname='newuser', displayname='New User', mail='test@example.com', password='notsecret')
		user, msg = signup.finish('wrongpassword')
		self.assertIsNone(user)
		self.assertIsInstance(msg, str)

	def test_no_signup(self):
		invite = Invite(valid_until=datetime.datetime.utcnow() + datetime.timedelta(seconds=60), allow_signup=False, creator=self.get_admin())
		self.assertTrue(invite.active)
		signup = InviteSignup(invite=invite, loginname='newuser', displayname='New User', mail='test@example.com', password='notsecret')
		valid, msg = signup.validate()
		self.assertFalse(valid)
		self.assertIsInstance(msg, str)
		user, msg = signup.finish('notsecret')
		self.assertIsNone(user)
		self.assertIsInstance(msg, str)

import unittest
import datetime
import time

from flask import url_for, session, current_app

# These imports are required, because otherwise we get circular imports?!
from uffd import user
from uffd.ldap import ldap

from uffd import create_app, db
from uffd.invite.models import Invite, InviteGrant, InviteSignup
from uffd.user.models import User, Group
from uffd.role.models import Role
from uffd.session.views import login_get_user

from utils import dump, UffdTestCase, db_flush

class TestInviteModel(UffdTestCase):
	def test_expire(self):
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60))
		self.assertFalse(invite.expired)
		self.assertTrue(invite.active)
		invite.valid_until = datetime.datetime.now() - datetime.timedelta(seconds=60)
		self.assertTrue(invite.expired)
		self.assertFalse(invite.active)

	def test_void(self):
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), single_use=False)
		self.assertFalse(invite.voided)
		self.assertTrue(invite.active)
		invite.used = True
		self.assertFalse(invite.voided)
		self.assertTrue(invite.active)
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), single_use=True)
		self.assertFalse(invite.voided)
		self.assertTrue(invite.active)
		invite.used = True
		self.assertTrue(invite.voided)
		self.assertFalse(invite.active)

	def test_permitted(self):
		role = Role(name='testrole')
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), allow_signup=True, roles=[role])
		self.assertTrue(invite.permitted)
		self.assertTrue(invite.active)
		invite.creator_dn = 'uid=doesnotexist,ou=users,dc=example,dc=com'
		self.assertFalse(invite.permitted)
		self.assertFalse(invite.active)
		invite.creator_dn = 'uid=testadmin,ou=users,dc=example,dc=com'
		self.assertTrue(invite.permitted)
		self.assertTrue(invite.active)
		invite.creator_dn = 'uid=testuser,ou=users,dc=example,dc=com'
		self.assertFalse(invite.permitted)
		self.assertFalse(invite.active)
		role.moderator_group_dn = 'cn=uffd_access,ou=groups,dc=example,dc=com'
		current_app.config['ACL_SIGNUP_GROUP'] = 'uffd_access'
		self.assertTrue(invite.permitted)
		self.assertTrue(invite.active)
		role.moderator_group_dn = None
		self.assertFalse(invite.permitted)
		self.assertFalse(invite.active)
		role.moderator_group_dn = 'cn=uffd_access,ou=groups,dc=example,dc=com'
		current_app.config['ACL_SIGNUP_GROUP'] = 'uffd_admin'
		self.assertFalse(invite.permitted)
		self.assertFalse(invite.active)

	def test_disable(self):
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60))
		self.assertTrue(invite.active)
		invite.disable()
		self.assertFalse(invite.active)

	def test_reset_disabled(self):
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60))
		invite.disable()
		self.assertFalse(invite.active)
		invite.reset()
		self.assertTrue(invite.active)

	def test_reset_expired(self):
		invite = Invite(valid_until=datetime.datetime.now() - datetime.timedelta(seconds=60))
		self.assertFalse(invite.active)
		invite.reset()
		self.assertFalse(invite.active)

	def test_reset_single_use(self):
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), single_use=False)
		invite.used = True
		invite.disable()
		self.assertFalse(invite.active)
		invite.reset()
		self.assertTrue(invite.active)

	def test_short_token(self):
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60))
		db.session.add(invite)
		db.session.commit()
		self.assertTrue(len(invite.short_token) <= len(invite.token)/3)

class TestInviteGrantModel(UffdTestCase):
	def test_success(self):
		user = User.query.get('uid=testuser,ou=users,dc=example,dc=com')
		group0 = Group.query.get('cn=uffd_access,ou=groups,dc=example,dc=com')
		role0 = Role(name='baserole', groups=[group0])
		db.session.add(role0)
		user.roles.add(role0)
		user.update_groups()
		group1 = Group.query.get('cn=uffd_admin,ou=groups,dc=example,dc=com')
		role1 = Role(name='testrole1', groups=[group1])
		db.session.add(role1)
		role2 = Role(name='testrole2')
		db.session.add(role2)
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), roles=[role1, role2])
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
		ldap.session.commit()
		db_flush()
		user = User.query.get('uid=testuser,ou=users,dc=example,dc=com')
		self.assertIn('baserole', [role.name for role in user.roles_effective])
		self.assertIn('testrole1', [role.name for role in user.roles])
		self.assertIn('testrole2', [role.name for role in user.roles])
		self.assertIn('cn=uffd_access,ou=groups,dc=example,dc=com', [group.dn for group in user.groups])
		self.assertIn('cn=uffd_admin,ou=groups,dc=example,dc=com', [group.dn for group in user.groups])

	def test_inactive(self):
		user = User.query.get('uid=testuser,ou=users,dc=example,dc=com')
		group = Group.query.get('cn=uffd_admin,ou=groups,dc=example,dc=com')
		role = Role(name='testrole1', groups=[group])
		db.session.add(role)
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), roles=[role], single_use=True, used=True)
		self.assertFalse(invite.active)
		grant = InviteGrant(invite=invite, user=user)
		success, msg = grant.apply()
		self.assertFalse(success)
		self.assertIsInstance(msg, str)
		self.assertNotIn(role, user.roles)
		self.assertNotIn(group, user.groups)

	def test_no_roles(self):
		user = User.query.get('uid=testuser,ou=users,dc=example,dc=com')
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60))
		self.assertTrue(invite.active)
		grant = InviteGrant(invite=invite, user=user)
		success, msg = grant.apply()
		self.assertFalse(success)
		self.assertIsInstance(msg, str)

	def test_no_new_roles(self):
		user = User.query.get('uid=testuser,ou=users,dc=example,dc=com')
		role = Role(name='testrole1')
		db.session.add(role)
		user.roles.add(role)
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), roles=[role])
		self.assertTrue(invite.active)
		grant = InviteGrant(invite=invite, user=user)
		success, msg = grant.apply()
		self.assertFalse(success)
		self.assertIsInstance(msg, str)

class TestInviteSignupModel(UffdTestCase):
	def create_base_roles(self):
		baserole = Role(name='base', is_default=True)
		baserole.groups.add(Group.query.get('cn=uffd_access,ou=groups,dc=example,dc=com'))
		baserole.groups.add(Group.query.get('cn=users,ou=groups,dc=example,dc=com'))
		db.session.add(baserole)
		db.session.commit()

	def test_success(self):
		self.create_base_roles()
		base_role = Role.query.filter_by(name='base').one()
		base_group1 = Group.query.get('cn=uffd_access,ou=groups,dc=example,dc=com')
		base_group2 = Group.query.get('cn=users,ou=groups,dc=example,dc=com')
		group = Group.query.get('cn=uffd_admin,ou=groups,dc=example,dc=com')
		role1 = Role(name='testrole1', groups=[group])
		db.session.add(role1)
		role2 = Role(name='testrole2')
		db.session.add(role2)
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), roles=[role1, role2], allow_signup=True)
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
		self.assertEqual(user.mail, 'test@example.com')
		self.assertEqual(signup.user.dn, user.dn)
		self.assertIn(base_role, user.roles_effective)
		self.assertIn(role1, user.roles)
		self.assertIn(role2, user.roles)
		self.assertIn(base_group1, user.groups)
		self.assertIn(base_group2, user.groups)
		self.assertIn(group, user.groups)
		db.session.commit()
		ldap.session.commit()
		db_flush()
		self.assertEqual(len(User.query.filter_by(loginname='newuser').all()), 1)

	def test_success_no_roles(self):
		self.create_base_roles()
		base_role = Role.query.filter_by(name='base').one()
		base_group1 = Group.query.get('cn=uffd_access,ou=groups,dc=example,dc=com')
		base_group2 = Group.query.get('cn=users,ou=groups,dc=example,dc=com')
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), allow_signup=True)
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
		self.assertEqual(user.mail, 'test@example.com')
		self.assertEqual(signup.user.dn, user.dn)
		self.assertIn(base_role, user.roles_effective)
		self.assertEqual(len(user.roles_effective), 1)
		self.assertIn(base_group1, user.groups)
		self.assertIn(base_group2, user.groups)
		self.assertEqual(len(user.groups), 2)
		db.session.commit()
		ldap.session.commit()
		db_flush()
		self.assertEqual(len(User.query.filter_by(loginname='newuser').all()), 1)

	def test_inactive(self):
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), allow_signup=True, single_use=True, used=True)
		self.assertFalse(invite.active)
		signup = InviteSignup(invite=invite, loginname='newuser', displayname='New User', mail='test@example.com', password='notsecret')
		valid, msg = signup.validate()
		self.assertFalse(valid)
		self.assertIsInstance(msg, str)
		user, msg = signup.finish('notsecret')
		self.assertIsNone(user)
		self.assertIsInstance(msg, str)

	def test_invalid(self):
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), allow_signup=True)
		self.assertTrue(invite.active)
		signup = InviteSignup(invite=invite, loginname='', displayname='New User', mail='test@example.com', password='notsecret')
		valid, msg = signup.validate()
		self.assertFalse(valid)
		self.assertIsInstance(msg, str)

	def test_invalid2(self):
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), allow_signup=True)
		self.assertTrue(invite.active)
		signup = InviteSignup(invite=invite, loginname='newuser', displayname='New User', mail='test@example.com', password='notsecret')
		user, msg = signup.finish('wrongpassword')
		self.assertIsNone(user)
		self.assertIsInstance(msg, str)

	def test_no_signup(self):
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), allow_signup=False)
		self.assertTrue(invite.active)
		signup = InviteSignup(invite=invite, loginname='newuser', displayname='New User', mail='test@example.com', password='notsecret')
		valid, msg = signup.validate()
		self.assertFalse(valid)
		self.assertIsInstance(msg, str)
		user, msg = signup.finish('notsecret')
		self.assertIsNone(user)
		self.assertIsInstance(msg, str)

class TestInviteAdminViews(UffdTestCase):
	def setUpApp(self):
		self.app.config['SELF_SIGNUP'] = False
		self.app.last_mail = None

	def login_admin(self):
		self.client.post(path=url_for('session.login'),
			data={'loginname': 'testadmin', 'password': 'adminpassword'}, follow_redirects=True)

	def login_user(self):
		self.client.post(path=url_for('session.login'),
			data={'loginname': 'testuser', 'password': 'userpassword'}, follow_redirects=True)

	def test_index(self):
		valid_until = datetime.datetime.now() + datetime.timedelta(seconds=60)
		valid_until_expired = datetime.datetime.now() - datetime.timedelta(seconds=60)
		user1 = User.query.get('uid=testuser,ou=users,dc=example,dc=com')
		user2 = User.query.get('uid=testadmin,ou=users,dc=example,dc=com')
		role1 = Role(name='testrole1')
		db.session.add(role1)
		role2 = Role(name='testrole2')
		db.session.add(role2)
		# All possible states
		db.session.add(Invite(valid_until=valid_until, single_use=False))
		db.session.add(Invite(valid_until=valid_until, single_use=True, used=False))
		db.session.add(Invite(valid_until=valid_until, single_use=True, used=True, signups=[InviteSignup(user=user1)]))
		db.session.add(Invite(valid_until=valid_until_expired))
		db.session.add(Invite(valid_until=valid_until, disabled=True))
		# Different permissions
		db.session.add(Invite(valid_until=valid_until, allow_signup=True))
		db.session.add(Invite(valid_until=valid_until, allow_signup=False))
		db.session.add(Invite(valid_until=valid_until, allow_signup=True, roles=[role1], grants=[InviteGrant(user=user2)]))
		db.session.add(Invite(valid_until=valid_until, allow_signup=False, roles=[role1, role2]))
		db.session.commit()
		self.login_admin()
		r = self.client.get(path=url_for('invite.index'), follow_redirects=True)
		dump('invite_index', r)
		self.assertEqual(r.status_code, 200)

	def test_index_empty(self):
		self.login_admin()
		r = self.client.get(path=url_for('invite.index'), follow_redirects=True)
		dump('invite_index_empty', r)
		self.assertEqual(r.status_code, 200)

	def test_index_nologin(self):
		r = self.client.get(path=url_for('invite.index'), follow_redirects=True)
		dump('invite_index_nologin', r)
		self.assertEqual(r.status_code, 200)

	def test_index_noaccess(self):
		self.login_user()
		r = self.client.get(path=url_for('invite.index'), follow_redirects=True)
		dump('invite_index_noaccess', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn('Access denied'.encode(), r.data)

	def test_index_signupperm(self):
		current_app.config['ACL_SIGNUP_GROUP'] = 'uffd_access'
		valid_until = datetime.datetime.now() + datetime.timedelta(seconds=60)
		invite1 = Invite(valid_until=valid_until, allow_signup=True, creator_dn='uid=testadmin,ou=users,dc=example,dc=com')
		db.session.add(invite1)
		invite2 = Invite(valid_until=valid_until, allow_signup=True, creator_dn='uid=testuser,ou=users,dc=example,dc=com')
		db.session.add(invite2)
		invite3 = Invite(valid_until=valid_until, allow_signup=True)
		db.session.add(invite3)
		db.session.commit()
		token1 = invite1.short_token
		token2 = invite2.short_token
		token3 = invite3.short_token
		self.login_user()
		r = self.client.get(path=url_for('invite.index'), follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertNotIn('Access denied'.encode(), r.data)
		self.assertNotIn(token1.encode(), r.data)
		self.assertIn(token2.encode(), r.data)
		self.assertNotIn(token3.encode(), r.data)

	def test_index_rolemod(self):
		role1 = Role(name='testrole1')
		db.session.add(role1)
		role2 = Role(name='testrole2', moderator_group_dn='cn=uffd_access,ou=groups,dc=example,dc=com')
		db.session.add(role2)
		valid_until = datetime.datetime.now() + datetime.timedelta(seconds=60)
		db.session.add(Invite(valid_until=valid_until, roles=[role1]))
		db.session.add(Invite(valid_until=valid_until, roles=[role2]))
		db.session.commit()
		self.login_user()
		r = self.client.get(path=url_for('invite.index'), follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertNotIn('Access denied'.encode(), r.data)
		self.assertNotIn('testrole1'.encode(), r.data)
		self.assertIn('testrole2'.encode(), r.data)

	def test_new(self):
		self.login_admin()
		role = Role(name='testrole1')
		db.session.add(role)
		db.session.commit()
		role_id = role.id
		r = self.client.get(path=url_for('invite.new'), follow_redirects=True)
		dump('invite_new', r)
		self.assertEqual(r.status_code, 200)
		valid_until = (datetime.datetime.now() + datetime.timedelta(seconds=60)).isoformat()
		self.assertListEqual(Invite.query.all(), [])
		r = self.client.post(path=url_for('invite.new_submit'),
			data={'single-use': '1', 'valid-until': valid_until,
			      'allow-signup': '1', 'role-%d'%role_id: '1'}, follow_redirects=True)
		dump('invite_new_submit', r)
		invite = Invite.query.one()
		role = Role.query.get(role_id)
		self.assertTrue(invite.active)
		self.assertTrue(invite.single_use)
		self.assertTrue(invite.allow_signup)
		self.assertListEqual(invite.roles, [role])

	def test_new_noperm(self):
		current_app.config['ACL_SIGNUP_GROUP'] = 'uffd_access'
		self.login_user()
		role = Role(name='testrole1')
		db.session.add(role)
		db.session.commit()
		role_id = role.id
		valid_until = (datetime.datetime.now() + datetime.timedelta(seconds=60)).isoformat()
		r = self.client.post(path=url_for('invite.new_submit'),
			data={'single-use': '1', 'valid-until': valid_until,
			      'allow-signup': '1', 'role-%d'%role_id: '1'}, follow_redirects=True)
		dump('invite_new_noperm', r)
		self.assertIsNone(Invite.query.first())

	def test_new_empty(self):
		current_app.config['ACL_SIGNUP_GROUP'] = 'uffd_access'
		self.login_user()
		valid_until = (datetime.datetime.now() + datetime.timedelta(seconds=60)).isoformat()
		r = self.client.post(path=url_for('invite.new_submit'),
			data={'single-use': '1', 'valid-until': valid_until,
			      'allow-signup': '0'}, follow_redirects=True)
		dump('invite_new_empty', r)
		self.assertIsNone(Invite.query.first())

	def test_disable(self):
		self.login_admin()
		valid_until = datetime.datetime.now() + datetime.timedelta(seconds=60)
		invite = Invite(valid_until=valid_until)
		db.session.add(invite)
		db.session.commit()
		id = invite.id
		self.assertTrue(Invite.query.get(id).active)
		r = self.client.post(path=url_for('invite.disable', invite_id=id), follow_redirects=True)
		dump('invite_disable', r)
		self.assertTrue(Invite.query.get(id).disabled)

	def test_disable_own(self):
		current_app.config['ACL_SIGNUP_GROUP'] = 'uffd_access'
		self.login_user()
		valid_until = datetime.datetime.now() + datetime.timedelta(seconds=60)
		invite = Invite(valid_until=valid_until, creator_dn='uid=testuser,ou=users,dc=example,dc=com')
		db.session.add(invite)
		db.session.commit()
		id = invite.id
		self.assertTrue(Invite.query.get(id).active)
		r = self.client.post(path=url_for('invite.disable', invite_id=id), follow_redirects=True)
		dump('invite_disable', r)
		self.assertTrue(Invite.query.get(id).disabled)

	def test_disable_rolemod(self):
		self.login_user()
		valid_until = datetime.datetime.now() + datetime.timedelta(seconds=60)
		role = Role(name='testrole', moderator_group_dn='cn=uffd_access,ou=groups,dc=example,dc=com')
		db.session.add(role)
		invite = Invite(valid_until=valid_until, creator_dn='uid=testadmin,ou=users,dc=example,dc=com', roles=[role])
		db.session.add(invite)
		db.session.commit()
		id = invite.id
		self.assertTrue(Invite.query.get(id).active)
		r = self.client.post(path=url_for('invite.disable', invite_id=id), follow_redirects=True)
		self.assertTrue(Invite.query.get(id).disabled)

	def test_disable_noperm(self):
		self.login_user()
		valid_until = datetime.datetime.now() + datetime.timedelta(seconds=60)
		db.session.add(Role(name='testrole1', moderator_group_dn='cn=uffd_access,ou=groups,dc=example,dc=com'))
		role = Role(name='testrole2', moderator_group_dn='cn=uffd_admin,ou=groups,dc=example,dc=com')
		db.session.add(role)
		invite = Invite(valid_until=valid_until, creator_dn='uid=testadmin,ou=users,dc=example,dc=com', roles=[role])
		db.session.add(invite)
		db.session.commit()
		id = invite.id
		r = self.client.post(path=url_for('invite.disable', invite_id=id), follow_redirects=True)
		self.assertFalse(Invite.query.get(id).disabled)
		self.assertTrue(Invite.query.get(id).active)

	def test_reset_disabled(self):
		self.login_admin()
		valid_until = datetime.datetime.now() + datetime.timedelta(seconds=60)
		invite = Invite(valid_until=valid_until, disabled=True)
		db.session.add(invite)
		db.session.commit()
		id = invite.id
		self.assertFalse(Invite.query.get(id).active)
		r = self.client.post(path=url_for('invite.reset', invite_id=id), follow_redirects=True)
		dump('invite_reset_disabled', r)
		self.assertTrue(Invite.query.get(id).active)

	def test_reset_voided(self):
		self.login_admin()
		valid_until = datetime.datetime.now() + datetime.timedelta(seconds=60)
		invite = Invite(valid_until=valid_until, single_use=True, used=True)
		db.session.add(invite)
		db.session.commit()
		id = invite.id
		self.assertFalse(Invite.query.get(id).active)
		r = self.client.post(path=url_for('invite.reset', invite_id=id), follow_redirects=True)
		dump('invite_reset_voided', r)
		self.assertTrue(Invite.query.get(id).active)

	def test_reset_own(self):
		current_app.config['ACL_SIGNUP_GROUP'] = 'uffd_access'
		self.login_user()
		valid_until = datetime.datetime.now() + datetime.timedelta(seconds=60)
		invite = Invite(valid_until=valid_until, disabled=True, creator_dn='uid=testuser,ou=users,dc=example,dc=com')
		db.session.add(invite)
		db.session.commit()
		id = invite.id
		self.assertFalse(Invite.query.get(id).active)
		r = self.client.post(path=url_for('invite.reset', invite_id=id), follow_redirects=True)
		dump('invite_reset_own', r)
		self.assertTrue(Invite.query.get(id).active)

	def test_reset_foreign(self):
		self.login_user()
		valid_until = datetime.datetime.now() + datetime.timedelta(seconds=60)
		role = Role(name='testrole', moderator_group_dn='cn=uffd_access,ou=groups,dc=example,dc=com')
		db.session.add(role)
		invite = Invite(valid_until=valid_until, disabled=True, creator_dn='uid=testadmin,ou=users,dc=example,dc=com', roles=[role])
		db.session.add(invite)
		db.session.commit()
		id = invite.id
		self.assertFalse(Invite.query.get(id).active)
		r = self.client.post(path=url_for('invite.reset', invite_id=id), follow_redirects=True)
		self.assertFalse(Invite.query.get(id).active)

class TestInviteUseViews(UffdTestCase):
	def setUpApp(self):
		self.app.config['SELF_SIGNUP'] = False
		self.app.last_mail = None

	def login_user(self):
		self.client.post(path=url_for('session.login'),
			data={'loginname': 'testuser', 'password': 'userpassword'}, follow_redirects=True)

	def test_use(self):
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), allow_signup=True, roles=[Role(name='testrole1'), Role(name='testrole2')])
		db.session.add(invite)
		db.session.commit()
		token = invite.token
		r = self.client.get(path=url_for('invite.use', token=token), follow_redirects=True)
		dump('invite_use', r)
		self.assertEqual(r.status_code, 200)

	def test_use_loggedin(self):
		self.login_user()
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), allow_signup=True, roles=[Role(name='testrole1'), Role(name='testrole2')])
		db.session.add(invite)
		db.session.commit()
		token = invite.token
		r = self.client.get(path=url_for('invite.use', token=token), follow_redirects=True)
		dump('invite_use_loggedin', r)
		self.assertEqual(r.status_code, 200)

	def test_use_inactive(self):
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), disabled=True)
		db.session.add(invite)
		db.session.commit()
		token = invite.token
		r = self.client.get(path=url_for('invite.use', token=token), follow_redirects=True)
		dump('invite_use_inactive', r)
		self.assertEqual(r.status_code, 200)

	# TODO: test cases for {logged in, not logged in} x (signup-only, grant-only, both, none?}

	def test_grant(self):
		user = User.query.get('uid=testuser,ou=users,dc=example,dc=com')
		group0 = Group.query.get('cn=uffd_access,ou=groups,dc=example,dc=com')
		role0 = Role(name='baserole', groups=[group0])
		db.session.add(role0)
		user.roles.add(role0)
		user.update_groups()
		group1 = Group.query.get('cn=uffd_admin,ou=groups,dc=example,dc=com')
		role1 = Role(name='testrole1', groups=[group1])
		db.session.add(role1)
		role2 = Role(name='testrole2')
		db.session.add(role2)
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), roles=[role1, role2])
		db.session.add(invite)
		db.session.commit()
		ldap.session.commit()
		token = invite.token
		self.assertIn(role0, user.roles)
		self.assertNotIn(role1, user.roles)
		self.assertNotIn(role2, user.roles)
		self.assertIn(group0, user.groups)
		self.assertNotIn(group1, user.groups)
		self.assertFalse(invite.used)
		self.login_user()
		r = self.client.post(path=url_for('invite.grant', token=token), follow_redirects=True)
		dump('invite_grant', r)
		self.assertEqual(r.status_code, 200)
		db_flush()
		invite = Invite.query.filter_by(token=token).first()
		user = User.query.get('uid=testuser,ou=users,dc=example,dc=com')
		self.assertTrue(invite.used)
		self.assertIn('baserole', [role.name for role in user.roles])
		self.assertIn('testrole1', [role.name for role in user.roles])
		self.assertIn('testrole2', [role.name for role in user.roles])
		self.assertIn('cn=uffd_access,ou=groups,dc=example,dc=com', [group.dn for group in user.groups])
		self.assertIn('cn=uffd_admin,ou=groups,dc=example,dc=com', [group.dn for group in user.groups])

	def test_grant_invalid_invite(self):
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), disabled=True)
		db.session.add(invite)
		db.session.commit()
		token = invite.token
		self.login_user()
		r = self.client.post(path=url_for('invite.grant', token=token), follow_redirects=True)
		dump('invite_grant_invalid_invite', r)
		self.assertEqual(r.status_code, 200)
		self.assertFalse(Invite.query.filter_by(token=token).first().used)

	def test_grant_no_roles(self):
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60))
		db.session.add(invite)
		db.session.commit()
		token = invite.token
		self.login_user()
		r = self.client.post(path=url_for('invite.grant', token=token), follow_redirects=True)
		dump('invite_grant_no_roles', r)
		self.assertEqual(r.status_code, 200)
		self.assertFalse(Invite.query.filter_by(token=token).first().used)

	def test_grant_no_new_roles(self):
		user = User.query.get('uid=testuser,ou=users,dc=example,dc=com')
		role = Role(name='testrole')
		db.session.add(role)
		user.roles.add(role)
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), roles=[role])
		db.session.add(invite)
		db.session.commit()
		token = invite.token
		self.login_user()
		r = self.client.post(path=url_for('invite.grant', token=token), follow_redirects=True)
		dump('invite_grant_no_new_roles', r)
		self.assertEqual(r.status_code, 200)
		self.assertFalse(Invite.query.filter_by(token=token).first().used)

	def test_signup(self):
		baserole = Role(name='base', is_default=True)
		baserole.groups.add(Group.query.get('cn=uffd_access,ou=groups,dc=example,dc=com'))
		baserole.groups.add(Group.query.get('cn=users,ou=groups,dc=example,dc=com'))
		db.session.add(baserole)
		group = Group.query.get('cn=uffd_admin,ou=groups,dc=example,dc=com')
		role1 = Role(name='testrole1', groups=[group])
		db.session.add(role1)
		role2 = Role(name='testrole2')
		db.session.add(role2)
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), roles=[role1, role2], allow_signup=True)
		db.session.add(invite)
		db.session.commit()
		token = invite.token
		r = self.client.get(path=url_for('invite.signup_start', token=token), follow_redirects=True)
		dump('invite_signup_start', r)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('invite.signup_submit', token=token),
			data={'loginname': 'newuser', 'displayname': 'New User', 'mail': 'test@example.com',
            'password1': 'notsecret', 'password2': 'notsecret'}, follow_redirects=True)
		dump('invite_signup_submit', r)
		self.assertEqual(r.status_code, 200)
		signup = InviteSignup.query.one()
		self.assertEqual(signup.loginname, 'newuser')
		self.assertEqual(signup.displayname, 'New User')
		self.assertEqual(signup.mail, 'test@example.com')
		self.assertIn(signup.token, str(self.app.last_mail.get_content()))
		self.assertTrue(signup.check_password('notsecret'))
		self.assertTrue(signup.validate()[0])

	def test_signup_invalid_invite(self):
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), allow_signup=True, disabled=True)
		db.session.add(invite)
		db.session.commit()
		r = self.client.get(path=url_for('invite.signup_start', token=invite.token), follow_redirects=True)
		dump('invite_signup_invalid_invite', r)
		self.assertEqual(r.status_code, 200)

	def test_signup_nosignup(self):
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), allow_signup=False)
		db.session.add(invite)
		db.session.commit()
		r = self.client.get(path=url_for('invite.signup_start', token=invite.token), follow_redirects=True)
		dump('invite_signup_nosignup', r)
		self.assertEqual(r.status_code, 200)

	def test_signup_wrongpassword(self):
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), allow_signup=True)
		db.session.add(invite)
		db.session.commit()
		r = self.client.post(path=url_for('invite.signup_submit', token=invite.token),
			data={'loginname': 'newuser', 'displayname': 'New User', 'mail': 'test@example.com',
			      'password1': 'notsecret', 'password2': 'notthesame'}, follow_redirects=True)
		dump('invite_signup_wrongpassword', r)
		self.assertEqual(r.status_code, 200)

	def test_signup_invalid(self):
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), allow_signup=True)
		db.session.add(invite)
		db.session.commit()
		r = self.client.post(path=url_for('invite.signup_submit', token=invite.token),
			data={'loginname': '', 'displayname': 'New User', 'mail': 'test@example.com',
			      'password1': 'notsecret', 'password2': 'notsecret'}, follow_redirects=True)
		dump('invite_signup_invalid', r)
		self.assertEqual(r.status_code, 200)

	def test_signup_mailerror(self):
		self.app.config['MAIL_SKIP_SEND'] = 'fail'
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), allow_signup=True)
		db.session.add(invite)
		db.session.commit()
		r = self.client.post(path=url_for('invite.signup_submit', token=invite.token),
			data={'loginname': 'newuser', 'displayname': 'New User', 'mail': 'test@example.com',
			      'password1': 'notsecret', 'password2': 'notsecret'}, follow_redirects=True)
		dump('invite_signup_mailerror', r)
		self.assertEqual(r.status_code, 200)

	def test_signup_hostlimit(self):
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), allow_signup=True)
		db.session.add(invite)
		db.session.commit()
		token = invite.token
		for i in range(20):
			r = self.client.post(path=url_for('invite.signup_submit', token=token),
				data={'loginname': 'newuser%d'%i, 'displayname': 'New User', 'mail': 'test%d@example.com'%i,
							'password1': 'notsecret', 'password2': 'notsecret'}, follow_redirects=True)
			self.assertEqual(r.status_code, 200)
		self.app.last_mail = None
		r = self.client.post(path=url_for('invite.signup_submit', token=token),
			data={'loginname': 'newuser', 'displayname': 'New User', 'mail': 'test@example.com',
			      'password1': 'notsecret', 'password2': 'notsecret'}, follow_redirects=True)
		dump('invite_signup_hostlimit', r)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(InviteSignup.query.filter_by(loginname='newuser').all(), [])
		self.assertIsNone(self.app.last_mail)

	def test_signup_mailimit(self):
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), allow_signup=True)
		db.session.add(invite)
		db.session.commit()
		token = invite.token
		for i in range(3):
			r = self.client.post(path=url_for('invite.signup_submit', token=token),
				data={'loginname': 'newuser%d'%i, 'displayname': 'New User', 'mail': 'test@example.com',
							'password1': 'notsecret', 'password2': 'notsecret'}, follow_redirects=True)
			self.assertEqual(r.status_code, 200)
		self.app.last_mail = None
		r = self.client.post(path=url_for('invite.signup_submit', token=token),
			data={'loginname': 'newuser', 'displayname': 'New User', 'mail': 'test@example.com',
			      'password1': 'notsecret', 'password2': 'notsecret'}, follow_redirects=True)
		dump('invite_signup_maillimit', r)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(InviteSignup.query.filter_by(loginname='newuser').all(), [])
		self.assertIsNone(self.app.last_mail)

	def test_signup_check(self):
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), allow_signup=True)
		db.session.add(invite)
		db.session.commit()
		token = invite.token
		r = self.client.post(path=url_for('invite.signup_check', token=token), follow_redirects=True,
		                     data={'loginname': 'newuser'})
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.content_type, 'application/json')
		self.assertEqual(r.json['status'], 'ok')

	def test_signup_check_invalid(self):
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), allow_signup=True)
		db.session.add(invite)
		db.session.commit()
		token = invite.token
		r = self.client.post(path=url_for('invite.signup_check', token=token), follow_redirects=True,
		                     data={'loginname': ''})
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.content_type, 'application/json')
		self.assertEqual(r.json['status'], 'invalid')

	def test_signup_check_exists(self):
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), allow_signup=True)
		db.session.add(invite)
		db.session.commit()
		token = invite.token
		r = self.client.post(path=url_for('invite.signup_check', token=token), follow_redirects=True,
		                     data={'loginname': 'testuser'})
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.content_type, 'application/json')
		self.assertEqual(r.json['status'], 'exists')

	def test_signup_check_nosignup(self):
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), allow_signup=False)
		db.session.add(invite)
		db.session.commit()
		token = invite.token
		r = self.client.post(path=url_for('invite.signup_check', token=token), follow_redirects=True,
		                     data={'loginname': 'testuser'})
		self.assertEqual(r.status_code, 403)
		self.assertEqual(r.content_type, 'application/json')
		self.assertEqual(r.json['status'], 'error')

	def test_signup_check_error(self):
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), allow_signup=True, disabled=True)
		db.session.add(invite)
		db.session.commit()
		token = invite.token
		r = self.client.post(path=url_for('invite.signup_check', token=token), follow_redirects=True,
		                     data={'loginname': 'testuser'})
		self.assertEqual(r.status_code, 403)
		self.assertEqual(r.content_type, 'application/json')
		self.assertEqual(r.json['status'], 'error')

	def test_signup_check_ratelimited(self):
		invite = Invite(valid_until=datetime.datetime.now() + datetime.timedelta(seconds=60), allow_signup=True)
		db.session.add(invite)
		db.session.commit()
		token = invite.token
		for i in range(20):
			r = self.client.post(path=url_for('invite.signup_check', token=token), follow_redirects=True,
													 data={'loginname': 'testuser'})
			self.assertEqual(r.status_code, 200)
			self.assertEqual(r.content_type, 'application/json')
		r = self.client.post(path=url_for('invite.signup_check', token=token), follow_redirects=True,
		                     data={'loginname': 'testuser'})
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.content_type, 'application/json')
		self.assertEqual(r.json['status'], 'ratelimited')

class TestInviteUseViewsOL(TestInviteUseViews):
	use_openldap = True

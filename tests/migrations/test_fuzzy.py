import os
import sys
import datetime

from uffd.database import db
from uffd.models import (
	User, UserEmail, Group,
	RecoveryCodeMethod, TOTPMethod, WebauthnMethod,
	Role, RoleGroup,
	Signup,
	Invite, InviteGrant, InviteSignup,
	DeviceLoginConfirmation,
	Service,
	OAuth2Client, OAuth2LogoutURI, OAuth2Grant, OAuth2Token, OAuth2DeviceLoginInitiation,
	PasswordToken,
)

from tests.utils import MigrationTestCase

class TestFuzzy(MigrationTestCase):
	def setUpApp(self):
		self.app.config['LDAP_SERVICE_MOCK'] = True
		self.app.config['OAUTH2_CLIENTS'] = {
			'test': {
				'service_name': 'test',
				'client_secret': 'testsecret',
				'redirect_uris': ['http://localhost:5004/oauthproxy/callback'],
				'logout_urls': ['http://localhost:5004/oauthproxy/logout']
			}
		}
		self.app.config['API_CLIENTS_2'] = {
			'test': {
				'service_name': 'test',
				'client_secret': 'testsecret',
				'scopes': ['checkpassword', 'getusers', 'getmails']
			},
		}

	# Runs every upgrade/downgrade script with data. To do this we first upgrade
	# to head, create data, then downgrade, upgrade, downgrade for every revision.
	def test_migrations_fuzzy(self):
		self.upgrade('head')
		# Users and groups were created by 878b25c4fae7_ldap_to_db because we set LDAP_SERVICE_MOCK to True
		user = User.query.first()
		group = Group.query.first()
		db.session.add(RecoveryCodeMethod(user=user))
		db.session.add(TOTPMethod(user=user, name='mytotp'))
		db.session.add(WebauthnMethod(user=user, name='mywebauthn', cred=b''))
		role = Role(name='role', groups={group: RoleGroup(group=group)})
		db.session.add(role)
		role.members.append(user)
		db.session.add(Role(name='base', included_roles=[role], locked=True, is_default=True, moderator_group=group, groups={group: RoleGroup(group=group)}))
		db.session.add(Signup(loginname='newuser', displayname='New User', mail='newuser@example.com', password='newpassword'))
		db.session.add(Signup(loginname='testuser', displayname='Testuser', mail='testuser@example.com', password='testpassword', user=user))
		invite = Invite(valid_until=datetime.datetime.now(), roles=[role])
		db.session.add(invite)
		invite.signups.append(InviteSignup(loginname='newuser', displayname='New User', mail='newuser@example.com', password='newpassword'))
		invite.grants.append(InviteGrant(user=user))
		db.session.add(Invite(creator=user, valid_until=datetime.datetime.now()))
		service = Service(name='testservice', access_group=group)
		oauth2_client = OAuth2Client(service=service, client_id='testclient', client_secret='testsecret', redirect_uris=['http://localhost:1234/callback'], logout_uris=[OAuth2LogoutURI(method='GET', uri='http://localhost:1234/callback')])
		db.session.add_all([service, oauth2_client])
		db.session.add(OAuth2Grant(user=user, client=oauth2_client, _code='testcode', redirect_uri='http://example.com/callback', expires=datetime.datetime.now()))
		db.session.add(OAuth2Token(user=user, client=oauth2_client, token_type='Bearer', _access_token='testcode', _refresh_token='testcode', expires=datetime.datetime.now()))
		db.session.add(OAuth2DeviceLoginInitiation(client=oauth2_client, confirmations=[DeviceLoginConfirmation(user=user)]))
		db.session.add(PasswordToken(user=user))
		db.session.commit()
		revs = [s.split('_', 1)[0] for s in os.listdir('uffd/migrations/versions') if '_' in s and s.endswith('.py')]
		for rev in revs:
			self.downgrade('-1')
			self.upgrade('+1')
			self.downgrade('-1')

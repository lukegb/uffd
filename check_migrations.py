#!/usr/bin/python3
import os
import sys
import logging
import datetime

import flask_migrate

from uffd import create_app, db
from uffd.user.models import User, Group
from uffd.mfa.models import RecoveryCodeMethod, TOTPMethod, WebauthnMethod
from uffd.role.models import Role, RoleGroup
from uffd.signup.models import Signup
from uffd.invite.models import Invite, InviteGrant, InviteSignup
from uffd.session.models import DeviceLoginConfirmation
from uffd.oauth2.models import OAuth2Grant, OAuth2Token, OAuth2DeviceLoginInitiation
from uffd.selfservice.models import PasswordToken, MailToken

def run_test(dburi, revision):
	config = {
		'TESTING': True,
		'DEBUG': True,
		'SQLALCHEMY_DATABASE_URI': dburi,
		'SECRET_KEY': 'DEBUGKEY',
		'MAIL_SKIP_SEND': True,
		'SELF_SIGNUP': True,
		'ENABLE_INVITE': True,
		'ENABLE_PASSWORDRESET': True,
		'LDAP_SERVICE_MOCK': True
	}
	app = create_app(config)
	with app.test_request_context():
		flask_migrate.upgrade(revision='head')
		# Add a few rows to all tables to make sure that the migrations work with data
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
		db.session.add(OAuth2Grant(user=user, client_id='testclient', code='testcode', redirect_uri='http://example.com/callback', expires=datetime.datetime.now()))
		db.session.add(OAuth2Token(user=user, client_id='testclient', token_type='Bearer', access_token='testcode', refresh_token='testcode', expires=datetime.datetime.now()))
		db.session.add(OAuth2DeviceLoginInitiation(oauth2_client_id='testclient', confirmations=[DeviceLoginConfirmation(user=user)]))
		db.session.add(PasswordToken(user=user))
		db.session.add(MailToken(user=user, newmail='test@example.com'))
		db.session.commit()
		flask_migrate.downgrade(revision=revision)
		flask_migrate.upgrade(revision='head')

if __name__ == '__main__':
	if len(sys.argv) != 2 or sys.argv[1] not in ['sqlite', 'mysql']:
		print('usage: check_migrations.py {sqlite|mysql}')
		exit(1)
	dbtype = sys.argv[1]
	revs = [s.split('_', 1)[0] for s in os.listdir('uffd/migrations/versions') if '_' in s and s.endswith('.py')] + ['base']
	logging.getLogger().setLevel(logging.INFO)
	failures = 0
	for rev in revs:
		logging.info(f'Testing "upgrade to head, add objects, downgrade to {rev}, upgrade to head"')
		# Cleanup/drop database
		if dbtype == 'sqlite':
			try:
				os.remove('/tmp/uffd_check_migrations_db.sqlite3')
			except FileNotFoundError:
				pass
			dburi = 'sqlite:////tmp/uffd_check_migrations_db.sqlite3'
		elif dbtype == 'mysql':
			import MySQLdb
			conn = MySQLdb.connect(user='root', unix_socket='/var/run/mysqld/mysqld.sock')
			cur = conn.cursor()
			try:
				cur.execute('DROP DATABASE uffd')
			except:
				pass
			cur.execute('CREATE DATABASE uffd')
			conn.close()
			dburi = 'mysql+mysqldb:///uffd?unix_socket=/var/run/mysqld/mysqld.sock'
		try:
			run_test(dburi, rev)
		except Exception as ex:
			failures += 1
			logging.error('Test failed', exc_info=ex)
	if failures:
		logging.info(f'{failures} tests failed')
		exit(1)
	logging.info('All tests succeeded')
	exit(0)

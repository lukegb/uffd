import os
import tempfile
import shutil
import unittest

from flask import request, url_for

from uffd import create_app, db
from uffd.user.models import User, Group

def dump(basename, resp):
	basename = basename.replace('.', '_').replace('/', '_')
	suffix = '.html'
	root = os.environ.get('DUMP_PAGES')
	if not root:
		return
	os.makedirs(root, exist_ok=True)
	path = os.path.join(root, basename+suffix)
	with open(path, 'wb') as f:
		f.write(resp.data)

def db_flush():
	db.session.rollback()
	db.session = db.create_scoped_session()
	if hasattr(request, 'ldap_connection'):
		del request.ldap_session

class UffdTestCase(unittest.TestCase):
	use_openldap = False
	use_userconnection = False

	def get_user(self):
		return User.query.get(self.test_data.get('user').get('dn'))

	def get_admin(self):
		return User.query.get(self.test_data.get('admin').get('dn'))

	def get_admin_group(self):
		return Group.query.get(self.test_data.get('group_uffd_admin').get('dn'))

	def get_access_group(self):
		return Group.query.get(self.test_data.get('group_uffd_access').get('dn'))

	def get_users_group(self):
		return Group.query.get(self.test_data.get('group_users').get('dn'))

	def login_as(self, user, ref=None):
		return self.client.post(path=url_for('session.login', ref=ref),
								data={'loginname': self.test_data.get(user).get('loginname'),
									'password': self.test_data.get(user).get('password')}, follow_redirects=True)

	def setUp(self):
		# It would be far better to create a minimal app here, but since the
		# session module depends on almost everything else, that is not really feasable
		config = {
			'TESTING': True,
			'DEBUG': True,
			'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
			'SECRET_KEY': 'DEBUGKEY',
			'LDAP_SERVICE_MOCK': True,
			'MAIL_SKIP_SEND': True,
			'SELF_SIGNUP': True,
			'ENABLE_INVITE': True,
			'ENABLE_PASSWORDRESET': True
		}
		if self.use_openldap:
			if not os.environ.get('UNITTEST_OPENLDAP'):
				self.skipTest('OPENLDAP_TESTING not set')
			config['LDAP_SERVICE_MOCK'] = False
			config['LDAP_SERVICE_URL'] = 'ldap://localhost'
			if self.use_userconnection:
				config['LDAP_SERVICE_USER_BIND'] = True
				config['SELF_SIGNUP'] = False
				config['ENABLE_INVITE'] = False
				config['ENABLE_PASSWORDRESET'] = False
				config['ENABLE_ROLESELFSERVICE'] = False
			else:
				config['LDAP_SERVICE_BIND_DN'] = 'cn=uffd,ou=system,dc=example,dc=com'
			config['LDAP_SERVICE_BIND_PASSWORD'] = 'uffd-ldap-password'
			os.system("ldapdelete -c -D 'cn=uffd,ou=system,dc=example,dc=com' -w '{}' -H '{}' -f tests/openldap_ldifs/ldap_server_entries_cleanup.ldif > /dev/null 2>&1".format(config['LDAP_SERVICE_BIND_PASSWORD'], config['LDAP_SERVICE_URL']))
			os.system("ldapadd -c -D 'cn=uffd,ou=system,dc=example,dc=com' -w '{}' -H '{}' -f tests/openldap_ldifs/ldap_server_entries_add.ldif".format(config['LDAP_SERVICE_BIND_PASSWORD'], config['LDAP_SERVICE_URL']))
			os.system("ldapmodify -c -D 'cn=uffd,ou=system,dc=example,dc=com' -w '{}' -H '{}' -f tests/openldap_ldifs/ldap_server_entries_modify.ldif".format(config['LDAP_SERVICE_BIND_PASSWORD'], config['LDAP_SERVICE_URL']))
			#os.system("/usr/sbin/slapcat -n 1 -l /dev/stdout")

		self.test_data = {
			'admin': {
				'loginname': 'testadmin',
				'dn': 'uid=testadmin,ou=users,dc=example,dc=com',
				'password': 'adminpassword'
			},
			'user': {
				'loginname': 'testuser',
				'dn': 'uid=testuser,ou=users,dc=example,dc=com',
				'password': 'userpassword'
			},
			'group_uffd_access': {
				'dn': 'cn=uffd_access,ou=groups,dc=example,dc=com'
			},
			'group_uffd_admin': {
				'dn': 'cn=uffd_admin,ou=groups,dc=example,dc=com'
			},
			'group_users': {
				'dn': 'cn=users,ou=groups,dc=example,dc=com'
			}
		}

		self.app = create_app(config)
		self.setUpApp()
		self.client = self.app.test_client()
		self.client.__enter__()
		# Just do some request so that we can use url_for
		self.client.get(path='/')
		db.create_all()

	def setUpApp(self):
		pass

	def tearDown(self):
		self.client.__exit__(None, None, None)

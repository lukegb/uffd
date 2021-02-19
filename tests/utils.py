import os
import tempfile
import shutil
import unittest

from uffd import create_app, db

def dump(basename, resp):
	basename = basename.replace('.', '_').replace('/', '_')
	suffix = '.html'
	root = os.environ.get('DUMP_PAGES')
	if not root:
		return
	os.makedirs(root, exist_ok=True)
	path = os.path.join(root, basename+suffix)
	with open(path, 'xb') as f:
		f.write(resp.data)

class UffdTestCase(unittest.TestCase):
	use_openldap = False

	def setUp(self):
		self.dir = tempfile.mkdtemp()
		# It would be far better to create a minimal app here, but since the
		# session module depends on almost everything else, that is not really feasable
		config = {
			'TESTING': True,
			'DEBUG': True,
			'SQLALCHEMY_DATABASE_URI': 'sqlite:///%s/db.sqlite'%self.dir,
			'SECRET_KEY': 'DEBUGKEY',
			'LDAP_SERVICE_MOCK': True,
		}
		if self.use_openldap:
			if not os.environ.get('UNITTEST_OPENLDAP'):
				self.skipTest('OPENLDAP_TESTING not set')
			config['LDAP_SERVICE_MOCK'] = False
			config['LDAP_SERVICE_URL'] = 'ldap://localhost'
			config['LDAP_SERVICE_BIND_DN'] = 'cn=uffd,ou=system,dc=example,dc=com'
			config['LDAP_SERVICE_BIND_PASSWORD'] = 'uffd-ldap-password'
			os.system("ldapdelete -c -D 'cn=uffd,ou=system,dc=example,dc=com' -w 'uffd-ldap-password' -H 'ldap://localhost' -f ldap_server_entries_cleanup.ldif > /dev/null 2>&1")
			os.system("ldapadd -c -D 'cn=uffd,ou=system,dc=example,dc=com' -w 'uffd-ldap-password' -H 'ldap://localhost' -f ldap_server_entries_add.ldif")
			os.system("ldapmodify -c -D 'cn=uffd,ou=system,dc=example,dc=com' -w 'uffd-ldap-password' -H 'ldap://localhost' -f ldap_server_entries_modify.ldif")
			#os.system("/usr/sbin/slapcat -n 1 -l /dev/stdout")
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
		shutil.rmtree(self.dir)

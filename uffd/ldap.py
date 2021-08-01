import base64
import hashlib

from flask import current_app, request, abort, session

import ldap3
from ldap3.core.exceptions import LDAPBindError, LDAPPasswordIsMandatoryError, LDAPInvalidDnError

# We import LDAPCommitError only because it is imported from us by other files. It is not needed here
from uffd.ldapalchemy import LDAPMapper, LDAPCommitError # pylint: disable=unused-import
from uffd.ldapalchemy.model import Query
from uffd.ldapalchemy.core import encode_filter


def check_hashed(password_hash, password):
	'''Return if password matches a LDAP-compatible password hash (only used for LDAP_SERVICE_MOCK)

	:param password_hash: LDAP-compatible password hash (plain password or "{ssha512}...")
	:type password_hash: bytes
	:param password: Plain, (ideally) utf8-encoded password
	:type password: bytes'''
	algorithms = {
		b'md5': 'MD5',
		b'sha': 'SHA1',
		b'sha256': 'SHA256',
		b'sha384': 'SHA384',
		b'sha512': 'SHA512'
	}
	if not password_hash.startswith(b'{'):
		return password_hash == password
	algorithm, data = password_hash[1:].split(b'}', 1)
	data = base64.b64decode(data)
	if algorithm in algorithms:
		ctx = hashlib.new(algorithms[algorithm], password)
		return data == ctx.digest()
	if algorithm.startswith(b's') and algorithm[1:] in algorithms:
		ctx = hashlib.new(algorithms[algorithm[1:]], password)
		salt = data[ctx.digest_size:]
		ctx.update(salt)
		return data == ctx.digest() + salt
	raise NotImplementedError()


class FlaskQuery(Query):
	def get_or_404(self, dn):
		res = self.get(dn)
		if res is None:
			abort(404)
		return res

	def first_or_404(self):
		res = self.first()
		if res is None:
			abort(404)
		return res


def test_user_bind(bind_dn, bind_pw):
	try:
		if current_app.config.get('LDAP_SERVICE_MOCK', False):
			# Since we reuse the same conn and ldap3's mock only supports plain
			# passwords for bind and rebind, we simulate the bind by retrieving
			# and checking the password hash ourselves.
			conn = ldap.get_connection()
			conn.search(bind_dn, search_filter='(objectclass=*)', search_scope=ldap3.BASE,
			            attributes=ldap3.ALL_ATTRIBUTES)
			if not conn.response:
				return False
			if not conn.response[0]['attributes'].get('userPassword'):
				return False
			return check_hashed(conn.response[0]['attributes']['userPassword'][0], bind_pw.encode())

		server = ldap3.Server(current_app.config["LDAP_SERVICE_URL"])
		conn = connect_and_bind_to_ldap(server, bind_dn, bind_pw)
		if not conn:
			return False
	except (LDAPBindError, LDAPPasswordIsMandatoryError, LDAPInvalidDnError):
		return False

	conn.search(conn.user, encode_filter(current_app.config["LDAP_USER_SEARCH_FILTER"]))
	lazy_entries = conn.entries
	# Do not end the connection when using mock, as it will be reused afterwards
	if not current_app.config.get('LDAP_SERVICE_MOCK', False):
		conn.unbind()
	return len(lazy_entries) == 1


def connect_and_bind_to_ldap(server, bind_dn, bind_pw):
	# Using auto_bind cannot close the connection, so define the connection with extra steps
	connection = ldap3.Connection(server, bind_dn, bind_pw)
	if connection.closed:
		connection.open(read_server_info=False)
	if current_app.config["LDAP_SERVICE_USE_STARTTLS"]:
		connection.start_tls(read_server_info=False)
	if not connection.bind(read_server_info=True):
		connection.unbind()
		raise LDAPBindError
	return connection


class FlaskLDAPMapper(LDAPMapper):
	def __init__(self):
		super().__init__()

		class Model(self.Model):
			query_class = FlaskQuery

		self.Model = Model # pylint: disable=invalid-name

	@property
	def session(self):
		if not hasattr(request, 'ldap_session'):
			request.ldap_session = self.Session(self.get_connection)
		return request.ldap_session

	def get_connection(self):
		if hasattr(request, 'ldap_connection'):
			return request.ldap_connection
		if current_app.config.get('LDAP_SERVICE_MOCK', False):
			if not current_app.debug:
				raise Exception('LDAP_SERVICE_MOCK cannot be enabled on production instances')
			# Entries are stored in-memory in the mocked `Connection` object. To make
			# changes persistent across requests we reuse the same `Connection` object
			# for all calls to `service_conn()` and `user_conn()`.
			if not hasattr(current_app, 'ldap_mock'):
				server = ldap3.Server.from_definition('ldap_mock', 'tests/openldap_mock/ldap_server_info.json',
				                                      'tests/openldap_mock/ldap_server_schema.json')
				current_app.ldap_mock = ldap3.Connection(server, client_strategy=ldap3.MOCK_SYNC)
				current_app.ldap_mock.strategy.entries_from_json('tests/openldap_mock/ldap_server_entries.json')
				current_app.ldap_mock.bind()
			return current_app.ldap_mock
		server = ldap3.Server(current_app.config["LDAP_SERVICE_URL"], get_info=ldap3.ALL)

		if current_app.config['LDAP_SERVICE_USER_BIND']:
			bind_dn = session['user_dn']
			bind_pw = session['user_pw']
		else:
			bind_dn = current_app.config["LDAP_SERVICE_BIND_DN"]
			bind_pw = current_app.config["LDAP_SERVICE_BIND_PASSWORD"]

		request.ldap_connection = connect_and_bind_to_ldap(server, bind_dn, bind_pw)
		return request.ldap_connection


ldap = FlaskLDAPMapper()

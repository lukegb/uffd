from flask import current_app, request

import ldap3

from ldap_mapper import LDAPMapper, LDAPCommitError # pylint: disable=unused-import

class FlaskLDAPMapper(LDAPMapper):
	def __init__(self):
		super().__init__()

	@property
	def session(self):
		if not hasattr(request, 'ldap_session'):
			request.ldap_session = self.Session(self.get_connection)
		return request.ldap_session

	def get_connection(self):
		if current_app.config.get('LDAP_SERVICE_MOCK', False):
			if not current_app.debug:
				raise Exception('LDAP_SERVICE_MOCK cannot be enabled on production instances')
			# Entries are stored in-memory in the mocked `Connection` object. To make
			# changes persistent across requests we reuse the same `Connection` object
			# for all calls to `service_conn()` and `user_conn()`.
			if not hasattr(current_app, 'ldap_mock'):
				server = ldap3.Server.from_definition('ldap_mock', 'ldap_server_info.json', 'ldap_server_schema.json')
				current_app.ldap_mock = ldap3.Connection(server, client_strategy=ldap3.MOCK_SYNC)
				current_app.ldap_mock.strategy.entries_from_json('ldap_server_entries.json')
				current_app.ldap_mock.bind()
			return current_app.ldap_mock
		server = ldap3.Server(current_app.config["LDAP_SERVICE_URL"], get_info=ldap3.ALL)
		return ldap3.Connection(server, current_app.config["LDAP_SERVICE_BIND_DN"],
		                        current_app.config["LDAP_SERVICE_BIND_PASSWORD"], auto_bind=True)

ldap = FlaskLDAPMapper()

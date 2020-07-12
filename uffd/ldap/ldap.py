from flask import Blueprint, request, session, current_app

from ldap3 import Server, Connection, ALL, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
from ldap3.utils.conv import escape_filter_chars

bp = Blueprint("ldap", __name__)

def fix_connection(conn):
	old_search = conn.search
	def search(*args, **kwargs):
		kwargs.update({'attributes': [ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES]})
		return old_search(*args, **kwargs)
	conn.search = search
	return conn

def service_conn():
	server = Server(current_app.config["LDAP_SERVICE_URL"], get_info=ALL)
	return Connection(server, current_app.config["LDAP_SERVICE_BIND_DN"], current_app.config["LDAP_SERVICE_BIND_PASSWORD"], auto_bind=True)

def user_conn():
	pass

def get_conn():
	conn = service_conn()
	return fix_connection(conn)

def uid_to_dn(uid):
	conn = service_conn()
	conn.search(current_app.config["LDAP_BASE_USER"], '(&(objectclass=person)(uidNumber={}))'.format(escape_filter_chars(uid)))
	if not len(conn.entries) == 1:
		return None
	else:
		return conn.entries[0].entry_dn

def loginname_to_dn(loginname):
	return 'uid={},{}'.format(escape_filter_chars(loginname), current_app.config["LDAP_BASE_USER"])

def get_next_uid():
	conn = service_conn()
	conn.search(current_app.config["LDAP_BASE_USER"], '(objectclass=person)')
	max_uid = current_app.config["LDAP_USER_MIN_UID"]
	for i in conn.entries:
		# skip out of range entries
		if i['uidNumber'].value > current_app.config["LDAP_USER_MAX_UID"]:
			continue
		if i['uidNumber'].value < current_app.config["LDAP_USER_MIN_UID"]:
			continue
		max_uid = max(i['uidNumber'].value, max_uid)
	next_uid = max_uid + 1
	if uid_to_dn(next_uid):
		raise Exception('No free uid found')
	else:
		return next_uid

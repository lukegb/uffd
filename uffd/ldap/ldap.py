import string

from flask import Blueprint, current_app
from ldap3.utils.conv import escape_filter_chars
from ldap3.core.exceptions import LDAPBindError, LDAPCursorError

from ldap3 import Server, Connection, ALL, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES

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
	return fix_connection(Connection(server, current_app.config["LDAP_SERVICE_BIND_DN"], current_app.config["LDAP_SERVICE_BIND_PASSWORD"], auto_bind=True))

def user_conn(loginname, password):
	if not loginname_is_safe(loginname):
		return False
	server = Server(current_app.config["LDAP_SERVICE_URL"], get_info=ALL)
	try:
		return fix_connection(Connection(server, loginname_to_dn(loginname), password, auto_bind=True))
	except LDAPBindError:
		return False

def get_conn():
	return service_conn()

def uid_to_dn(uid):
	conn = get_conn()
	conn.search(current_app.config["LDAP_BASE_USER"], '(&(objectclass=person)(uidNumber={}))'.format(escape_filter_chars(uid)))
	if not len(conn.entries) == 1:
		return None
	return conn.entries[0].entry_dn

def loginname_to_dn(loginname):
	if loginname_is_safe(loginname):
		return 'uid={},{}'.format(loginname, current_app.config["LDAP_BASE_USER"])
	raise Exception('unsafe login name')

def mail_to_dn(uid):
	if mailname_is_safe(uid):
		return 'uid={},{}'.format(uid, current_app.config["LDAP_BASE_MAIL"])
	raise Exception('unsafe mail name')

def loginname_is_safe(value):
	if len(value) > 32 or len(value) < 1:
		return False
	for char in value:
		if not char in string.ascii_lowercase + string.digits + '_':
			return False
	return True

def mailname_is_safe(value):
	return loginname_is_safe(value)

def get_next_uid():
	conn = get_conn()
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
	return next_uid

def get_ldap_attribute_safe(ldapobject, attribute):
	try:
		result = ldapobject[attribute].value if attribute in ldapobject  else None
	# we have to catch LDAPCursorError here, because ldap3 in older versions has a broken __contains__ function
	# see https://github.com/cannatag/ldap3/issues/493
	# fixed in version 2.5
	# debian buster ships 2.4.1
	except LDAPCursorError:
		result = None
	return result

def get_ldap_array_attribute_safe(ldapobject, attribute):
	# if the aray is empty, the attribute does not exist.
	# if there is only one elemtent, ldap returns a string and not an array with one element
	# we sanitize this to always be an array
	result = get_ldap_attribute_safe(ldapobject, attribute)
	if not result:
		result = []
	if isinstance(result, str):
		result = [result]
	return result

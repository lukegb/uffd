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
	conn = Connection(server, current_app.config["LDAP_SERVICE_BIND_DN"], current_app.config["LDAP_SERVICE_BIND_PASSWORD"], auto_bind=True)
	return fix_connection(conn)

def user_conn():
	pass

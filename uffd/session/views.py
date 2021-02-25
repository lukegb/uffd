import datetime
import secrets
import functools

from flask import Blueprint, render_template, request, url_for, redirect, flash, current_app, session, abort

import ldap3
from ldap3.core.exceptions import LDAPBindError, LDAPPasswordIsMandatoryError
from ldapalchemy.core import encode_filter

from uffd.user.models import User
from uffd.ldap import ldap
from uffd.ratelimit import Ratelimit, host_ratelimit, format_delay

bp = Blueprint("session", __name__, template_folder='templates', url_prefix='/')

login_ratelimit = Ratelimit('login', 1*60, 3)

def login_get_user(loginname, password):
	dn = User(loginname=loginname).dn
	if current_app.config.get('LDAP_SERVICE_MOCK', False):
		conn = ldap.get_connection()
		# Since we reuse the same conn for all calls to `user_conn()` we
		# simulate the password check by rebinding. Note that ldap3's mocking
		# implementation just compares the string in the objects's userPassword
		# field with the password, no support for hashing or OpenLDAP-style
		# password-prefixes ("{PLAIN}..." or "{ssha512}...").
		try:
			if not conn.rebind(dn, password):
				return None
		except (LDAPBindError, LDAPPasswordIsMandatoryError):
			return None
	else:
		server = ldap3.Server(current_app.config["LDAP_SERVICE_URL"], get_info=ldap3.ALL)
		auto_bind = ldap3.AUTO_BIND_TLS_BEFORE_BIND if current_app.config["LDAP_SERVICE_USE_STARTTLS"] else True
		try:
			conn = ldap3.Connection(server, dn, password, auto_bind=auto_bind)
		except (LDAPBindError, LDAPPasswordIsMandatoryError):
			return None
	conn.search(conn.user, encode_filter(current_app.config["LDAP_USER_SEARCH_FILTER"]))
	if len(conn.entries) != 1:
		return None
	return User.query.get(dn)

@bp.route("/logout")
def logout():
	# The oauth2 module takes data from `session` and injects it into the url,
	# so we need to build the url BEFORE we clear the session!
	resp = redirect(url_for('oauth2.logout', ref=url_for('.login')))
	session.clear()
	return resp

@bp.route("/login", methods=('GET', 'POST'))
def login():
	if request.method == 'GET':
		return render_template('login.html', ref=request.values.get('ref'))

	username = request.form['loginname']
	password = request.form['password']
	login_delay = login_ratelimit.get_delay(username)
	host_delay = host_ratelimit.get_delay()
	if login_delay or host_delay:
		if login_delay > host_delay:
			flash('We received too many invalid login attempts for this user! Please wait at least %s.'%format_delay(login_delay))
		else:
			flash('We received too many requests from your ip address/network! Please wait at least %s.'%format_delay(host_delay))
		return render_template('login.html', ref=request.values.get('ref'))
	user = login_get_user(username, password)
	if user is None:
		login_ratelimit.log(username)
		host_ratelimit.log()
		flash('Login name or password is wrong')
		return render_template('login.html', ref=request.values.get('ref'))
	if not user.is_in_group(current_app.config['ACL_SELFSERVICE_GROUP']):
		flash('You do not have access to this service')
		return render_template('login.html', ref=request.values.get('ref'))
	session.clear()
	session['user_dn'] = user.dn
	session['logintime'] = datetime.datetime.now().timestamp()
	session['_csrf_token'] = secrets.token_hex(128)
	return redirect(url_for('mfa.auth', ref=request.values.get('ref', url_for('index'))))

def get_current_user():
	if 'user_dn' not in session:
		return None
	return User.query.get(session['user_dn'])

def login_valid():
	user = get_current_user()
	if user is None:
		return False
	if datetime.datetime.now().timestamp() > session['logintime'] + current_app.config['SESSION_LIFETIME_SECONDS']:
		return False
	return True

def is_valid_session():
	if not login_valid():
		return False
	if not session.get('user_mfa'):
		return False
	return True
bp.add_app_template_global(is_valid_session)

def pre_mfa_login_required(no_redirect=False):
	def wrapper(func):
		@functools.wraps(func)
		def decorator(*args, **kwargs):
			if not login_valid() or datetime.datetime.now().timestamp() > session['logintime'] + 10*60:
				session.clear()
				if no_redirect:
					abort(403)
				flash('You need to login first')
				return redirect(url_for('session.login', ref=request.url))
			return func(*args, **kwargs)
		return decorator
	return wrapper

def login_required(group=None):
	def wrapper(func):
		@functools.wraps(func)
		def decorator(*args, **kwargs):
			if not login_valid():
				flash('You need to login first')
				return redirect(url_for('session.login', ref=request.url))
			if not session.get('user_mfa'):
				return redirect(url_for('mfa.auth', ref=request.url))
			if not get_current_user().is_in_group(group):
				flash('Access denied')
				return redirect(url_for('index'))
			return func(*args, **kwargs)
		return decorator
	return wrapper

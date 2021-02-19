import datetime
import secrets
import functools

from flask import Blueprint, render_template, request, url_for, redirect, flash, current_app, session, abort

from uffd.user.models import User
from uffd.ldap import user_conn
from uffd.ratelimit import Ratelimit, host_ratelimit, format_delay

bp = Blueprint("session", __name__, template_folder='templates', url_prefix='/')

login_ratelimit = Ratelimit('login', 1*60, 3)

def login_get_user(loginname, password):
	print('login with', loginname, password)
	dn = User(loginname=loginname).dn
	conn = user_conn(dn, password)
	if not conn:
		print('conn is None')
		return None
	conn.search(conn.user, '(objectClass=person)')
	if len(conn.entries) != 1:
		print('wrong number of entries', conn.entries)
		return None
	return User.ldap_get(dn)

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
		print(session)
		return None
	return User.ldap_get(session['user_dn'])

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

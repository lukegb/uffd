import datetime
import secrets
import string
import functools

from flask import Blueprint, render_template, request, url_for, redirect, flash, current_app, session

from uffd.navbar import register_navbar
from uffd.csrf import csrf_protect
from uffd.user.models import User
from uffd.ldap import get_conn, user_conn, uid_to_dn

bp = Blueprint("session", __name__, template_folder='templates', url_prefix='/')

@bp.route("/logout")
def logout():
	session.clear()
	return redirect(url_for('.login'))

@bp.route("/login", methods=('GET', 'POST'))
def login():
	if request.method == 'GET':
		return render_template('login.html')

	username = request.form['loginname']
	password = request.form['password']
	conn = user_conn(username, password)
	if not conn:
		flash('Login name or password is wrong')
		return redirect(url_for('.login'))
	conn.search(conn.user, '(objectClass=person)')
	if not len(conn.entries) == 1:
		flash('Login name or password is wrong')
		return redirect(url_for('.login'))
	user = User.from_ldap(conn.entries[0])
	if not user.is_in_group(current_app.config['ACL_SELFSERVICE_GROUP']):
		flash('You do not have access to this service')
		return redirect(url_for('.login'))
	session['user_uid'] = user.uid
	session['logintime'] = datetime.datetime.now().timestamp()
	session['_csrf_token'] = secrets.token_hex(128)
	return redirect(request.values.get('ref', url_for('index')))

def get_current_user():
	if not session.get('user_uid'):
		return None
	if not hasattr(request, 'current_user'):
		request.current_user = User.from_ldap_dn(uid_to_dn(session['user_uid']))
	return request.current_user

def is_valid_session():
	user = get_current_user()
	if not user:
		return False
	if datetime.datetime.now().timestamp() > session['logintime'] + current_app.config['SESSION_LIFETIME_SECONDS']:
		flash('Session timed out')
		return False
	return True
bp.add_app_template_global(is_valid_session)

def login_required(group=None):
	def wrapper(func):
		@functools.wraps(func)
		def decorator(*args, **kwargs):
			if not is_valid_session():
				flash('You need to login first')
				return redirect(url_for('session.login', ref=request.url))
			if not get_current_user().is_in_group(group):
				flash('Access denied')
				return redirect(url_for('index'))
			return func(*args, **kwargs)
		return decorator
	return wrapper

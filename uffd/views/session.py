import datetime
import secrets
import functools

from flask import Blueprint, render_template, request, url_for, redirect, flash, current_app, session, abort
from flask_babel import gettext as _

from uffd.database import db
from uffd.csrf import csrf_protect
from uffd.secure_redirect import secure_local_redirect
from uffd.models import User, DeviceLoginInitiation, DeviceLoginConfirmation, Ratelimit, host_ratelimit, format_delay

bp = Blueprint("session", __name__, template_folder='templates', url_prefix='/')

login_ratelimit = Ratelimit('login', 1*60, 3)

@bp.before_app_request
def set_request_user():
	request.user = None
	request.user_pre_mfa = None
	if 'user_id' not in session:
		return
	if 'logintime' not in session:
		return
	if datetime.datetime.utcnow().timestamp() > session['logintime'] + current_app.config['SESSION_LIFETIME_SECONDS']:
		return
	user = User.query.get(session['user_id'])
	if not user or user.is_deactivated or not user.is_in_group(current_app.config['ACL_ACCESS_GROUP']):
		return
	request.user_pre_mfa = user
	if session.get('user_mfa'):
		request.user = user

@bp.route("/logout")
def logout():
	# The oauth2 module takes data from `session` and injects it into the url,
	# so we need to build the url BEFORE we clear the session!
	resp = redirect(url_for('oauth2.logout', ref=request.values.get('ref', url_for('.login'))))
	session.clear()
	return resp

def set_session(user, skip_mfa=False):
	session.clear()
	session.permanent = True
	session['user_id'] = user.id
	session['logintime'] = datetime.datetime.utcnow().timestamp()
	session['_csrf_token'] = secrets.token_hex(128)
	if skip_mfa:
		session['user_mfa'] = True

@bp.route("/login", methods=('GET', 'POST'))
def login():
	# pylint: disable=too-many-return-statements
	if request.user_pre_mfa:
		return redirect(url_for('mfa.auth', ref=request.values.get('ref', url_for('index'))))
	if request.method == 'GET':
		return render_template('session/login.html', ref=request.values.get('ref'))

	username = request.form['loginname'].lower()
	password = request.form['password']
	login_delay = login_ratelimit.get_delay(username)
	host_delay = host_ratelimit.get_delay()
	if login_delay or host_delay:
		if login_delay > host_delay:
			flash(_('We received too many invalid login attempts for this user! Please wait at least %(delay)s.', delay=format_delay(login_delay)))
		else:
			flash(_('We received too many requests from your ip address/network! Please wait at least %(delay)s.', delay=format_delay(host_delay)))
		return render_template('session/login.html', ref=request.values.get('ref'))

	user = User.query.filter_by(loginname=username).one_or_none()
	if user is None or not user.password.verify(password):
		login_ratelimit.log(username)
		host_ratelimit.log()
		flash(_('Login name or password is wrong'))
		return render_template('session/login.html', ref=request.values.get('ref'))
	if user.is_deactivated:
		flash(_('Your account is deactivated. Contact %(contact_email)s for details.', contact_email=current_app.config['ORGANISATION_CONTACT']))
		return render_template('session/login.html', ref=request.values.get('ref'))
	if user.password.needs_rehash:
		user.password = password
		db.session.commit()
	if not user.is_in_group(current_app.config['ACL_ACCESS_GROUP']):
		flash(_('You do not have access to this service'))
		return render_template('session/login.html', ref=request.values.get('ref'))
	set_session(user)
	return redirect(url_for('mfa.auth', ref=request.values.get('ref', url_for('index'))))

def login_required_pre_mfa(no_redirect=False):
	def wrapper(func):
		@functools.wraps(func)
		def decorator(*args, **kwargs):
			if not request.user_pre_mfa:
				if no_redirect:
					abort(403)
				flash(_('You need to login first'))
				return redirect(url_for('session.login', ref=request.full_path))
			return func(*args, **kwargs)
		return decorator
	return wrapper

def login_required(permission_check=lambda: True):
	def wrapper(func):
		@functools.wraps(func)
		def decorator(*args, **kwargs):
			if not request.user_pre_mfa:
				flash(_('You need to login first'))
				return redirect(url_for('session.login', ref=request.full_path))
			if not request.user:
				return redirect(url_for('mfa.auth', ref=request.full_path))
			if not permission_check():
				abort(403)
			return func(*args, **kwargs)
		return decorator
	return wrapper

@bp.route("/login/device/start")
def devicelogin_start():
	session['devicelogin_started'] = True
	return secure_local_redirect(request.values['ref'])

@bp.route("/login/device")
def devicelogin():
	if 'devicelogin_id' not in session or 'devicelogin_secret' not in session:
		return redirect(url_for('session.login', ref=request.values['ref'], devicelogin=True))
	initiation = DeviceLoginInitiation.query.filter_by(id=session['devicelogin_id'], secret=session['devicelogin_secret']).one_or_none()
	if not initiation or initiation.expired:
		flash(_('Initiation code is no longer valid'))
		return redirect(url_for('session.login', ref=request.values['ref'], devicelogin=True))
	return render_template('session/devicelogin.html', ref=request.values.get('ref'), initiation=initiation)

@bp.route("/login/device", methods=['POST'])
def devicelogin_submit():
	if 'devicelogin_id' not in session or 'devicelogin_secret' not in session:
		return redirect(url_for('session.login', ref=request.values['ref'], devicelogin=True))
	initiation = DeviceLoginInitiation.query.filter_by(id=session['devicelogin_id'], secret=session['devicelogin_secret']).one_or_none()
	if not initiation or initiation.expired:
		flash(_('Initiation code is no longer valid'))
		return redirect(url_for('session.login', ref=request.values['ref'], devicelogin=True))
	confirmation = DeviceLoginConfirmation.query.filter_by(initiation=initiation, code=request.form['confirmation-code']).one_or_none()
	if confirmation is None:
		flash(_('Invalid confirmation code'))
		return render_template('session/devicelogin.html', ref=request.values.get('ref'), initiation=initiation)
	session['devicelogin_confirmation'] = confirmation.id
	return secure_local_redirect(request.values['ref'])

@bp.route("/device")
@login_required()
def deviceauth():
	if 'initiation-code' not in request.values:
		return render_template('session/deviceauth.html')
	initiation = DeviceLoginInitiation.query.filter_by(code=request.values['initiation-code']).one_or_none()
	if initiation is None or initiation.expired:
		flash(_('Invalid initiation code'))
		return redirect(url_for('session.deviceauth'))
	return render_template('session/deviceauth.html', initiation=initiation)

@bp.route("/device", methods=['POST'])
@login_required()
@csrf_protect(blueprint=bp)
def deviceauth_submit():
	DeviceLoginConfirmation.query.filter_by(user=request.user).delete()
	initiation = DeviceLoginInitiation.query.filter_by(code=request.form['initiation-code']).one_or_none()
	if initiation is None or initiation.expired:
		flash(_('Invalid initiation code'))
		return redirect(url_for('session.deviceauth'))
	confirmation = DeviceLoginConfirmation(user=request.user, initiation=initiation)
	db.session.add(confirmation)
	db.session.commit()
	return render_template('session/deviceauth.html', initiation=initiation, confirmation=confirmation)

@bp.route("/device/finish", methods=['GET', 'POST'])
@login_required()
def deviceauth_finish():
	DeviceLoginConfirmation.query.filter_by(user=request.user).delete()
	db.session.commit()
	return redirect(url_for('index'))

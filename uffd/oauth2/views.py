import datetime
import functools
import urllib.parse

from flask import Blueprint, request, jsonify, render_template, session, redirect, url_for, flash
from flask_oauthlib.provider import OAuth2Provider
from flask_babel import gettext as _
from sqlalchemy.exc import IntegrityError

from uffd.ratelimit import host_ratelimit, format_delay
from uffd.database import db
from uffd.secure_redirect import secure_local_redirect
from uffd.session.models import DeviceLoginConfirmation
from .models import OAuth2Client, OAuth2Grant, OAuth2Token, OAuth2DeviceLoginInitiation

oauth = OAuth2Provider()

@oauth.clientgetter
def load_client(client_id):
	return OAuth2Client.from_id(client_id)

@oauth.grantgetter
def load_grant(client_id, code):
	return OAuth2Grant.query.filter_by(client_id=client_id, code=code).first()

@oauth.grantsetter
def save_grant(client_id, code, oauthreq, *args, **kwargs): # pylint: disable=unused-argument
	expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=100)
	grant = OAuth2Grant(user_dn=request.oauth2_user.dn, client_id=client_id,
		code=code['code'], redirect_uri=oauthreq.redirect_uri, expires=expires, _scopes=' '.join(oauthreq.scopes))
	db.session.add(grant)
	db.session.commit()
	return grant

@oauth.tokengetter
def load_token(access_token=None, refresh_token=None):
	if access_token:
		return OAuth2Token.query.filter_by(access_token=access_token).first()
	if refresh_token:
		return OAuth2Token.query.filter_by(refresh_token=refresh_token).first()
	return None

@oauth.tokensetter
def save_token(token_data, oauthreq, *args, **kwargs): # pylint: disable=unused-argument
	OAuth2Token.query.filter_by(client_id=oauthreq.client.client_id, user_dn=oauthreq.user.dn).delete()
	expires_in = token_data.get('expires_in')
	expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_in)
	tok = OAuth2Token(
		user_dn=oauthreq.user.dn,
		client_id=oauthreq.client.client_id,
		token_type=token_data['token_type'],
		access_token=token_data['access_token'],
		refresh_token=token_data['refresh_token'],
		expires=expires,
		_scopes=' '.join(oauthreq.scopes)
	)
	db.session.add(tok)
	db.session.commit()
	return tok

bp = Blueprint('oauth2', __name__, url_prefix='/oauth2/', template_folder='templates')

@bp.record
def init(state):
	state.app.config.setdefault('OAUTH2_PROVIDER_ERROR_ENDPOINT', 'oauth2.error')
	oauth.init_app(state.app)

# flask-oauthlib has the bug to require the scope parameter for authorize
# requests, which is actually optional according to the OAuth2.0 spec.
# We don't really use scopes and this requirement just complicates the
# configuration of clients.
# See also: https://github.com/lepture/flask-oauthlib/pull/320
def inject_scope(func):
	@functools.wraps(func)
	def decorator(*args, **kwargs):
		args = request.args.to_dict()
		if not args.get('scope'):
			args['scope'] = 'profile'
			return redirect(request.base_url+'?'+urllib.parse.urlencode(args))
		return func(*args, **kwargs)
	return decorator

@bp.route('/authorize', methods=['GET', 'POST'])
@inject_scope
@oauth.authorize_handler
def authorize(*args, **kwargs): # pylint: disable=unused-argument
	client = kwargs['request'].client
	request.oauth2_user = None
	if request.user:
		request.oauth2_user = request.user
	elif 'devicelogin_started' in session:
		del session['devicelogin_started']
		host_delay = host_ratelimit.get_delay()
		if host_delay:
			flash(_('We received too many requests from your ip address/network! Please wait at least %(delay)s.', delay=format_delay(host_delay)))
			return redirect(url_for('session.login', ref=request.full_path, devicelogin=True))
		host_ratelimit.log()
		initiation = OAuth2DeviceLoginInitiation(oauth2_client_id=client.client_id)
		db.session.add(initiation)
		try:
			db.session.commit()
		except IntegrityError:
			flash(_('Device login is currently not available. Try again later!'))
			return redirect(url_for('session.login', ref=request.values['ref'], devicelogin=True))
		session['devicelogin_id'] = initiation.id
		session['devicelogin_secret'] = initiation.secret
		return redirect(url_for('session.devicelogin', ref=request.full_path))
	elif 'devicelogin_id' in session and 'devicelogin_secret' in session and 'devicelogin_confirmation' in session:
		initiation = OAuth2DeviceLoginInitiation.query.filter_by(id=session['devicelogin_id'], secret=session['devicelogin_secret'],
		                                                         oauth2_client_id=client.client_id).one_or_none()
		confirmation = DeviceLoginConfirmation.query.get(session['devicelogin_confirmation'])
		del session['devicelogin_id']
		del session['devicelogin_secret']
		del session['devicelogin_confirmation']
		if not initiation or initiation.expired or not confirmation:
			flash('Device login failed')
			return redirect(url_for('session.login', ref=request.full_path, devicelogin=True))
		request.oauth2_user = confirmation.user
		db.session.delete(initiation)
		db.session.commit()
	else:
		return redirect(url_for('session.login', ref=request.full_path, devicelogin=True))
	# Here we would normally ask the user, if he wants to give the requesting
	# service access to his data. Since we only have trusted services (the
	# clients defined in the server config), we don't ask for consent.
	session['oauth2-clients'] = session.get('oauth2-clients', [])
	if client.client_id not in session['oauth2-clients']:
		session['oauth2-clients'].append(client.client_id)
	return client.access_allowed(request.oauth2_user)

@bp.route('/token', methods=['GET', 'POST'])
@oauth.token_handler
def token():
	return None

@bp.route('/userinfo')
@oauth.require_oauth('profile')
def userinfo():
	user = request.oauth.user
	# We once exposed the entryUUID here as "ldap_uuid" until realising that it
	# can (and does!) change randomly and is therefore entirely useless as an
	# indentifier.
	return jsonify(
		id=user.uid,
		name=user.displayname,
		nickname=user.loginname,
		email=user.mail,
		ldap_dn=user.dn,
		groups=[group.name for group in user.groups]
	)

@bp.route('/error')
def error():
	args = dict(request.values)
	err = args.pop('error', 'unknown')
	error_description = args.pop('error_description', '')
	return render_template('oauth2/error.html', error=err, error_description=error_description, args=args)

@bp.app_url_defaults
def inject_logout_params(endpoint, values):
	if endpoint != 'oauth2.logout' or not session.get('oauth2-clients'):
		return
	values['client_ids'] = ','.join(session['oauth2-clients'])

@bp.route('/logout')
def logout():
	if not request.values.get('client_ids'):
		return secure_local_redirect(request.values.get('ref', '/'))
	client_ids = request.values['client_ids'].split(',')
	clients = [OAuth2Client.from_id(client_id) for client_id in client_ids]
	return render_template('oauth2/logout.html', clients=clients)

import datetime
import functools
import secrets

from flask import Blueprint, request, jsonify, render_template, session, redirect, url_for, flash, abort
import oauthlib.oauth2
from flask_babel import gettext as _
from sqlalchemy.exc import IntegrityError

from uffd.ratelimit import host_ratelimit, format_delay
from uffd.database import db
from uffd.secure_redirect import secure_local_redirect
from uffd.session.models import DeviceLoginConfirmation
from .models import OAuth2Client, OAuth2Grant, OAuth2Token, OAuth2DeviceLoginInitiation

class UffdRequestValidator(oauthlib.oauth2.RequestValidator):
	# Argument "oauthreq" is named "request" in superclass but this clashes with flask's "request" object
	# Arguments "token_value" and "token_data" are named "token" in superclass but this clashs with "token" endpoint
	# pylint: disable=arguments-differ,arguments-renamed,unused-argument,too-many-public-methods,abstract-method

	# In all cases (aside from validate_bearer_token), either validate_client_id or authenticate_client is called
	# before anything else. authenticate_client_id would be called instead of authenticate_client for non-confidential
	# clients. However, we don't support those.
	def validate_client_id(self, client_id, oauthreq, *args, **kwargs):
		try:
			oauthreq.client = OAuth2Client.from_id(client_id)
			return True
		except KeyError:
			return False

	def authenticate_client(self, oauthreq, *args, **kwargs):
		if oauthreq.client_secret is None:
			return False
		try:
			oauthreq.client = OAuth2Client.from_id(oauthreq.client_id)
		except KeyError:
			return False
		return secrets.compare_digest(oauthreq.client.client_secret, oauthreq.client_secret)

	def get_default_redirect_uri(self, client_id, oauthreq, *args, **kwargs):
		return oauthreq.client.default_redirect_uri

	def validate_redirect_uri(self, client_id, redirect_uri, oauthreq, *args, **kwargs):
		return redirect_uri in oauthreq.client.redirect_uris

	def validate_response_type(self, client_id, response_type, client, oauthreq, *args, **kwargs):
		return response_type == 'code'

	def get_default_scopes(self, client_id, oauthreq, *args, **kwargs):
		return oauthreq.client.default_scopes

	def validate_scopes(self, client_id, scopes, client, oauthreq, *args, **kwargs):
		return set(scopes).issubset({'profile'})

	def save_authorization_code(self, client_id, code, oauthreq, *args, **kwargs):
		expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=100)
		grant = OAuth2Grant(user_dn=oauthreq.user.dn, client_id=client_id, code=code['code'],
		                    redirect_uri=oauthreq.redirect_uri, expires=expires, _scopes=' '.join(oauthreq.scopes))
		db.session.add(grant)
		db.session.commit()

	def validate_code(self, client_id, code, client, oauthreq, *args, **kwargs):
		oauthreq.grant = OAuth2Grant.query.filter_by(client_id=client_id, code=code).first()
		if not oauthreq.grant:
			return False
		if datetime.datetime.utcnow() > oauthreq.grant.expires:
			return False
		oauthreq.user = oauthreq.grant.user
		oauthreq.scopes = oauthreq.grant.scopes
		return True

	def invalidate_authorization_code(self, client_id, code, oauthreq, *args, **kwargs):
		OAuth2Grant.query.filter_by(client_id=client_id, code=code).delete()
		db.session.commit()

	def save_bearer_token(self, token_data, oauthreq, *args, **kwargs):
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
		return oauthreq.client.default_redirect_uri

	def validate_grant_type(self, client_id, grant_type, client, oauthreq, *args, **kwargs):
		return grant_type == 'authorization_code'

	def confirm_redirect_uri(self, client_id, code, redirect_uri, client, oauthreq, *args, **kwargs):
		return redirect_uri == oauthreq.grant.redirect_uri

	def validate_bearer_token(self, token_value, scopes, oauthreq):
		tok = OAuth2Token.query.filter_by(access_token=token_value).first()
		if not tok:
			return False
		if datetime.datetime.utcnow() > tok.expires:
			oauthreq.error_message = 'Token expired'
			return False
		if not set(scopes).issubset(tok.scopes):
			oauthreq.error_message = 'Scopes invalid'
			return False
		oauthreq.access_token = tok
		oauthreq.user = tok.user
		oauthreq.scopes = scopes
		oauthreq.client = tok.client
		oauthreq.client_id = tok.client_id
		return True

	# get_original_scopes/validate_refresh_token are only used for refreshing tokens. We don't implement the refresh endpoint.
	# revoke_token is only used for revoking access tokens. We don't implement the revoke endpoint.
	# get_id_token/validate_silent_authorization/validate_silent_login are OpenID Connect specfic.
	# validate_user/validate_user_match are not required for Authorization Code Grant flow.

validator = UffdRequestValidator()
server = oauthlib.oauth2.WebApplicationServer(validator)
bp = Blueprint('oauth2', __name__, url_prefix='/oauth2/', template_folder='templates')

def display_oauth_errors(func):
	@functools.wraps(func)
	def decorator(*args, **kwargs):
		try:
			return func(*args, **kwargs)
		except oauthlib.oauth2.rfc6749.errors.OAuth2Error as ex:
			return render_template('oauth2/error.html', error=type(ex).__name__, error_description=ex.description), 400
	return decorator

@bp.route('/authorize', methods=['GET', 'POST'])
@display_oauth_errors
def authorize():
	scopes, credentials = server.validate_authorization_request(request.url, request.method, request.form, request.headers)
	client = OAuth2Client.from_id(credentials['client_id'])

	if request.user:
		credentials['user'] = request.user
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
		credentials['user'] = confirmation.user
		db.session.delete(initiation)
		db.session.commit()
	else:
		return redirect(url_for('session.login', ref=request.full_path, devicelogin=True))

	# Here we would normally ask the user, if he wants to give the requesting
	# service access to his data. Since we only have trusted services (the
	# clients defined in the server config), we don't ask for consent.
	if not client.access_allowed(credentials['user']):
		raise oauthlib.oauth2.rfc6749.errors.AccessDeniedError('User is not permitted to authenticate with this service.')
	session['oauth2-clients'] = session.get('oauth2-clients', [])
	if client.client_id not in session['oauth2-clients']:
		session['oauth2-clients'].append(client.client_id)

	headers, body, status = server.create_authorization_response(request.url, request.method, request.form, request.headers, scopes, credentials)
	return body or '', status, headers

@bp.route('/token', methods=['GET', 'POST'])
def token():
	headers, body, status = server.create_token_response(request.url, request.method, request.form, request.headers)
	return body, status, headers

def oauth_required(*scopes):
	def wrapper(func):
		@functools.wraps(func)
		def decorator(*args, **kwargs):
			valid, oauthreq = server.verify_request(request.url, request.method, request.form, request.headers, scopes)
			if not valid:
				abort(401)
			request.oauth = oauthreq
			return func(*args, **kwargs)
		return decorator
	return wrapper

@bp.route('/userinfo')
@oauth_required('profile')
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

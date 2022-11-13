import functools
import secrets
import urllib.parse

from flask import Blueprint, request, jsonify, render_template, session, redirect, url_for, flash, abort
import oauthlib.oauth2
from flask_babel import gettext as _
from sqlalchemy.exc import IntegrityError

from uffd.secure_redirect import secure_local_redirect
from uffd.database import db
from uffd.models import DeviceLoginConfirmation, OAuth2Client, OAuth2Grant, OAuth2Token, OAuth2DeviceLoginInitiation, host_ratelimit, format_delay, ServiceUser

class UffdRequestValidator(oauthlib.oauth2.RequestValidator):
	# Argument "oauthreq" is named "request" in superclass but this clashes with flask's "request" object
	# Arguments "token_value" and "token_data" are named "token" in superclass but this clashs with "token" endpoint
	# pylint: disable=arguments-differ,arguments-renamed,unused-argument,too-many-public-methods,abstract-method

	# In all cases (aside from validate_bearer_token), either validate_client_id or authenticate_client is called
	# before anything else. authenticate_client_id would be called instead of authenticate_client for non-confidential
	# clients. However, we don't support those.
	def validate_client_id(self, client_id, oauthreq, *args, **kwargs):
		oauthreq.client = OAuth2Client.query.filter_by(client_id=client_id).one_or_none()
		return oauthreq.client is not None

	def authenticate_client(self, oauthreq, *args, **kwargs):
		authorization = oauthreq.extra_credentials.get('authorization')
		if authorization:
			# From RFC6749 2.3.1:
			# Clients in possession of a client password MAY use the HTTP Basic authentication
			# scheme as defined in [RFC2617] to authenticate with the authorization server.
			# The client identifier is encoded using the "application/x-www-form-urlencoded"
			# encoding algorithm per Appendix B, and the encoded value is used as the username
			# the client password is encoded using the same algorithm and used as the password.
			oauthreq.client_id = urllib.parse.unquote(authorization.username)
			oauthreq.client_secret = urllib.parse.unquote(authorization.password)
		if oauthreq.client_secret is None:
			return False
		oauthreq.client = OAuth2Client.query.filter_by(client_id=oauthreq.client_id).one_or_none()
		if oauthreq.client is None:
			return False
		if not oauthreq.client.client_secret.verify(oauthreq.client_secret):
			return False
		if oauthreq.client.client_secret.needs_rehash:
			oauthreq.client.client_secret = oauthreq.client_secret
			db.session.commit()
		return True

	def get_default_redirect_uri(self, client_id, oauthreq, *args, **kwargs):
		return oauthreq.client.default_redirect_uri

	def validate_redirect_uri(self, client_id, redirect_uri, oauthreq, *args, **kwargs):
		return redirect_uri in oauthreq.client.redirect_uris

	def validate_response_type(self, client_id, response_type, client, oauthreq, *args, **kwargs):
		return response_type == 'code'

	def get_default_scopes(self, client_id, oauthreq, *args, **kwargs):
		return oauthreq.client.default_scopes

	def validate_scopes(self, client_id, scopes, client, oauthreq, *args, **kwargs):
		if scopes == ['']:
			oauthreq.scopes = scopes = self.get_default_scopes(client_id, oauthreq)
		return set(scopes).issubset({'profile'})

	def save_authorization_code(self, client_id, code, oauthreq, *args, **kwargs):
		grant = OAuth2Grant(user=oauthreq.user, client=oauthreq.client, code=code['code'],
		                    redirect_uri=oauthreq.redirect_uri, scopes=oauthreq.scopes)
		db.session.add(grant)
		db.session.commit()
		# Oauthlib does not really provide a way to customize grant code generation.
		# Actually `code` is created just before `save_authorization_code` is called
		# and the same dict is later used to generate the OAuth2 response. So by
		# modifing the `code` dict we can actually influence the grant code.
		code['code'] = f"{grant.id}-{code['code']}"

	def validate_code(self, client_id, code, client, oauthreq, *args, **kwargs):
		if '-' not in code:
			return False
		grant_id, grant_code = code.split('-', 2)
		oauthreq.grant = OAuth2Grant.query.get(grant_id)
		if not oauthreq.grant or oauthreq.grant.client != client:
			return False
		if not secrets.compare_digest(oauthreq.grant.code, grant_code):
			return False
		if oauthreq.grant.expired:
			return False
		if oauthreq.grant.user.is_deactivated:
			return False
		oauthreq.user = oauthreq.grant.user
		oauthreq.scopes = oauthreq.grant.scopes
		return True

	def invalidate_authorization_code(self, client_id, code, oauthreq, *args, **kwargs):
		OAuth2Grant.query.filter_by(client=oauthreq.client, code=code).delete()
		db.session.commit()

	def save_bearer_token(self, token_data, oauthreq, *args, **kwargs):
		tok = OAuth2Token(
			user=oauthreq.user,
			client=oauthreq.client,
			token_type=token_data['token_type'],
			access_token=token_data['access_token'],
			refresh_token=token_data['refresh_token'],
			expires_in_seconds=token_data['expires_in'],
			scopes=oauthreq.scopes
		)
		db.session.add(tok)
		db.session.commit()
		# Oauthlib does not really provide a way to customize access/refresh token
		# generation. Actually `token_data` is created just before
		# `save_bearer_token` is called and the same dict is later used to generate
		# the OAuth2 response. So by modifing the `token_data` dict we can actually
		# influence the tokens.
		token_data['access_token'] = f"{tok.id}-{token_data['access_token']}"
		token_data['refresh_token'] = f"{tok.id}-{token_data['refresh_token']}"
		return oauthreq.client.default_redirect_uri

	def validate_grant_type(self, client_id, grant_type, client, oauthreq, *args, **kwargs):
		return grant_type == 'authorization_code'

	def confirm_redirect_uri(self, client_id, code, redirect_uri, client, oauthreq, *args, **kwargs):
		return redirect_uri == oauthreq.grant.redirect_uri

	def validate_bearer_token(self, token_value, scopes, oauthreq):
		if '-' not in token_value:
			return False
		tok_id, tok_secret = token_value.split('-', 2)
		tok = OAuth2Token.query.get(tok_id)
		if not tok or not secrets.compare_digest(tok.access_token, tok_secret):
			return False
		if tok.expired:
			oauthreq.error_message = 'Token expired'
			return False
		if tok.user.is_deactivated:
			oauthreq.error_message = 'User deactivated'
			return False
		if not set(scopes).issubset(tok.scopes):
			oauthreq.error_message = 'Scopes invalid'
			return False
		oauthreq.access_token = tok
		oauthreq.user = tok.user
		oauthreq.scopes = scopes
		oauthreq.client = tok.client
		oauthreq.client_id = oauthreq.client.client_id
		return True

	# get_original_scopes/validate_refresh_token are only used for refreshing tokens. We don't implement the refresh endpoint.
	# revoke_token is only used for revoking access tokens. We don't implement the revoke endpoint.
	# get_id_token/validate_silent_authorization/validate_silent_login are OpenID Connect specfic.
	# validate_user/validate_user_match are not required for Authorization Code Grant flow.

validator = UffdRequestValidator()
server = oauthlib.oauth2.WebApplicationServer(validator)
bp = Blueprint('oauth2', __name__, url_prefix='/oauth2/', template_folder='templates')

@bp.errorhandler(oauthlib.oauth2.rfc6749.errors.OAuth2Error)
def handle_oauth2error(error):
	return render_template('oauth2/error.html', error=type(error).__name__, error_description=error.description), 400

@bp.route('/authorize', methods=['GET', 'POST'])
def authorize():
	scopes, credentials = server.validate_authorization_request(request.url, request.method, request.form, request.headers)
	client = OAuth2Client.query.filter_by(client_id=credentials['client_id']).one()

	if request.user:
		credentials['user'] = request.user
	elif 'devicelogin_started' in session:
		del session['devicelogin_started']
		host_delay = host_ratelimit.get_delay()
		if host_delay:
			flash(_('We received too many requests from your ip address/network! Please wait at least %(delay)s.', delay=format_delay(host_delay)))
			return redirect(url_for('session.login', ref=request.full_path, devicelogin=True))
		host_ratelimit.log()
		initiation = OAuth2DeviceLoginInitiation(client=client)
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
		                                                         client=client).one_or_none()
		confirmation = DeviceLoginConfirmation.query.get(session['devicelogin_confirmation'])
		del session['devicelogin_id']
		del session['devicelogin_secret']
		del session['devicelogin_confirmation']
		if not initiation or initiation.expired or not confirmation or confirmation.user.is_deactivated:
			flash(_('Device login failed'))
			return redirect(url_for('session.login', ref=request.full_path, devicelogin=True))
		credentials['user'] = confirmation.user
		db.session.delete(initiation)
		db.session.commit()
	else:
		flash(_('You need to login to access this service'))
		return redirect(url_for('session.login', ref=request.full_path, devicelogin=True))

	# Here we would normally ask the user, if he wants to give the requesting
	# service access to his data. Since we only have trusted services (the
	# clients defined in the server config), we don't ask for consent.
	if not client.access_allowed(credentials['user']):
		abort(403, description=_("You don't have the permission to access the service <b>%(service_name)s</b>.", service_name=client.service.name))
	session['oauth2-clients'] = session.get('oauth2-clients', [])
	if client.client_id not in session['oauth2-clients']:
		session['oauth2-clients'].append(client.client_id)

	headers, body, status = server.create_authorization_response(request.url, request.method, request.form, request.headers, scopes, credentials)
	return body or '', status, headers

@bp.route('/token', methods=['GET', 'POST'])
def token():
	headers, body, status = server.create_token_response(request.url, request.method, request.form,
	                                                     request.headers, {'authorization': request.authorization})
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
	service_user = ServiceUser.query.get((request.oauth.client.service_id, request.oauth.user.id))
	return jsonify(
		id=service_user.user.unix_uid,
		name=service_user.user.displayname,
		nickname=service_user.user.loginname,
		email=service_user.email,
		groups=[group.name for group in service_user.user.groups]
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
	clients = [OAuth2Client.query.filter_by(client_id=client_id).one() for client_id in client_ids]
	return render_template('oauth2/logout.html', clients=clients)

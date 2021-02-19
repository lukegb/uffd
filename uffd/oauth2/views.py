import datetime
import functools
import urllib.parse

from flask import Blueprint, request, jsonify, render_template, session, redirect

from flask_oauthlib.provider import OAuth2Provider

from uffd.database import db
from uffd.session.views import get_current_user, login_required
from .models import OAuth2Client, OAuth2Grant, OAuth2Token

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
	grant = OAuth2Grant(user_dn=get_current_user().dn, client_id=client_id,
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
@login_required()
@inject_scope
@oauth.authorize_handler
def authorize(*args, **kwargs): # pylint: disable=unused-argument
	# Here we would normally ask the user, if he wants to give the requesting
	# service access to his data. Since we only have trusted services (the
	# clients defined in the server config), we don't ask for consent.
	client = kwargs['request'].client
	session['oauth2-clients'] = session.get('oauth2-clients', [])
	if client.client_id not in session['oauth2-clients']:
		session['oauth2-clients'].append(client.client_id)
	return client.access_allowed(get_current_user())

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
	return render_template('error.html', error=err, error_description=error_description, args=args)

@bp.app_url_defaults
def inject_logout_params(endpoint, values):
	if endpoint != 'oauth2.logout' or not session.get('oauth2-clients'):
		return
	values['client_ids'] = ','.join(session['oauth2-clients'])

@bp.route('/logout')
def logout():
	if not request.values.get('client_ids'):
		return redirect(request.values.get('ref', '/'))
	client_ids = request.values['client_ids'].split(',')
	clients = [OAuth2Client.from_id(client_id) for client_id in client_ids]
	return render_template('logout.html', clients=clients)

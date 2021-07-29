from warnings import warn
import urllib.parse

from flask import Blueprint, render_template, session, request, redirect, url_for, flash, current_app, abort
from flask_babel import gettext as _

from uffd.database import db
from uffd.ldap import ldap
from uffd.mfa.models import MFAMethod, TOTPMethod, WebauthnMethod, RecoveryCodeMethod
from uffd.session.views import login_required, login_required_pre_mfa, set_request_user
from uffd.user.models import User
from uffd.csrf import csrf_protect
from uffd.secure_redirect import secure_local_redirect
from uffd.ratelimit import Ratelimit, format_delay

bp = Blueprint('mfa', __name__, template_folder='templates', url_prefix='/mfa/')

mfa_ratelimit = Ratelimit('mfa', 1*60, 3)

@bp.route('/', methods=['GET'])
@login_required()
def setup():
	return render_template('mfa/setup.html')

@bp.route('/setup/disable', methods=['GET'])
@login_required()
def disable():
	return render_template('mfa/disable.html')

@bp.route('/setup/disable', methods=['POST'])
@login_required()
@csrf_protect(blueprint=bp)
def disable_confirm():
	MFAMethod.query.filter_by(dn=request.user.dn).delete()
	db.session.commit()
	request.user.update_groups()
	ldap.session.commit()
	return redirect(url_for('mfa.setup'))

@bp.route('/admin/<int:uid>/disable')
@login_required()
@csrf_protect(blueprint=bp)
def admin_disable(uid):
	# Group cannot be checked with login_required kwarg, because the config
	# variable is not available when the decorator is processed
	if not request.user.is_in_group(current_app.config['ACL_ADMIN_GROUP']):
		flash('Access denied')
		return redirect(url_for('index'))
	user = User.query.filter_by(uid=uid).one()
	MFAMethod.query.filter_by(dn=user.dn).delete()
	db.session.commit()
	user.update_groups()
	ldap.session.commit()
	flash(_('Two-factor authentication was reset'))
	return redirect(url_for('user.show', uid=uid))

@bp.route('/setup/recovery', methods=['POST'])
@login_required()
@csrf_protect(blueprint=bp)
def setup_recovery():
	for method in RecoveryCodeMethod.query.filter_by(dn=request.user.dn).all():
		db.session.delete(method)
	methods = []
	for _ in range(10):
		method = RecoveryCodeMethod(request.user)
		methods.append(method)
		db.session.add(method)
	db.session.commit()
	return render_template('mfa/setup_recovery.html', methods=methods)

@bp.route('/setup/totp', methods=['GET'])
@login_required()
def setup_totp():
	method = TOTPMethod(request.user)
	session['mfa_totp_key'] = method.key
	return render_template('mfa/setup_totp.html', method=method, name=request.values['name'])

@bp.route('/setup/totp', methods=['POST'])
@login_required()
@csrf_protect(blueprint=bp)
def setup_totp_finish():
	if not RecoveryCodeMethod.query.filter_by(dn=request.user.dn).all():
		flash(_('Generate recovery codes first!'))
		return redirect(url_for('mfa.setup'))
	method = TOTPMethod(request.user, name=request.values['name'], key=session.pop('mfa_totp_key'))
	if method.verify(request.form['code']):
		db.session.add(method)
		db.session.commit()
		request.user.update_groups()
		ldap.session.commit()
		return redirect(url_for('mfa.setup'))
	flash(_('Code is invalid'))
	return redirect(url_for('mfa.setup_totp', name=request.values['name']))

@bp.route('/setup/totp/<int:id>/delete')
@login_required()
@csrf_protect(blueprint=bp)
def delete_totp(id): #pylint: disable=redefined-builtin
	method = TOTPMethod.query.filter_by(dn=request.user.dn, id=id).first_or_404()
	db.session.delete(method)
	db.session.commit()
	request.user.update_groups()
	ldap.session.commit()
	return redirect(url_for('mfa.setup'))

# WebAuthn support is optional because fido2 has a pretty unstable
# interface (v0.5.0 on buster and current version are completely
# incompatible) and might be difficult to install with the correct version
try:
	from fido2.client import ClientData
	from fido2.server import Fido2Server, RelyingParty
	from fido2.ctap2 import AttestationObject, AuthenticatorData
	from fido2 import cbor
	WEBAUTHN_SUPPORTED = True
except ImportError as err:
	warn(_('2FA WebAuthn support disabled because import of the fido2 module failed (%s)')%err)
	WEBAUTHN_SUPPORTED = False

bp.add_app_template_global(WEBAUTHN_SUPPORTED, name='webauthn_supported')

if WEBAUTHN_SUPPORTED:
	def get_webauthn_server():
		return Fido2Server(RelyingParty(current_app.config.get('MFA_RP_ID', urllib.parse.urlsplit(request.url).hostname), current_app.config['MFA_RP_NAME']))

	@bp.route('/setup/webauthn/begin', methods=['POST'])
	@login_required()
	@csrf_protect(blueprint=bp)
	def setup_webauthn_begin():
		if not RecoveryCodeMethod.query.filter_by(dn=request.user.dn).all():
			abort(403)
		methods = WebauthnMethod.query.filter_by(dn=request.user.dn).all()
		creds = [method.cred for method in methods]
		server = get_webauthn_server()
		registration_data, state = server.register_begin(
			{
				"id": request.user.dn.encode(),
				"name": request.user.loginname,
				"displayName": request.user.displayname,
			},
			creds,
			user_verification='discouraged',
		)
		session["webauthn-state"] = state
		return cbor.dumps(registration_data)

	@bp.route('/setup/webauthn/complete', methods=['POST'])
	@login_required()
	@csrf_protect(blueprint=bp)
	def setup_webauthn_complete():
		server = get_webauthn_server()
		data = cbor.loads(request.get_data())[0]
		client_data = ClientData(data["clientDataJSON"])
		att_obj = AttestationObject(data["attestationObject"])
		auth_data = server.register_complete(session["webauthn-state"], client_data, att_obj)
		method = WebauthnMethod(request.user, auth_data.credential_data, name=data['name'])
		db.session.add(method)
		db.session.commit()
		request.user.update_groups()
		ldap.session.commit()
		return cbor.dumps({"status": "OK"})

	@bp.route("/auth/webauthn/begin", methods=["POST"])
	@login_required_pre_mfa(no_redirect=True)
	def auth_webauthn_begin():
		server = get_webauthn_server()
		creds = [method.cred for method in request.user_pre_mfa.mfa_webauthn_methods]
		if not creds:
			abort(404)
		auth_data, state = server.authenticate_begin(creds, user_verification='discouraged')
		session["webauthn-state"] = state
		return cbor.dumps(auth_data)

	@bp.route("/auth/webauthn/complete", methods=["POST"])
	@login_required_pre_mfa(no_redirect=True)
	def auth_webauthn_complete():
		server = get_webauthn_server()
		creds = [method.cred for method in request.user_pre_mfa.mfa_webauthn_methods]
		if not creds:
			abort(404)
		data = cbor.loads(request.get_data())[0]
		credential_id = data["credentialId"]
		client_data = ClientData(data["clientDataJSON"])
		auth_data = AuthenticatorData(data["authenticatorData"])
		signature = data["signature"]
		# authenticate_complete() (as of python-fido2 v0.5.0, the version in Debian Buster)
		# does not check signCount, although the spec recommends it
		server.authenticate_complete(
			session.pop("webauthn-state"),
			creds,
			credential_id,
			client_data,
			auth_data,
			signature,
		)
		session['user_mfa'] = True
		set_request_user()
		return cbor.dumps({"status": "OK"})

@bp.route('/setup/webauthn/<int:id>/delete')
@login_required()
@csrf_protect(blueprint=bp)
def delete_webauthn(id): #pylint: disable=redefined-builtin
	method = WebauthnMethod.query.filter_by(dn=request.user.dn, id=id).first_or_404()
	db.session.delete(method)
	db.session.commit()
	request.user.update_groups()
	ldap.session.commit()
	return redirect(url_for('mfa.setup'))

@bp.route('/auth', methods=['GET'])
@login_required_pre_mfa()
def auth():
	if not request.user_pre_mfa.mfa_enabled:
		session['user_mfa'] = True
		set_request_user()
	if session.get('user_mfa'):
		return secure_local_redirect(request.values.get('ref', url_for('index')))
	return render_template('mfa/auth.html', ref=request.values.get('ref'))

@bp.route('/auth', methods=['POST'])
@login_required_pre_mfa()
def auth_finish():
	delay = mfa_ratelimit.get_delay(request.user_pre_mfa.dn)
	if delay:
		flash(_('We received too many invalid attempts! Please wait at least %s.')%format_delay(delay))
		return redirect(url_for('mfa.auth', ref=request.values.get('ref')))
	for method in request.user_pre_mfa.mfa_totp_methods:
		if method.verify(request.form['code']):
			session['user_mfa'] = True
			set_request_user()
			return secure_local_redirect(request.values.get('ref', url_for('index')))
	for method in request.user_pre_mfa.mfa_recovery_codes:
		if method.verify(request.form['code']):
			db.session.delete(method)
			db.session.commit()
			session['user_mfa'] = True
			set_request_user()
			if len(request.user_pre_mfa.mfa_recovery_codes) <= 1:
				flash(_('You have exhausted your recovery codes. Please generate new ones now!'))
				return redirect(url_for('mfa.setup'))
			if len(request.user_pre_mfa.mfa_recovery_codes) <= 5:
				flash(_('You only have a few recovery codes remaining. Make sure to generate new ones before they run out.'))
				return redirect(url_for('mfa.setup'))
			return secure_local_redirect(request.values.get('ref', url_for('index')))
	mfa_ratelimit.log(request.user_pre_mfa.dn)
	flash(_('Two-factor authentication failed'))
	return redirect(url_for('mfa.auth', ref=request.values.get('ref')))

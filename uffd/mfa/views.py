from flask import Blueprint, render_template, session, request, redirect, url_for, flash, current_app
import urllib.parse

from fido2.webauthn import PublicKeyCredentialRpEntity, UserVerificationRequirement
from fido2.client import ClientData
from fido2.server import Fido2Server
from fido2.ctap2 import AttestationObject, AuthenticatorData
from fido2 import cbor

from uffd.database import db
from uffd.mfa.models import MFAMethod, TOTPMethod, WebauthnMethod, RecoveryCodeMethod
from uffd.session.views import get_current_user, login_required, is_valid_session
from uffd.ldap import uid_to_dn
from uffd.user.models import User
from uffd.csrf import csrf_protect

bp = Blueprint('mfa', __name__, template_folder='templates', url_prefix='/mfa/')

@bp.route('/', methods=['GET'])
@login_required()
def setup():
	user = get_current_user()
	recovery_methods = RecoveryCodeMethod.query.filter_by(dn=user.dn).all()
	totp_methods = TOTPMethod.query.filter_by(dn=user.dn).all()
	webauthn_methods = WebauthnMethod.query.filter_by(dn=user.dn).all()
	return render_template('setup.html', totp_methods=totp_methods, webauthn_methods=webauthn_methods, recovery_methods=recovery_methods)

@bp.route('/setup/disable', methods=['GET'])
@login_required()
def disable():
	return render_template('disable.html')

@bp.route('/setup/disable', methods=['POST'])
@login_required()
@csrf_protect(blueprint=bp)
def disable_confirm():
	user = get_current_user()
	MFAMethod.query.filter_by(dn=user.dn).delete()
	db.session.commit()
	return redirect(url_for('mfa.setup'))

@bp.route('/admin/<int:uid>/disable')
@login_required()
@csrf_protect(blueprint=bp)
def admin_disable(uid):
	# Group cannot be checked with login_required kwarg, because the config
	# variable is not available when the decorator is processed
	if not get_current_user().is_in_group(current_app.config['ACL_ADMIN_GROUP']):
		flash('Access denied')
		return redirect(url_for('index'))
	user = User.from_ldap_dn(uid_to_dn(uid))
	MFAMethod.query.filter_by(dn=user.dn).delete()
	db.session.commit()
	flash('Two-factor authentication was reset')
	return redirect(url_for('user.show', uid=uid))

@bp.route('/setup/recovery', methods=['POST'])
@login_required()
@csrf_protect(blueprint=bp)
def setup_recovery():
	user = get_current_user()
	for method in RecoveryCodeMethod.query.filter_by(dn=user.dn).all():
		db.session.delete(method)
	methods = []
	for _ in range(10):
		method = RecoveryCodeMethod(user)
		methods.append(method)
		db.session.add(method)
	db.session.commit()
	return render_template('setup_recovery.html', methods=methods)

@bp.route('/setup/totp', methods=['GET'])
@login_required()
def setup_totp():
	user = get_current_user()
	method = TOTPMethod(user)
	session['mfa_totp_key'] = method.key
	return render_template('setup_totp.html', method=method, name=request.values['name'])

@bp.route('/setup/totp', methods=['POST'])
@login_required()
@csrf_protect(blueprint=bp)
def setup_totp_finish():
	user = get_current_user()
	if not RecoveryCodeMethod.query.filter_by(dn=user.dn).all():
		flash('Generate recovery codes first!')
		return redirect(url_for('mfa.setup'))
	method = TOTPMethod(user, name=request.values['name'], key=session.pop('mfa_totp_key'))
	if method.verify(request.form['code']):
		db.session.add(method)
		db.session.commit()
		return redirect(url_for('mfa.setup'))
	flash('Code is invalid')
	return redirect(url_for('mfa.setup_totp'))

@bp.route('/setup/totp/<int:id>/delete')
@login_required()
@csrf_protect(blueprint=bp)
def delete_totp(id):
	user = get_current_user()
	method = TOTPMethod.query.filter_by(dn=user.dn, id=id).first_or_404()
	db.session.delete(method)
	db.session.commit()
	return redirect(url_for('mfa.setup'))

def get_webauthn_server():
	return Fido2Server(PublicKeyCredentialRpEntity(urllib.parse.urlsplit(request.url).hostname, "uffd"))

@bp.route('/setup/webauthn/begin', methods=['POST'])
@login_required()
@csrf_protect(blueprint=bp)
def setup_webauthn_begin():
	user = get_current_user()
	if not RecoveryCodeMethod.query.filter_by(dn=user.dn).all():
		abort(403)
	methods = WebauthnMethod.query.filter_by(dn=user.dn).all()
	creds = [method.cred_data.credential_data for method in methods]
	server = get_webauthn_server()
	registration_data, state = server.register_begin(
		{
			"id": user.loginname.encode(),
			"name": user.loginname,
			"displayName": user.displayname,
		},
		creds,
		user_verification=UserVerificationRequirement.DISCOURAGED,
		authenticator_attachment="cross-platform",
	)
	session["webauthn-state"] = state
	return cbor.encode(registration_data)

@bp.route('/setup/webauthn/complete', methods=['POST'])
@login_required()
@csrf_protect(blueprint=bp)
def setup_webauthn_complete():
	user = get_current_user()
	server = get_webauthn_server()
	data = cbor.decode(request.get_data())
	client_data = ClientData(data["clientDataJSON"])
	att_obj = AttestationObject(data["attestationObject"])
	auth_data = server.register_complete(session["webauthn-state"], client_data, att_obj)
	method = WebauthnMethod(user, auth_data, name=data['name'])
	db.session.add(method)
	db.session.commit()
	print("REGISTERED CREDENTIAL:", auth_data.credential_data)
	return cbor.encode({"status": "OK"})

@bp.route('/setup/webauthn/<int:id>/delete')
@login_required()
@csrf_protect(blueprint=bp)
def delete_webauthn(id):
	user = get_current_user()
	method = WebauthnMethod.query.filter_by(dn=user.dn, id=id).first_or_404()
	db.session.delete(method)
	db.session.commit()
	return redirect(url_for('mfa.setup'))

@bp.route("/auth/webauthn/begin", methods=["POST"])
def auth_webauthn_begin():
	user = get_current_user()
	server = get_webauthn_server()
	methods = WebauthnMethod.query.filter_by(dn=user.dn).all()
	creds = [method.cred_data.credential_data for method in methods]
	if not creds:
		abort(404)
	auth_data, state = server.authenticate_begin(creds, user_verification=UserVerificationRequirement.DISCOURAGED)
	session["webauthn-state"] = state
	return cbor.encode(auth_data)

@bp.route("/auth/webauthn/complete", methods=["POST"])
def auth_webauthn_complete():
	user = get_current_user()
	server = get_webauthn_server()
	methods = WebauthnMethod.query.filter_by(dn=user.dn).all()
	creds = [method.cred_data.credential_data for method in methods]
	if not creds:
		abort(404)
	data = cbor.decode(request.get_data())
	credential_id = data["credentialId"]
	client_data = ClientData(data["clientDataJSON"])
	auth_data = AuthenticatorData(data["authenticatorData"])
	signature = data["signature"]
	server.authenticate_complete(
		session.pop("webauthn-state"),
		creds,
		credential_id,
		client_data,
		auth_data,
		signature,
	)
	session['user_mfa'] = True
	return cbor.encode({"status": "OK"})

@bp.route('/auth', methods=['GET'])
@login_required(skip_mfa=True)
def auth():
	user = get_current_user()
	recovery_methods = RecoveryCodeMethod.query.filter_by(dn=user.dn).all()
	totp_methods = TOTPMethod.query.filter_by(dn=user.dn).all()
	webauthn_methods = WebauthnMethod.query.filter_by(dn=user.dn).all()
	if not totp_methods and not webauthn_methods:
		session['user_mfa'] = True
	if session.get('user_mfa'):
		return redirect(request.values.get('ref', url_for('index')))
	return render_template('auth.html', ref=request.values.get('ref'), totp_methods=totp_methods,
			webauthn_methods=webauthn_methods, recovery_methods=recovery_methods)

@bp.route('/auth', methods=['POST'])
@login_required(skip_mfa=True)
def auth_finish():
	user = get_current_user()
	recovery_methods = RecoveryCodeMethod.query.filter_by(dn=user.dn).all()
	totp_methods = TOTPMethod.query.filter_by(dn=user.dn).all()
	for method in totp_methods:
		if method.verify(request.form['code']):
			session['user_mfa'] = True
			return redirect(request.values.get('ref', url_for('index')))
	for method in recovery_methods:
		if method.verify(request.form['code']):
			db.session.delete(method)
			db.session.commit()
			session['user_mfa'] = True
			if len(recovery_methods) <= 1:
				flash('You have exhausted your recovery codes. Please generate new ones now!')
				return redirect(url_for('mfa.setup'))
			elif len(recovery_methods) <= 5:
				flash('You only have a few recovery codes remaining. Make sure to generate new ones before they run out.')
				return redirect(url_for('mfa.setup'))
			return redirect(request.values.get('ref', url_for('index')))
	flash('Two-factor authentication failed')
	return redirect(url_for('mfa.auth', ref=request.values.get('ref')))

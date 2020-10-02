from flask import Blueprint, render_template, session, request, redirect, url_for, flash
import urllib.parse

from fido2.webauthn import PublicKeyCredentialRpEntity, UserVerificationRequirement
from fido2.client import ClientData
from fido2.server import Fido2Server
from fido2.ctap2 import AttestationObject, AuthenticatorData
from fido2 import cbor

from uffd.database import db
from uffd.mfa.models import TOTPMethod, WebauthnMethod
from uffd.session.views import get_current_user, login_required

bp = Blueprint('mfa', __name__, template_folder='templates', url_prefix='/mfa/')

@bp.route('/', methods=['GET'])
@login_required()
def setup():
	user = get_current_user()
	totp_methods = TOTPMethod.query.filter_by(dn=user.dn).all()
	webauthn_methods = WebauthnMethod.query.filter_by(dn=user.dn).all()
	return render_template('setup.html', totp_methods=totp_methods, webauthn_methods=webauthn_methods)

@bp.route('/setup/totp', methods=['GET'])
@login_required()
def setup_totp():
	user = get_current_user()
	method = TOTPMethod(user)
	session['mfa_totp_key'] = method.key
	return render_template('setup_totp.html', method=method)

@bp.route('/setup/totp', methods=['POST'])
@login_required()
def setup_totp_finish():
	user = get_current_user()
	method = TOTPMethod(user, name=request.form['name'], key=session['mfa_totp_key'])
	del session['mfa_totp_key']
	if method.verify(request.form['code']):
		db.session.add(method)
		db.session.commit()
		return redirect(url_for('mfa.setup'))
	flash('Code is invalid')
	return redirect(url_for('mfa.setup_totp'))

@bp.route('/setup/totp/<int:id>/delete')
@login_required()
def delete_totp(id):
	user = get_current_user()
	method = TOTPMethod.query.filter_by(dn=user.dn, id=id).first_or_404()
	db.session.delete(method)
	db.session.commit()
	return redirect(url_for('mfa.setup'))

@bp.route('/setup/webauthn', methods=['GET'])
@login_required()
def setup_webauthn():
	user = get_current_user()
	return render_template('setup_webauthn.html')

def get_webauthn_server():
	return Fido2Server(PublicKeyCredentialRpEntity(urllib.parse.urlsplit(request.url).hostname, "uffd"))

@bp.route('/setup/webauthn/begin', methods=['POST'])
@login_required()
def setup_webauthn_begin():
	user = get_current_user()
	server = get_webauthn_server()
	registration_data, state = server.register_begin(
		{
			"id": user.loginname.encode(),
			"name": user.loginname,
			"displayName": user.displayname,
			"icon": "https://example.com/image.png",
		},
		[],
		user_verification=UserVerificationRequirement.DISCOURAGED,
		authenticator_attachment="cross-platform",
	)
	session["state"] = state
	return cbor.encode(registration_data)

@bp.route('/setup/webauthn/complete', methods=['POST'])
@login_required()
def setup_webauthn_complete():
	user = get_current_user()
	server = get_webauthn_server()
	data = cbor.decode(request.get_data())
	client_data = ClientData(data["clientDataJSON"])
	att_obj = AttestationObject(data["attestationObject"])
	auth_data = server.register_complete(session["state"], client_data, att_obj)
	method = WebauthnMethod(user, auth_data, name=data['name'])
	db.session.add(method)
	db.session.commit()
	print("REGISTERED CREDENTIAL:", auth_data.credential_data)
	return cbor.encode({"status": "OK"})

@bp.route('/setup/webauthn/<int:id>/delete')
@login_required()
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
	print(creds)
	if not creds:
		abort(404)
	auth_data, state = server.authenticate_begin(creds, user_verification=UserVerificationRequirement.DISCOURAGED)
	session["state"] = state
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
	print("clientData", client_data)
	print("AuthenticatorData", auth_data)
	server.authenticate_complete(
		session.pop("state"),
		creds,
		credential_id,
		client_data,
		auth_data,
		signature,
	)
	print("ASSERTION OK")
	return cbor.encode({"status": "OK"})

@bp.route('/auth', methods=['GET'])
@login_required()
def auth():
	user = get_current_user()
	totp_methods = TOTPMethod.query.filter_by(dn=user.dn).all()
	webauthn_methods = WebauthnMethod.query.filter_by(dn=user.dn).all()
	return render_template('auth.html', ref=request.values.get('ref'), totp_methods=totp_methods,
			webauthn_methods=webauthn_methods)

@bp.route('/auth', methods=['POST'])
@login_required()
def auth_finish():
	user = get_current_user()
	methods = TOTPMethod.query.filter_by(dn=user.dn).all()
	for method in methods:
		if method.verify(request.form['code']):
			session['mfa_verifed'] = True
			return redirect(request.values.get('ref', url_for('index')))
	flash('Two-factor authentication failed')
	return redirect(url_for('mfa.auth', ref=request.values.get('ref')))

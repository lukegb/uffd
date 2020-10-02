from flask import Blueprint, render_template, session, request, redirect, url_for, flash

from uffd.database import db
from uffd.mfa.models import TOTPMethod
from uffd.session.views import get_current_user, login_required

bp = Blueprint('mfa', __name__, template_folder='templates', url_prefix='/mfa/')


@bp.route('/', methods=['GET'])
@login_required()
def setup():
	user = get_current_user()
	methods = TOTPMethod.query.filter_by(dn=user.dn).all()
	return render_template('setup.html', methods=methods)

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

@bp.route('/auth', methods=['GET'])
@login_required()
def auth():
	user = get_current_user()
	methods = TOTPMethod.query.filter_by(dn=user.dn).all()
	return render_template('auth.html', ref=request.values.get('ref'), methods=methods)

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

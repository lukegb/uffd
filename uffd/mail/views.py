from flask import Blueprint, render_template, request, url_for, redirect, flash, current_app

from uffd.navbar import register_navbar
from uffd.csrf import csrf_protect
from uffd.ldap import get_conn, escape_filter_chars
from uffd.session import login_required, is_valid_session, get_current_user

from uffd.mail.models import Mail

bp = Blueprint("mail", __name__, template_folder='templates', url_prefix='/mail/')
@bp.before_request
@login_required()
def mail_acl(): #pylint: disable=inconsistent-return-statements
	if not mail_acl_check():
		flash('Access denied')
		return redirect(url_for('index'))

def mail_acl_check():
	return is_valid_session() and get_current_user().is_in_group(current_app.config['ACL_ADMIN_GROUP'])

@bp.route("/")
@register_navbar('Mail', icon='envelope', blueprint=bp, visible=mail_acl_check)
def index():
	conn = get_conn()
	conn.search(current_app.config["LDAP_BASE_MAIL"], '(objectclass=postfixVirtual)')
	mails = []
	for i in conn.entries:
		mails.append(Mail.from_ldap(i))
	return render_template('mail_list.html', mails=mails)

@bp.route("/<uid>")
@bp.route("/new")
def show(uid=None):
	if not uid:
		mail = Mail()
	else:
		conn = get_conn()
		conn.search(current_app.config["LDAP_BASE_MAIL"], '(&(objectclass=postfixVirtual)(uid={}))'.format((escape_filter_chars(uid))))
		assert len(conn.entries) == 1
		mail = Mail.from_ldap(conn.entries[0])
	return render_template('mail.html', mail=mail)

@bp.route("/<uid>/update", methods=['POST'])
@bp.route("/new", methods=['POST'])
@csrf_protect(blueprint=bp)
def update(uid=False):
	conn = get_conn()
	is_newmail = bool(not uid)
	if is_newmail:
		mail = Mail()
	else:
		conn = get_conn()
		conn.search(current_app.config["LDAP_BASE_MAIL"], '(&(objectclass=postfixVirtual)(uid={}))'.format((escape_filter_chars(uid))))
		assert len(conn.entries) == 1
		mail = Mail.from_ldap(conn.entries[0])

	if is_newmail:
		mail.uid = request.form.get('mail-uid')
	mail.receivers = request.form.get('mail-receivers', '').splitlines()
	mail.destinations = request.form.get('mail-destinations', '').splitlines()

	if mail.to_ldap(new=is_newmail):
		flash('Mail mapping updated.')
	else:
		flash('Error updating mail mapping: {}'.format(conn.result['message']))
		if is_newmail:
			return redirect(url_for('mail.index'))
	return redirect(url_for('mail.show', uid=mail.uid))

@bp.route("/<uid>/del")
@csrf_protect(blueprint=bp)
def delete(uid):
	conn = get_conn()
	conn.search(current_app.config["LDAP_BASE_MAIL"], '(&(objectclass=postfixVirtual)(uid={}))'.format((escape_filter_chars(uid))))
	assert len(conn.entries) == 1
	mail = conn.entries[0]

	if conn.delete(mail.entry_dn):
		flash('Deleted mail mapping.')
	else:
		flash('Could not delete mail mapping: {}'.format(conn.result['message']))
	return redirect(url_for('mail.index'))

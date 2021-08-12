from flask import Blueprint, render_template, request, url_for, redirect, flash, current_app
from flask_babel import gettext as _, lazy_gettext

from uffd.navbar import register_navbar
from uffd.csrf import csrf_protect
from uffd.ldap import ldap
from uffd.session import login_required

from uffd.mail.models import Mail

bp = Blueprint("mail", __name__, template_folder='templates', url_prefix='/mail/')
@bp.before_request
@login_required()
def mail_acl(): #pylint: disable=inconsistent-return-statements
	if not mail_acl_check():
		flash('Access denied')
		return redirect(url_for('index'))

def mail_acl_check():
	return request.user and request.user.is_in_group(current_app.config['ACL_ADMIN_GROUP'])

@bp.route("/")
@register_navbar(29, lazy_gettext('Forwardings'), icon='envelope', blueprint=bp, visible=mail_acl_check)
def index():
	return render_template('mail/list.html', mails=Mail.query.all())

@bp.route("/<uid>")
@bp.route("/new")
def show(uid=None):
	mail = Mail()
	if uid is not None:
		mail = Mail.query.filter_by(uid=uid).first_or_404()
	return render_template('mail/show.html', mail=mail)

@bp.route("/<uid>/update", methods=['POST'])
@bp.route("/new", methods=['POST'])
@csrf_protect(blueprint=bp)
def update(uid=None):
	if uid is not None:
		mail = Mail.query.filter_by(uid=uid).first_or_404()
	else:
		mail = Mail(uid=request.form.get('mail-uid'))
	mail.receivers = request.form.get('mail-receivers', '').splitlines()
	mail.destinations = request.form.get('mail-destinations', '').splitlines()
	ldap.session.add(mail)
	ldap.session.commit()
	flash(_('Mail mapping updated.'))
	return redirect(url_for('mail.show', uid=mail.uid))

@bp.route("/<uid>/del")
@csrf_protect(blueprint=bp)
def delete(uid):
	mail = Mail.query.filter_by(uid=uid).first_or_404()
	ldap.session.delete(mail)
	ldap.session.commit()
	flash(_('Deleted mail mapping.'))
	return redirect(url_for('mail.index'))

from flask import Blueprint, render_template, request, url_for, redirect, flash, current_app
from flask_babel import gettext as _, lazy_gettext

from uffd.navbar import register_navbar
from uffd.csrf import csrf_protect
from uffd.database import db
from uffd.models import Mail
from .session import login_required

bp = Blueprint("mail", __name__, template_folder='templates', url_prefix='/mail/')

def mail_acl_check():
	return request.user and request.user.is_in_group(current_app.config['ACL_ADMIN_GROUP'])

@bp.before_request
@login_required(mail_acl_check)
def mail_acl():
	pass

@bp.route("/")
@register_navbar(lazy_gettext('Forwardings'), icon='envelope', blueprint=bp, visible=mail_acl_check)
def index():
	return render_template('mail/list.html', mails=Mail.query.all())

@bp.route("/<int:mail_id>")
@bp.route("/new")
def show(mail_id=None):
	if mail_id is not None:
		mail = Mail.query.get_or_404(mail_id)
	else:
		mail = Mail()
	return render_template('mail/show.html', mail=mail)

@bp.route("/<int:mail_id>/update", methods=['POST'])
@bp.route("/new", methods=['POST'])
@csrf_protect(blueprint=bp)
def update(mail_id=None):
	if mail_id is not None:
		mail = Mail.query.get_or_404(mail_id)
	else:
		mail = Mail(uid=request.form.get('mail-uid'))
	mail.receivers = request.form.get('mail-receivers', '').splitlines()
	mail.destinations = request.form.get('mail-destinations', '').splitlines()
	if mail.invalid_receivers:
		for addr in mail.invalid_receivers:
			flash(_('Invalid receive address: %(mail_address)s', mail_address=addr))
		return render_template('mail/show.html', mail=mail)
	db.session.add(mail)
	db.session.commit()
	flash(_('Mail mapping updated.'))
	return redirect(url_for('mail.show', mail_id=mail.id))

@bp.route("/<int:mail_id>/del")
@csrf_protect(blueprint=bp)
def delete(mail_id):
	mail = Mail.query.get_or_404(mail_id)
	db.session.delete(mail)
	db.session.commit()
	flash(_('Deleted mail mapping.'))
	return redirect(url_for('mail.index'))

from flask import Blueprint, render_template, request, url_for, redirect, flash, current_app

from uffd.navbar import register_navbar
from uffd.csrf import csrf_protect

from uffd.user.models import User, Group
from uffd.session import get_current_user, login_required, is_valid_session
from uffd.ldap import get_conn, escape_filter_chars

bp = Blueprint("selfservice", __name__, template_folder='templates', url_prefix='/self/')

@bp.before_request
@login_required()
def self_acl():
	pass
	#if not self_acl_check():
	#	flash('Access denied')
	#	return redirect(url_for('index'))

def self_acl_check():
	return is_valid_session() and get_current_user().is_in_group(current_app.config['ACL_SELFSERVICE_GROUP'])

@bp.route("/")
@register_navbar('Selfservice', icon='portrait', blueprint=bp, visible=is_valid_session)
def self_index():
	return render_template('self.html', user=get_current_user())

@bp.route("/update", methods=(['POST']))
@csrf_protect
def self_update():
	pass


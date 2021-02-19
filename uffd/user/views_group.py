from flask import Blueprint, render_template, url_for, redirect, flash, current_app

from uffd.navbar import register_navbar
from uffd.ldap import get_conn, escape_filter_chars
from uffd.session import login_required, is_valid_session, get_current_user

from .models import Group

bp = Blueprint("group", __name__, template_folder='templates', url_prefix='/group/')
@bp.before_request
@login_required()
def group_acl(): #pylint: disable=inconsistent-return-statements
	if not group_acl_check():
		flash('Access denied')
		return redirect(url_for('index'))

def group_acl_check():
	return is_valid_session() and get_current_user().is_in_group(current_app.config['ACL_ADMIN_GROUP'])

@bp.route("/")
@register_navbar('Groups', icon='layer-group', blueprint=bp, visible=group_acl_check)
def index():
	return render_template('group_list.html', groups=Group.ldap_all())

@bp.route("/<int:gid>")
def show(gid):
	return render_template('group.html', group=Group.ldap_filter_by(gid=gid)[0])

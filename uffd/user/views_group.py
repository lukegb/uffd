from flask import Blueprint, render_template, url_for, redirect, flash, current_app, request
from flask_babel import gettext as _, lazy_gettext

from uffd.navbar import register_navbar
from uffd.session import login_required

from .models import Group

bp = Blueprint("group", __name__, template_folder='templates', url_prefix='/group/')
@bp.before_request
@login_required()
def group_acl(): #pylint: disable=inconsistent-return-statements
	if not group_acl_check():
		flash(_('Access denied'))
		return redirect(url_for('index'))

def group_acl_check():
	return request.user and request.user.is_in_group(current_app.config['ACL_ADMIN_GROUP'])

@bp.route("/")
@register_navbar(23, lazy_gettext('Groups'), icon='layer-group', blueprint=bp, visible=group_acl_check)
def index():
	return render_template('group/list.html', groups=Group.query.all())

@bp.route("/<int:gid>")
def show(gid):
	return render_template('group/show.html', group=Group.query.filter_by(gid=gid).first_or_404())

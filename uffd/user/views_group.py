from flask import Blueprint, render_template, current_app, request, abort
from flask_babel import lazy_gettext

from uffd.navbar import register_navbar
from uffd.session import login_required

from .models import Group

bp = Blueprint("group", __name__, template_folder='templates', url_prefix='/group/')
@bp.before_request
@login_required()
def group_acl():
	if not group_acl_check():
		abort(403)

def group_acl_check():
	return request.user and request.user.is_in_group(current_app.config['ACL_ADMIN_GROUP'])

@bp.route("/")
@register_navbar(23, lazy_gettext('Groups'), icon='layer-group', blueprint=bp, visible=group_acl_check)
def index():
	return render_template('group/list.html', groups=Group.query.all())

@bp.route("/<int:gid>")
def show(gid):
	return render_template('group/show.html', group=Group.query.filter_by(gid=gid).first_or_404())

from flask import Blueprint, render_template, request, url_for, redirect, flash, abort
from flask_babel import gettext as _, lazy_gettext

from uffd.navbar import register_navbar
from uffd.csrf import csrf_protect
from uffd.database import db
from uffd.models import Role, User, Group
from .session import login_required

bp = Blueprint('rolemod', __name__, template_folder='templates', url_prefix='/rolemod/')

def user_is_rolemod():
	return request.user and Role.query.join(Role.moderator_group).join(Group.members).filter(User.id==request.user.id).count()

@bp.before_request
@login_required()
def acl_check():
	if not user_is_rolemod():
		abort(403)

@bp.route("/")
@register_navbar(lazy_gettext('Moderation'), icon='user-lock', blueprint=bp, visible=user_is_rolemod)
def index():
	roles = Role.query.join(Role.moderator_group).join(Group.members).filter(User.id==request.user.id).all()
	return render_template('rolemod/list.html', roles=roles)

@bp.route("/<int:role_id>")
def show(role_id):
	role = Role.query.get_or_404(role_id)
	if role.moderator_group not in request.user.groups:
		abort(403)
	return render_template('rolemod/show.html', role=role)

@bp.route("/<int:role_id>", methods=['POST'])
@csrf_protect(blueprint=bp)
def update(role_id):
	role = Role.query.get_or_404(role_id)
	if role.moderator_group not in request.user.groups:
		abort(403)
	if request.form['description'] != role.description:
		if len(request.form['description']) > 256:
			flash(_('Description too long'))
			return redirect(url_for('.show', role_id=role.id))
		role.description = request.form['description']
	db.session.commit()
	return redirect(url_for('.show', role_id=role.id))

@bp.route("/<int:role_id>/delete_member/<int:member_id>")
@csrf_protect(blueprint=bp)
def delete_member(role_id, member_id):
	role = Role.query.get_or_404(role_id)
	if role.moderator_group not in request.user.groups:
		abort(403)
	member = User.query.get_or_404(member_id)
	if member in role.members:
		role.members.remove(member)
	member.update_groups()
	db.session.commit()
	flash(_('Member removed'))
	return redirect(url_for('.show', role_id=role.id))

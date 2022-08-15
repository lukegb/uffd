from flask import Blueprint, render_template, request, url_for, redirect, flash, current_app
from flask_babel import gettext as _, lazy_gettext

from uffd.navbar import register_navbar
from uffd.csrf import csrf_protect
from uffd.database import db
from uffd.models import Role, RoleGroup, Group
from .session import login_required

bp = Blueprint("role", __name__, template_folder='templates', url_prefix='/role/')

def role_acl_check():
	return request.user and request.user.is_in_group(current_app.config['ACL_ADMIN_GROUP'])

@bp.before_request
@login_required(role_acl_check)
def role_acl():
	pass

@bp.route("/")
@register_navbar(lazy_gettext('Roles'), icon='key', blueprint=bp, visible=role_acl_check)
def index():
	return render_template('role/list.html', roles=Role.query.all())

@bp.route("/new")
def new():
	return render_template('role/show.html', role=Role(), groups=Group.query.all(), roles=Role.query.all())

@bp.route("/<int:roleid>")
def show(roleid=None):
	role = Role.query.get(roleid)
	return render_template('role/show.html', role=role, groups=Group.query.all(), roles=Role.query.all())

@bp.route("/<int:roleid>/update", methods=['POST'])
@bp.route("/new", methods=['POST'])
@csrf_protect(blueprint=bp)
def update(roleid=None):
	if roleid is None:
		role = Role()
		db.session.add(role)
	else:
		role = Role.query.get(roleid)
	role.description = request.values['description']
	if not role.locked:
		role.name = request.values['name']
		if not request.values['moderator-group']:
			role.moderator_group = None
		else:
			role.moderator_group = Group.query.get(request.values['moderator-group'])
		for included_role in Role.query.all():
			if included_role != role and request.values.get('include-role-{}'.format(included_role.id)):
				role.included_roles.append(included_role)
			elif included_role in role.included_roles:
				role.included_roles.remove(included_role)
		role.groups.clear()
		for group in Group.query.all():
			if request.values.get(f'group-{group.id}', False):
				role.groups[group] = RoleGroup(requires_mfa=bool(request.values.get(f'group-mfa-{group.id}', '')))
	role.update_member_groups()
	db.session.commit()
	return redirect(url_for('role.show', roleid=role.id))

@bp.route("/<int:roleid>/del")
@csrf_protect(blueprint=bp)
def delete(roleid):
	role = Role.query.get(roleid)
	if role.locked:
		flash(_('Locked roles cannot be deleted'))
		return redirect(url_for('role.show', roleid=role.id))
	old_members = set(role.members_effective)
	role.members.clear()
	db.session.delete(role)
	for user in old_members:
		user.update_groups()
	db.session.commit()
	return redirect(url_for('role.index'))

@bp.route("/<int:roleid>/unlock")
@csrf_protect(blueprint=bp)
def unlock(roleid):
	role = Role.query.get(roleid)
	role.locked = False
	db.session.commit()
	return redirect(url_for('role.show', roleid=role.id))

@bp.route("/<int:roleid>/setdefault")
@csrf_protect(blueprint=bp)
def set_default(roleid):
	role = Role.query.get(roleid)
	if role.is_default:
		return redirect(url_for('role.show', roleid=role.id))
	role.is_default = True
	for user in set(role.members):
		if not user.is_service_user:
			role.members.remove(user)
	role.update_member_groups()
	db.session.commit()
	return redirect(url_for('role.show', roleid=role.id))

@bp.route("/<int:roleid>/unsetdefault")
@csrf_protect(blueprint=bp)
def unset_default(roleid):
	role = Role.query.get(roleid)
	if not role.is_default:
		return redirect(url_for('role.show', roleid=role.id))
	old_members = set(role.members_effective)
	role.is_default = False
	for user in old_members:
		if not user.is_service_user:
			user.update_groups()
	db.session.commit()
	return redirect(url_for('role.show', roleid=role.id))

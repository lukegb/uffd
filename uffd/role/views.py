from flask import Blueprint, render_template, request, url_for, redirect, flash, current_app

from uffd.navbar import register_navbar
from uffd.csrf import csrf_protect
from uffd.role.models import Role
from uffd.user.models import Group
from uffd.session import get_current_user, login_required, is_valid_session
from uffd.database import db
from uffd.ldap import ldap

bp = Blueprint("role", __name__, template_folder='templates', url_prefix='/role/')
@bp.before_request
@login_required()
def role_acl(): #pylint: disable=inconsistent-return-statements
	if not role_acl_check():
		flash('Access denied')
		return redirect(url_for('index'))

def role_acl_check():
	return is_valid_session() and get_current_user().is_in_group(current_app.config['ACL_ADMIN_GROUP'])

@bp.route("/")
@register_navbar('Roles', icon='key', blueprint=bp, visible=role_acl_check)
def index():
	return render_template('role_list.html', roles=Role.query.all())

@bp.route("/<int:roleid>")
@bp.route("/new")
def show(roleid=False):
	if not roleid:
		role = Role()
	else:
		role = Role.query.filter_by(id=roleid).one()
	return render_template('role.html', role=role, groups=Group.query.all())

@bp.route("/<int:roleid>/update", methods=['POST'])
@bp.route("/new", methods=['POST'])
@csrf_protect(blueprint=bp)
def update(roleid=False):
	is_newrole = bool(not roleid)
	if is_newrole:
		role = Role()
		db.session.add(role)
	else:
		role = Role.query.filter_by(id=roleid).one()
	role.name = request.values['name']
	role.description = request.values['description']
	for group in Group.query.all():
		if request.values.get('group-{}'.format(group.gid), False):
			role.groups.add(group)
		else:
			role.groups.discard(group)
	role.update_member_groups()
	db.session.commit()
	ldap.session.commit()
	return redirect(url_for('role.index'))

@bp.route("/<int:roleid>/del")
@csrf_protect(blueprint=bp)
def delete(roleid):
	role = Role.query.filter_by(id=roleid).one()
	oldmembers = list(role.members)
	role.members.clear()
	db.session.delete(role)
	for user in oldmembers:
		user.update_groups()
	db.session.commit()
	ldap.session.commit()
	return redirect(url_for('role.index'))

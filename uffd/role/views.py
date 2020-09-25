from flask import Blueprint, render_template, request, url_for, redirect, flash, current_app

from uffd.navbar import register_navbar
from uffd.csrf import csrf_protect
from uffd.role.models import Role
from uffd.role.utils import recalculate_user_groups
from uffd.user.models import Group
from uffd.session import get_current_user, login_required, is_valid_session
from uffd.database import db

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
	groups = Group.from_ldap_all()
	return render_template('role.html', role=role, groups=groups)

@bp.route("/<int:roleid>/update", methods=['POST'])
@bp.route("/new", methods=['POST'])
@csrf_protect(blueprint=bp)
def update(roleid=False):
	is_newrole = bool(not roleid)
	session = db.session
	if is_newrole:
		role = Role()
		session.add(role)
	else:
		role = Role.query.filter_by(id=roleid).one()
	role.name = request.values['name']
	role.description = request.values['description']

	groups = Group.from_ldap_all()
	role_group_dns = role.group_dns()
	for group in groups:
		if request.values.get('group-{}'.format(group.gid), False):
			if group.dn in role_group_dns:
				continue
			role.add_group(group)
		elif group.dn in role_group_dns:
			role.del_group(group)

	members = role.member_ldap()
	for user in members:
		recalculate_user_groups(user)
		if not user.to_ldap():
			flash('updating group membership for user {} failed'.format(user.loginname))

	session.commit()
	return redirect(url_for('role.index'))

@bp.route("/<int:roleid>/del")
@csrf_protect(blueprint=bp)
def delete(roleid):
	session = db.session
	role = Role.query.filter_by(id=roleid).one()
	members = role.member_ldap()
	session.delete(role)
	session.commit()
	for user in members:
		recalculate_user_groups(user)
		if not user.to_ldap():
			flash('updating group membership for user {} failed'.format(user.loginname))
	session.commit()
	return redirect(url_for('role.index'))

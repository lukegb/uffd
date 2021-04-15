import sys

from flask import Blueprint, render_template, request, url_for, redirect, flash, current_app
import click

from uffd.navbar import register_navbar
from uffd.csrf import csrf_protect
from uffd.role.models import Role
from uffd.user.models import User, Group
from uffd.session import get_current_user, login_required, is_valid_session
from uffd.database import db
from uffd.ldap import ldap

bp = Blueprint("role", __name__, template_folder='templates', url_prefix='/role/')

@bp.record
def add_cli_commands(state):
	@state.app.cli.command('roles-update-all', help='Update group memberships for all users based on their roles')
	@click.option('--check-only', is_flag=True)
	def roles_update_all(check_only): #pylint: disable=unused-variable
		consistent = True
		with current_app.test_request_context():
			for user in User.query.all():
				groups_added, groups_removed = user.update_groups()
				if groups_added:
					consistent = False
					print('Adding groups [%s] to user %s'%(', '.join([group.name for group in groups_added]), user.dn))
				if groups_removed:
					consistent = False
					print('Removing groups [%s] from user %s'%(', '.join([group.name for group in groups_removed]), user.dn))
			if not check_only:
				ldap.session.commit()
			if check_only and not consistent:
				print('No changes were made because --check-only is set')
				print()
				print('Error: LDAP groups are not consistent with roles in database')
				sys.exit(1)

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
	# prefetch all users so the ldap orm can cache them and doesn't run one ldap query per user
	User.query.all()
	if not roleid:
		role = Role()
	else:
		role = Role.query.filter_by(id=roleid).one()
	return render_template('role.html', role=role, groups=Group.query.all(), roles=Role.query.all())

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
	if not request.values['moderator-group']:
		role.moderator_group_dn = None
	else:
		role.moderator_group = Group.query.get(request.values['moderator-group'])
	for included_role in Role.query.all():
		if included_role != role and request.values.get('include-role-{}'.format(included_role.id)):
			role.included_roles.append(included_role)
		elif included_role in role.included_roles:
			role.included_roles.remove(included_role)
	for group in Group.query.all():
		if request.values.get('group-{}'.format(group.gid), False):
			role.groups.add(group)
		else:
			role.groups.discard(group)
	role.update_member_groups()
	db.session.commit()
	ldap.session.commit()
	return redirect(url_for('role.show', roleid=roleid))

@bp.route("/<int:roleid>/del")
@csrf_protect(blueprint=bp)
def delete(roleid):
	role = Role.query.filter_by(id=roleid).one()
	oldmembers = set(role.members).union(role.indirect_members)
	role.members.clear()
	db.session.delete(role)
	for user in oldmembers:
		user.update_groups()
	db.session.commit()
	ldap.session.commit()
	return redirect(url_for('role.index'))

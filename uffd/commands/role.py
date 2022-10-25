from flask import current_app
from flask.cli import AppGroup
from sqlalchemy.exc import IntegrityError
import click

from uffd.database import db
from uffd.models import Group, Role, RoleGroup

role_command = AppGroup('role', help='Manage roles')

# pylint: disable=too-many-arguments,too-many-locals

def update_attrs(role, description=None, default=None,
                 moderator_group=None, clear_moderator_group=False,
                 clear_groups=False, add_group=tuple(), remove_group=tuple(),
                 clear_roles=False, add_role=tuple(), remove_role=tuple()):
	if description is not None:
		role.description = description
	if default is not None:
		role.is_default = default
	if clear_moderator_group:
		role.moderator_group = None
	elif moderator_group is not None:
		group = Group.query.filter_by(name=moderator_group).one_or_none()
		if group is None:
			raise click.ClickException(f'Moderaor group {moderator_group} not found')
		role.moderator_group = group
	if clear_groups:
		role.groups.clear()
	for group_name in add_group:
		group = Group.query.filter_by(name=group_name).one_or_none()
		if group is None:
			raise click.ClickException(f'Group {group_name} not found')
		role.groups[group] = RoleGroup(group=group)
	for group_name in remove_group:
		group = Group.query.filter_by(name=group_name).one_or_none()
		if group is None:
			raise click.ClickException(f'Group {group_name} not found')
		del role.groups[group]
	if clear_roles:
		role.included_roles.clear()
	for role_name in add_role:
		_role = Role.query.filter_by(name=role_name).one_or_none()
		if _role is None:
			raise click.ClickException(f'Role {role_name} not found')
		role.included_roles.append(_role)
	for role_name in remove_role:
		_role = Role.query.filter_by(name=role_name).one_or_none()
		if _role is None:
			raise click.ClickException(f'Role {role_name} not found')
		role.included_roles.remove(_role)

@role_command.command(help='List names of all roles')
def list():
	with current_app.test_request_context():
		for role in Role.query:
			click.echo(role.name)

@role_command.command(help='Show details of group')
@click.argument('name')
def show(name):
	with current_app.test_request_context():
		role = Role.query.filter_by(name=name).one_or_none()
		if role is None:
			raise click.ClickException(f'Role {name} not found')
		click.echo(f'Name: {role.name}')
		click.echo(f'Description: {role.description}')
		click.echo(f'Default: {role.is_default}')
		click.echo(f'Moderator group: {role.moderator_group.name if role.moderator_group else None}')
		click.echo(f'Direct groups: {", ".join(sorted([group.name for group in role.groups]))}')
		click.echo(f'Effective groups: {", ".join(sorted([group.name for group in role.groups_effective]))}')
		click.echo(f'Included roles: {", ".join(sorted([irole.name for irole in role.included_roles]))}')
		click.echo(f'Direct members: {", ".join(sorted([user.loginname for user in role.members]))}')
		click.echo(f'Effective members: {", ".join(sorted([user.loginname for user in role.members_effective]))}')

@role_command.command(help='Create new role')
@click.argument('name')
@click.option('--description', default='', help='Set description text.')
@click.option('--default/--no-default', default=False, help='Mark role as default or not. Non-service users are auto-added to default roles.')
@click.option('--moderator-group', metavar='GROUP_NAME', help='Set moderator group. No moderator group if unset.')
@click.option('--add-group', multiple=True, metavar='GROUP_NAME', help='Add group granted to role members. Repeat to add multiple groups.')
@click.option('--add-role', multiple=True, metavar='ROLE_NAME', help='Add role to inherit groups from. Repeat to add multiple roles.')
def create(name, description, default, moderator_group, add_group, add_role):
	with current_app.test_request_context():
		try:
			role = Role(name=name)
			update_attrs(role, description, default, moderator_group,
			             add_group=add_group, add_role=add_role)
			db.session.add(role)
			role.update_member_groups()
			db.session.commit()
		except IntegrityError:
			# pylint: disable=raise-missing-from
			raise click.ClickException(f'A role with name "{name}" already exists')

@role_command.command(help='Update role attributes')
@click.argument('name')
@click.option('--description', help='Set description text.')
@click.option('--default/--no-default', default=None, help='Mark role as default or not. Non-service users are auto-added to default roles.')
@click.option('--moderator-group', metavar='GROUP_NAME', help='Set moderator group.')
@click.option('--no-moderator-group', is_flag=True, flag_value=True, default=False, help='Clear moderator group setting.')
@click.option('--clear-groups', is_flag=True, flag_value=True, default=False, help='Remove all groups granted to role members. Executed before --add-group.')
@click.option('--add-group', multiple=True, metavar='GROUP_NAME', help='Add group granted to role members. Repeat to add multiple groups.')
@click.option('--remove-group', multiple=True, metavar='GROUP_NAME', help='Remove group granted to role members. Repeat to remove multiple groups.')
@click.option('--clear-roles', is_flag=True, flag_value=True, default=False, help='Remove all included roles. Executed before --add-role.')
@click.option('--add-role', multiple=True, metavar='ROLE_NAME', help='Add role to inherit groups from. Repeat to add multiple roles.')
@click.option('--remove-role', multiple=True, metavar='ROLE_NAME', help='Remove included role. Repeat to remove multiple roles.')
def update(name, description, default, moderator_group, no_moderator_group,
           clear_groups, add_group, remove_group, clear_roles, add_role, remove_role):
	with current_app.test_request_context():
		role = Role.query.filter_by(name=name).one_or_none()
		if role is None:
			raise click.ClickException(f'Role {name} not found')
		old_members = set(role.members_effective)
		update_attrs(role, description, default, moderator_group,
		             no_moderator_group, clear_groups, add_group, remove_group,
		             clear_roles, add_role, remove_role)
		for user in old_members:
			user.update_groups()
		role.update_member_groups()
		db.session.commit()

@role_command.command(help='Delete role')
@click.argument('name')
def delete(name):
	with current_app.test_request_context():
		role = Role.query.filter_by(name=name).one_or_none()
		if role is None:
			raise click.ClickException(f'Role {name} not found')
		old_members = set(role.members_effective)
		db.session.delete(role)
		for user in old_members:
			user.update_groups()
		db.session.commit()

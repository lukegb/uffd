from flask import current_app
from flask.cli import AppGroup
from sqlalchemy.exc import IntegrityError
import click

from uffd.database import db

from uffd.models import Group

group_command = AppGroup('group', help='Manage groups')

@group_command.command(help='List names of all groups')
def list():
	with current_app.test_request_context():
		for group in Group.query:
			click.echo(group.name)

@group_command.command(help='Show details of group')
@click.argument('name')
def show(name):
	with current_app.test_request_context():
		group = Group.query.filter_by(name=name).one_or_none()
		if group is None:
			raise click.ClickException(f'Group {name} not found')
		click.echo(f'Name: {group.name}')
		click.echo(f'Unix GID: {group.unix_gid}')
		click.echo(f'Description: {group.description}')
		click.echo(f'Members: {", ".join([user.loginname for user in group.members])}')

@group_command.command(help='Create new group')
@click.argument('name')
@click.option('--description', default='', help='Set description text. Empty per default.')
def create(name, description):
	with current_app.test_request_context():
		group = Group(description=description)
		if not group.set_name(name):
			raise click.ClickException('Invalid name')
		try:
			db.session.add(group)
			db.session.commit()
		except IntegrityError:
			# pylint: disable=raise-missing-from
			raise click.ClickException(f'A group with name "{name}" already exists')

@group_command.command(help='Update group attributes')
@click.argument('name')
@click.option('--description', help='Set description text.')
def update(name, description):
	with current_app.test_request_context():
		group = Group.query.filter_by(name=name).one_or_none()
		if group is None:
			raise click.ClickException(f'Group {name} not found')
		if description is not None:
			group.description = description
		db.session.commit()

@group_command.command(help='Delete group')
@click.argument('name')
def delete(name):
	with current_app.test_request_context():
		group = Group.query.filter_by(name=name).one_or_none()
		if group is None:
			raise click.ClickException(f'Group {name} not found')
		db.session.delete(group)
		db.session.commit()

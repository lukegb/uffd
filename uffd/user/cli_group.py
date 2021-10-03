from flask import Blueprint, current_app
from flask.cli import AppGroup
from sqlalchemy.exc import IntegrityError
import click

from uffd.database import db

from .models import Group

bp = Blueprint('group_cli', __name__)
group_cli = AppGroup('group', help='Manage groups')

@bp.record
def add_cli_commands(state):
	state.app.cli.add_command(group_cli)

@group_cli.command(help='List names of all groups')
def list():
	with current_app.test_request_context():
		for group in Group.query:
			click.echo(group.name)

@group_cli.command(help='Show details of group')
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

@group_cli.command(help='Create new group')
@click.argument('name')
@click.option('--description', default='', help='Set description text. Empty per default.')
def create(name, description):
	with current_app.test_request_context():
		try:
			db.session.add(Group(name=name, description=description))
			db.session.commit()
		except IntegrityError as ex:
			raise click.ClickException(f'Group creation failed: {ex}')

@group_cli.command(help='Update group attributes')
@click.argument('name')
@click.option('--description', default='', help='Set description text.')
def update(name, description):
	with current_app.test_request_context():
		group = Group.query.filter_by(name=name).one_or_none()
		if group is None:
			raise click.ClickException(f'Group {name} not found')
		if description is not None:
			group.description = description
		db.session.commit()

@group_cli.command(help='Delete group')
@click.argument('name')
def delete(name):
	with current_app.test_request_context():
		group = Group.query.filter_by(name=name).one_or_none()
		if group is None:
			raise click.ClickException(f'Group {name} not found')
		db.session.delete(group)
		db.session.commit()

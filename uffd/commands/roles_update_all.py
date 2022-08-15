import sys

from flask import current_app
from flask.cli import with_appcontext
import click

from uffd.database import db
from uffd.models import User

@click.command('roles-update-all', help='Update group memberships for all users based on their roles')
@click.option('--check-only', is_flag=True)
@with_appcontext
def roles_update_all_command(check_only): #pylint: disable=unused-variable
	consistent = True
	with current_app.test_request_context():
		for user in User.query.all():
			groups_added, groups_removed = user.update_groups()
			if groups_added:
				consistent = False
				print('Adding groups [%s] to user %s'%(', '.join([group.name for group in groups_added]), user.loginname))
			if groups_removed:
				consistent = False
				print('Removing groups [%s] from user %s'%(', '.join([group.name for group in groups_removed]), user.loginname))
		if not check_only:
			db.session.commit()
		if check_only and not consistent:
			print('No changes were made because --check-only is set')
			print()
			print('Error: Groups are not consistent with roles in database')
			sys.exit(1)

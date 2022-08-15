import click
from flask.cli import with_appcontext

from uffd.tasks import cleanup_task
from uffd.database import db

@click.command('cleanup', help='Cleanup expired data')
@with_appcontext
def cleanup_command():
	cleanup_task.run()
	db.session.commit()

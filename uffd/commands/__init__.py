from .user import user_command
from .group import group_command
from .role import role_command
from .profile import profile_command
from .gendevcert import gendevcert_command
from .cleanup import cleanup_command
from .roles_update_all import roles_update_all_command
from .unique_email_addresses import unique_email_addresses_command

def init_app(app):
	app.cli.add_command(user_command)
	app.cli.add_command(group_command)
	app.cli.add_command(role_command)
	app.cli.add_command(gendevcert_command)
	app.cli.add_command(profile_command)
	app.cli.add_command(cleanup_command)
	app.cli.add_command(roles_update_all_command)
	app.cli.add_command(unique_email_addresses_command)

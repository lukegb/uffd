from .views_user import bp as bp_user
from .cli_user import bp as bp_cli_user
from .views_group import bp as bp_group
from .cli_group import bp as bp_cli_group

bp = [bp_user, bp_group, bp_cli_user, bp_cli_group]

from .views_user import bp as bp_user
from .views_group import bp as bp_group
from .models import User, Group

bp = [bp_user, bp_group]

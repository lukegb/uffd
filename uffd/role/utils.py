from uffd.role.models import Role

def recalculate_user_groups(user):
	usergroups = set()
	for role in Role.get_for_user(user).all():
		usergroups.update(role.group_dns())
	user.replace_group_dns(usergroups)

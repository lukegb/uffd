from uffd.role.models import Role

def recalculate_user_groups(user):
	newgroups = set()
	for role in Role.get_for_user(user).all():
		# TODO: improve this after finding a solution for the Role<->Group relation
		newgroups.update({Group.ldap_get(dn) for dn in role.group_dns()})
	user.groups = newgroups

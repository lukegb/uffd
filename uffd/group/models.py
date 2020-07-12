from uffd import ldap

class Group():
	gid = None
	name = None
	description = None

	def __init__(self, gid=None, name='', members=None, description=''):
		self.gid = gid
		self.name = name
		if isinstance(members, str):
			members = [members]
		self.members_ldap = members
		self._members = None
		self.description = description

	@classmethod
	def from_ldap(cls, ldapobject):
		return Group(
				gid=ldapobject['gidNumber'].value,
				name=ldapobject['cn'].value,
				members=ldapobject['uniqueMember'],
				description=ldapobject['description'].value if 'description' in ldapobject else '',
			)

	@classmethod
	def from_ldap_dn(cls, dn):
		conn = ldap.get_conn()
		conn.search(dn, '(objectClass=groupOfUniqueNames)')
		if not len(conn.entries) == 1:
			return None
		return Group.from_ldap(conn.entries[0])

	def to_ldap(self, new):
		pass

	def get_members(self):
		from uffd.user.models import User
		if self._members:
			return self._members
		members = []
		for i in self.members_ldap:
			newmember = User.from_ldap_dn(i)
			if newmember:
				members.append(newmember)
		self._members = members
		return members

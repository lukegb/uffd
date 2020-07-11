import string
from uffd import ldap

class User():
	uid = None
	loginname = None
	displayname = None
	mail = None

	def __init__(self, uid=None, loginname='', displayname='', mail='', groups=None):
		self.uid = uid
		self.loginname = loginname
		self.displayname = displayname
		self.mail = mail
		if isinstance(groups, str):
			groups = [groups]
		self.groups_ldap = groups
		self._groups = None

	@classmethod
	def from_ldap(cls, ldapobject):
		return User(
				uid=ldapobject['uidNumber'].value,
				loginname=ldapobject['uid'].value,
				displayname=ldapobject['cn'].value,
				mail=ldapobject['mail'].value,
				groups=ldapobject['memberOf'].value if 'memberOf' in ldapobject else [],
			)

	@classmethod
	def from_ldap_dn(cls, dn):
		conn = ldap.service_conn()
		conn.search(dn, '(objectClass=person)')
		if not len(conn.entries) == 1:
			return None
		return User.from_ldap(conn.entries[0])

	def to_ldap(self, new):
		pass

	def get_groups(self):
		from uffd.group.models import Group
		if self._groups:
			return self._groups
		groups = []
		for i in self.groups_ldap:
			newgroup = Group.from_ldap_dn(i)
			if newgroup:
				groups.append(newgroup)
		self._groups = groups
		return groups

	def set_loginname(self, value):
		if len(value) > 32 or len(value) < 1:
			return False
		for char in value:
			if not char in string.ascii_lowercase + string.digits + '_':
				return False
		self.loginname = value
		return True

	def set_displayname(self, value):
		if len(value) > 128 or len(value) < 1:
			return False
		self.displayname = value
		return True

	def set_password(self, value):
		raise Exception('TODO: user want to change passwords')

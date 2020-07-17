from ldap3 import MODIFY_REPLACE, HASHED_SALTED_SHA512
from ldap3.utils.hashed import hashed
from flask import current_app

from uffd import ldap

class User():
	def __init__(self, uid=None, loginname='', displayname='', mail='', groups=None):
		self.uid = uid
		self.loginname = loginname
		self.displayname = displayname
		self.mail = mail
		self.groups_ldap = groups or []
		self._groups = None
		self.newpassword = None

	@classmethod
	def from_ldap(cls, ldapobject):
		# if you are in no groups, the "memberOf" attribute does not exist
		# if you are only in one group, ldap returns a string not an array with one element
		# we sanitize this to always be an array
		sanitized_groups = ldapobject['memberOf'].value if 'memberOf' in ldapobject else []
		if isinstance(sanitized_groups, str):
			sanitized_groups = [sanitized_groups]
		return User(
				uid=ldapobject['uidNumber'].value,
				loginname=ldapobject['uid'].value,
				displayname=ldapobject['cn'].value,
				mail=ldapobject['mail'].value,
				groups=sanitized_groups,
			)

	@classmethod
	def from_ldap_dn(cls, dn):
		conn = ldap.get_conn()
		conn.search(dn, '(objectClass=person)')
		if not len(conn.entries) == 1:
			return None
		return User.from_ldap(conn.entries[0])

	def to_ldap(self, new=False):
		conn = ldap.get_conn()
		if new:
			attributes = {
				'uidNumber': ldap.get_next_uid(),
				'gidNumber': current_app.config['LDAP_USER_GID'],
				'homeDirectory': '/home/'+self.loginname,
				'sn': ' ',
				# same as for update
				'givenName': self.displayname,
				'displayName': self.displayname,
				'cn': self.displayname,
				'mail': self.mail,
			}
			dn = ldap.loginname_to_dn(self.loginname)
			result = conn.add(dn, current_app.config['LDAP_USER_OBJECTCLASSES'], attributes)
		else:
			attributes = {
				'givenName': [(MODIFY_REPLACE, [self.displayname])],
				'displayName': [(MODIFY_REPLACE, [self.displayname])],
				'cn': [(MODIFY_REPLACE, [self.displayname])],
				'mail': [(MODIFY_REPLACE, [self.mail])],
				}
			if self.newpassword:
				attributes['userPassword'] = [(MODIFY_REPLACE, [hashed(HASHED_SALTED_SHA512, self.newpassword)])]
			dn = ldap.uid_to_dn(self.uid)
			result = conn.modify(dn, attributes)
		return result

	def get_groups(self):
		if self._groups:
			return self._groups
		groups = []
		for i in self.groups_ldap:
			newgroup = Group.from_ldap_dn(i)
			if newgroup:
				groups.append(newgroup)
		self._groups = groups
		return groups

	def is_in_group(self, name):
		if not name:
			return True
		groups = self.get_groups()
		for i in groups:
			if i.name == name:
				return True
		return False

	def set_loginname(self, value):
		if not ldap.loginname_is_safe(value):
			return False
		self.loginname = value
		return True

	def set_displayname(self, value):
		if len(value) > 128 or len(value) < 1:
			return False
		self.displayname = value
		return True

	def set_password(self, value):
		if len(value) < 8:
			return False
		self.newpassword = value
		return True

	def set_mail(self, value):
		if len(value) < 3 or '@' not in value:
			return False
		self.mail = value
		return True

class Group():
	def __init__(self, gid=None, name='', members=None, description=''):
		self.gid = gid
		self.name = name
		self.members_ldap = members
		self._members = None
		self.description = description

	@classmethod
	def from_ldap(cls, ldapobject):
		if 'description' in ldapobject:
			description = ldapobject['description'].value
		else:
			description = ''
		# if a group has no members, "uniqueMember" attribute does not exist
		# if a group has exactly one member, ldap returns a string not an array with one element
		# we sanitize this to always be an array
		sanitized_members = ldapobject['uniqueMember']
		if isinstance(sanitized_members, str):
			sanitized_members = [sanitized_members]
		return Group(
				gid=ldapobject['gidNumber'].value,
				name=ldapobject['cn'].value,
				members=sanitized_members,
				description=description,
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
		if self._members:
			return self._members
		members = []
		for i in self.members_ldap:
			newmember = User.from_ldap_dn(i)
			if newmember:
				members.append(newmember)
		self._members = members
		return members

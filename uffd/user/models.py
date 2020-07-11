import string

from ldap3 import MODIFY_REPLACE, HASHED_SALTED_SHA512
from flask import current_app

from uffd import ldap

class User():
	uid = None
	loginname = None
	displayname = None
	mail = None
	newpassword = None

	def __init__(self, uid=None, loginname='', displayname='', mail='', groups=None):
		self.uid = uid
		self.loginname = loginname
		self.displayname = displayname
		self.mail = mail
		if isinstance(groups, str):
			groups = [groups]
		self.groups_ldap = groups or []
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
		conn = ldap.service_conn()
		if new:
			attributes= {
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
			dn = ldap.uid_to_dn(self.uid)
			result = conn.modify(dn, attributes)
		if result:
			if self.newpassword:
				print(self.newpassword)
				conn.extend.standard.modify_password(user=dn, old_password=None, new_password=self.newpassword, hash_algorithm=HASHED_SALTED_SHA512)
		return result

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
		self.newpassword = value

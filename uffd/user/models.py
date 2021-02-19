import secrets

from ldap3 import MODIFY_REPLACE, MODIFY_DELETE, MODIFY_ADD, HASHED_SALTED_SHA512
from ldap3.utils.hashed import hashed
from flask import current_app

from uffd import ldap


class BaseUser:
	def __init__(self, attributes=None, groups=None, dn=None):
		self.uid = None
		self.mail = ''
		self.loginname = ''
		self.displayname = ''

		if attributes is not None:
			for attribute_name, attribute_value in attributes.items():
				setattr(self, attribute_name, attribute_value)

		self.dn = dn
		self.newpassword = None
		self.groups_ldap = groups or []
		self.initial_groups_ldap = groups or []
		self.groups_changed = False
		self._groups = None

	@classmethod
	def from_ldap(cls, ldapobject):
		ldap_attributes = {
			"loginname": ldap.get_ldap_attribute_safe(ldapobject, "uid"),
			"uid": ldap.get_ldap_attribute_safe(ldapobject, current_app.config["LDAP_USER_ATTRIBUTE_UID"]),
			"displayname": ldap.get_ldap_attribute_safe(ldapobject, current_app.config["LDAP_USER_ATTRIBUTE_DISPLAYNAME"]),
			"mail": ldap.get_ldap_attribute_safe(ldapobject, current_app.config["LDAP_USER_ATTRIBUTE_MAIL"]),
		}

		for user_attribute, ldap_attribute in current_app.config["LDAP_USER_ATTRIBUTE_EXTRA"].items():
			ldap_attribute_name = ldap_attribute.get("name", "")
			if ldap_attribute.get("type", "single"):
				ldap_attributes[user_attribute] = ldap.get_ldap_attribute_safe(ldapobject, ldap_attribute_name)
			else:
				ldap_attributes[user_attribute] = ldap.get_ldap_array_attribute_safe(ldapobject, ldap_attribute_name)

		return User(
				groups=ldap.get_ldap_array_attribute_safe(ldapobject, 'memberOf'),
				dn=ldapobject.entry_dn,
				attributes=ldap_attributes,
			)

	@classmethod
	def from_ldap_dn(cls, dn):
		conn = ldap.get_conn()
		conn.search(dn, current_app.config["LDAP_USER_FILTER"])
		if not len(conn.entries) == 1:
			return None
		return User.from_ldap(conn.entries[0])

	def to_ldap(self, new=False):
		conn = ldap.get_conn()
		if new:
			self.uid = ldap.get_next_uid()
			attributes = {
				current_app.config["LDAP_USER_ATTRIBUTE_UID"]: self.uid,
				current_app.config["LDAP_USER_ATTRIBUTE_DISPLAYNAME"]: self.displayname,
				current_app.config["LDAP_USER_ATTRIBUTE_MAIL"]: self.mail,
				'gidNumber': current_app.config['LDAP_USER_GID'],
				'homeDirectory': '/home/'+self.loginname,
				'sn': ' ',
				'userPassword': hashed(HASHED_SALTED_SHA512, secrets.token_hex(128)),
				# same as for update
				'givenName': self.displayname,
				'displayName': self.displayname,
			}
			dn = ldap.loginname_to_dn(self.loginname)
			result = conn.add(dn, current_app.config['LDAP_USER_OBJECTCLASSES'], attributes)
		else:
			attributes = {
				'givenName': [(MODIFY_REPLACE, [self.displayname])],
				'displayName': [(MODIFY_REPLACE, [self.displayname])],
				current_app.config["LDAP_USER_ATTRIBUTE_DISPLAYNAME"]: [(MODIFY_REPLACE, [self.displayname])],
				current_app.config["LDAP_USER_ATTRIBUTE_MAIL"]: [(MODIFY_REPLACE, [self.mail])],
				}
			if self.newpassword:
				attributes['userPassword'] = [(MODIFY_REPLACE, [hashed(HASHED_SALTED_SHA512, self.newpassword)])]
			dn = ldap.uid_to_dn(self.uid)
			result = conn.modify(dn, attributes)
		self.dn = dn

		group_conn = ldap.get_conn()
		for group in self.initial_groups_ldap:
			if not group in self.groups_ldap:
				group_conn.modify(group, {'uniqueMember': [(MODIFY_DELETE, [self.dn])]})
		for group in self.groups_ldap:
			if not group in self.initial_groups_ldap:
				group_conn.modify(group, {'uniqueMember': [(MODIFY_ADD, [self.dn])]})
		self.groups_changed = False

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

	def replace_group_dns(self, values):
		self._groups = None
		self.groups_ldap = values
		self.groups_changed = True

	def is_in_group(self, name):
		if not name:
			return True
		groups = self.get_groups()
		for i in groups:
			if i.name == name:
				return True
		return False

	def has_permission(self, required_group=None):
		if not required_group:
			return True
		group_names = {group.name for group in self.get_groups()}
		group_sets = required_group
		if isinstance(group_sets, str):
			group_sets = [group_sets]
		for group_set in group_sets:
			if isinstance(group_set, str):
				group_set = [group_set]
			if set(group_set) - group_names == set():
				return True
		return False

	def set_loginname(self, value):
		if not ldap.loginname_is_safe(value):
			return False
		self.loginname = value
		self.dn = ldap.loginname_to_dn(self.loginname)
		return True

	def set_displayname(self, value):
		if len(value) > 128 or len(value) < 1:
			return False
		self.displayname = value
		return True

	def set_password(self, value):
		if len(value) < 8 or len(value) > 256:
			return False
		self.newpassword = value
		return True

	def set_mail(self, value):
		if len(value) < 3 or '@' not in value:
			return False
		self.mail = value
		return True


User = BaseUser


class Group:
	def __init__(self, gid=None, name='', members=None, description='', dn=None):
		self.gid = gid
		self.name = name
		self.members_ldap = members
		self._members = None
		self.description = description
		self.dn = dn

	@classmethod
	def from_ldap(cls, ldapobject):
		return Group(
				gid=ldapobject['gidNumber'].value,
				name=ldapobject['cn'].value,
				members=ldap.get_ldap_array_attribute_safe(ldapobject, 'uniqueMember'),
				description=ldap.get_ldap_attribute_safe(ldapobject, 'description') or '',
				dn=ldapobject.entry_dn,
			)

	@classmethod
	def from_ldap_dn(cls, dn):
		conn = ldap.get_conn()
		conn.search(dn, current_app.config["LDAP_GROUP_FILTER"])
		if not len(conn.entries) == 1:
			return None
		return Group.from_ldap(conn.entries[0])

	@classmethod
	def from_ldap_all(cls):
		conn = ldap.get_conn()
		conn.search(current_app.config["LDAP_BASE_GROUPS"], current_app.config["LDAP_GROUP_FILTER"])
		groups = []
		for i in conn.entries:
			groups.append(Group.from_ldap(i))
		return groups

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

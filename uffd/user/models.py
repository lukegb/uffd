import secrets
import string
import re

from flask import current_app
from ldap3.utils.hashed import hashed, HASHED_SALTED_SHA512

from uffd.ldap import ldap
from uffd.lazyconfig import lazyconfig_str, lazyconfig_list

def get_next_uid(service=False):
	if service:
		new_uid_min = current_app.config['LDAP_USER_SERVICE_MIN_UID']
		new_uid_max = current_app.config['LDAP_USER_SERVICE_MAX_UID']
	else:
		new_uid_min = current_app.config['LDAP_USER_MIN_UID']
		new_uid_max = current_app.config['LDAP_USER_MAX_UID']
	next_uid = new_uid_min
	for user in User.query.all():
		if user.uid <= new_uid_max:
			next_uid = max(next_uid, user.uid + 1)
	if next_uid > new_uid_max:
		raise Exception('No free uid found')
	return next_uid

class ObjectAttributeDict:
	def __init__(self, obj):
		self.obj = obj

	def __getitem__(self, key):
		return getattr(self.obj, key)

def format_with_attributes(fmtstr, obj):
	# Do str.format-style string formatting with the attributes of an object
	# E.g. format_with_attributes("/home/{loginname}", obj) = "/home/foobar" if obj.loginname = "foobar"
	return fmtstr.format_map(ObjectAttributeDict(obj))

class BaseUser(ldap.Model):
	ldap_search_base = lazyconfig_str('LDAP_USER_SEARCH_BASE')
	ldap_filter_params = lazyconfig_list('LDAP_USER_SEARCH_FILTER')
	ldap_object_classes = lazyconfig_list('LDAP_USER_OBJECTCLASSES')
	ldap_dn_base = lazyconfig_str('LDAP_USER_SEARCH_BASE')
	ldap_dn_attribute = lazyconfig_str('LDAP_USER_DN_ATTRIBUTE')

	uid = ldap.Attribute(lazyconfig_str('LDAP_USER_UID_ATTRIBUTE'), default=get_next_uid, aliases=lazyconfig_list('LDAP_USER_UID_ALIASES'))
	loginname = ldap.Attribute(lazyconfig_str('LDAP_USER_LOGINNAME_ATTRIBUTE'), aliases=lazyconfig_list('LDAP_USER_LOGINNAME_ALIASES'))
	displayname = ldap.Attribute(lazyconfig_str('LDAP_USER_DISPLAYNAME_ATTRIBUTE'), aliases=lazyconfig_list('LDAP_USER_DISPLAYNAME_ALIASES'))
	mail = ldap.Attribute(lazyconfig_str('LDAP_USER_MAIL_ATTRIBUTE'), aliases=lazyconfig_list('LDAP_USER_MAIL_ALIASES'))
	pwhash = ldap.Attribute('userPassword', default=lambda: hashed(HASHED_SALTED_SHA512, secrets.token_hex(128)))

	groups = set() # Shuts up pylint, overwritten by back-reference
	roles = set() # Shuts up pylint, overwritten by back-reference

	@property
	def group_dns(self):
		return [group.dn for group in self.groups]

	@property
	def is_service_user(self):
		if self.uid is None:
			return None
		return self.uid >= current_app.config['LDAP_USER_SERVICE_MIN_UID'] and self.uid <= current_app.config['LDAP_USER_SERVICE_MAX_UID']

	@is_service_user.setter
	def is_service_user(self, value):
		assert self.uid is None
		if value:
			self.uid = get_next_uid(service=True)

	def add_default_attributes(self):
		for name, values in current_app.config['LDAP_USER_DEFAULT_ATTRIBUTES'].items():
			if self.ldap_object.getattr(name):
				continue
			if not isinstance(values, list):
				values = [values]
			formatted_values = []
			for value in values:
				if isinstance(value, str):
					value = format_with_attributes(value, self)
				formatted_values.append(value)
			self.ldap_object.setattr(name, formatted_values)

	ldap_add_hooks = ldap.Model.ldap_add_hooks + (add_default_attributes,)

	# Write-only property
	def password(self, value):
		self.pwhash = hashed(HASHED_SALTED_SHA512, value)
	password = property(fset=password)

	def is_in_group(self, name):
		if not name:
			return True
		for group in self.groups:
			if group.name == name:
				return True
		return False

	def has_permission(self, required_group=None):
		if not required_group:
			return True
		group_names = {group.name for group in self.groups}
		group_sets = required_group
		if isinstance(group_sets, str):
			group_sets = [group_sets]
		for group_set in group_sets:
			if isinstance(group_set, str):
				group_set = [group_set]
			if set(group_set) - group_names == set():
				return True
		return False

	def set_loginname(self, value, ignore_blocklist=False):
		if len(value) > 32 or len(value) < 1:
			return False
		for char in value:
			if not char in string.ascii_lowercase + string.digits + '_-':
				return False
		if not ignore_blocklist:
			for expr in current_app.config['LOGINNAME_BLOCKLIST']:
				if re.match(expr, value):
					return False
		self.loginname = value
		return True

	def set_displayname(self, value):
		if len(value) > 128 or len(value) < 1:
			return False
		self.displayname = value
		return True

	def set_password(self, value):
		if len(value) < 8 or len(value) > 256:
			return False
		self.password = value
		return True

	def set_mail(self, value):
		if len(value) < 3 or '@' not in value:
			return False
		self.mail = value
		return True

User = BaseUser

class Group(ldap.Model):
	ldap_search_base = lazyconfig_str('LDAP_GROUP_SEARCH_BASE')
	ldap_filter_params = lazyconfig_list('LDAP_GROUP_SEARCH_FILTER')

	gid = ldap.Attribute(lazyconfig_str('LDAP_GROUP_GID_ATTRIBUTE'))
	name = ldap.Attribute(lazyconfig_str('LDAP_GROUP_NAME_ATTRIBUTE'))
	description = ldap.Attribute(lazyconfig_str('LDAP_GROUP_DESCRIPTION_ATTRIBUTE'), default='')
	members = ldap.Relationship(lazyconfig_str('LDAP_GROUP_MEMBER_ATTRIBUTE'), User, backref='groups')

	roles = [] # Shuts up pylint, overwritten by back-reference

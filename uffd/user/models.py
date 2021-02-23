import secrets
import string

from flask import current_app
from ldap3.utils.hashed import hashed, HASHED_SALTED_SHA512

from uffd.ldap import ldap
from uffd.lazyconfig import lazyconfig_str, lazyconfig_list

def get_next_uid():
	max_uid = current_app.config['LDAP_USER_MIN_UID']
	for user in User.query.all():
		if user.uid <= current_app.config['LDAP_USER_MAX_UID']:
			max_uid = max(user.uid, max_uid)
	next_uid = max_uid + 1
	if next_uid > current_app.config['LDAP_USER_MAX_UID']:
		raise Exception('No free uid found')
	return next_uid

class User(ldap.Model):
	ldap_search_base = lazyconfig_str('LDAP_BASE_USER')
	ldap_filter_params = lazyconfig_list('LDAP_FILTER_USER')
	ldap_object_classes = lazyconfig_list('LDAP_USER_OBJECTCLASSES')
	ldap_dn_base = lazyconfig_str('LDAP_BASE_USER')
	ldap_dn_attribute = 'uid'

	uid = ldap.Attribute(lazyconfig_str('LDAP_USER_ATTRIBUTE_UID'), default=get_next_uid)
	loginname = ldap.Attribute('uid')
	displayname = ldap.Attribute(lazyconfig_str('LDAP_USER_ATTRIBUTE_DISPLAYNAME'), aliases=['givenName', 'displayName'])
	mail = ldap.Attribute(lazyconfig_str('LDAP_USER_ATTRIBUTE_MAIL'))
	pwhash = ldap.Attribute('userPassword', default=lambda: hashed(HASHED_SALTED_SHA512, secrets.token_hex(128)))

	groups = [] # Shuts up pylint, overwritten by back-reference
	roles = [] # Shuts up pylint, overwritten by back-reference

	def dummy_attribute_defaults(self):
		if self.ldap_object.getattr('sn') == []:
			self.ldap_object.setattr('sn', [' '])
		if self.ldap_object.getattr('homeDirectory') == []:
			self.ldap_object.setattr('homeDirectory', ['/home/%s'%self.loginname])
		if self.ldap_object.getattr('gidNumber') == []:
			self.ldap_object.setattr('gidNumber', [current_app.config['LDAP_USER_GID']])

	ldap_add_hooks = ldap.Model.ldap_add_hooks + (dummy_attribute_defaults,)

	# Write-only property
	def password(self, value):
		self.pwhash = hashed(HASHED_SALTED_SHA512, value)
	password = property(fset=password)

	@property
	def ldif(self):
		return '<none yet>' # TODO: Do we really need this?!

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

	def set_loginname(self, value):
		if len(value) > 32 or len(value) < 1:
			return False
		for char in value:
			if not char in string.ascii_lowercase + string.digits + '_-':
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

class Group(ldap.Model):
	ldap_search_base = lazyconfig_str('LDAP_BASE_GROUPS')
	ldap_filter_params = lazyconfig_list('LDAP_FILTER_GROUP')

	gid = ldap.Attribute('gidNumber')
	name = ldap.Attribute('cn')
	description = ldap.Attribute('description', default='')
	members = ldap.Relationship('uniqueMember', User, backref='groups')

	roles = [] # Shuts up pylint, overwritten by back-reference

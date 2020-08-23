import secrets

from ldap3 import MODIFY_REPLACE, MODIFY_DELETE, MODIFY_ADD, HASHED_SALTED_SHA512
from flask import current_app

from uffd import ldap

class Mail():
	def __init__(self, uid=None, destinations=[], receivers=[], dn=None):
		self.uid = uid
		self.receivers = receivers
		self.destinations = destinations
		self.dn = dn

	@classmethod
	def from_ldap(cls, ldapobject):
		return Mail(
				uid=ldapobject['uid'].value,
				receivers=ldap.get_ldap_array_attribute_safe(ldapobject, 'mailacceptinggeneralid'),
				destinations=ldap.get_ldap_array_attribute_safe(ldapobject, 'maildrop'),
				dn=ldapobject.entry_dn,
			)

	@classmethod
	def from_ldap_dn(cls, dn):
		conn = ldap.get_conn()
		conn.search(dn, '(objectClass=postfixVirtual)')
		if not len(conn.entries) == 1:
			return None
		return Mail.from_ldap(conn.entries[0])

	def to_ldap(self, new=False):
		conn = ldap.get_conn()
		if new:
			self.uid = ldap.get_next_uid()
			attributes = {
				'uidNumber': self.uid,
				'gidNumber': current_app.config['LDAP_USER_GID'],
				'homeDirectory': '/home/'+self.loginname,
				'sn': ' ',
				'userPassword': hashed(HASHED_SALTED_SHA512, secrets.token_hex(128)),
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


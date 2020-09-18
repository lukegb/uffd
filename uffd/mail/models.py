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
			attributes = {
				'uid': self.uid,
				# same as for update
				'mailacceptinggeneralid': self.receivers,
				'maildrop': self.destinations,
			}
			self.dn = ldap.mail_to_dn(self.uid)
			result = conn.add(self.dn, current_app.config['MAIL_LDAP_OBJECTCLASSES'], attributes)
		else:
			attributes = {
				'mailacceptinggeneralid': [(MODIFY_REPLACE, self.receivers)],
				'maildrop': [(MODIFY_REPLACE, self.destinations)],
				}
			result = conn.modify(self.dn, attributes)
		return result


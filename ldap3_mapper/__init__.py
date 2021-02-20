import ldap3

from .types import LDAPCommitError
from . import base

class LDAP3Mapper:
	def __init__(self, server=None, bind_dn=None, bind_password=None):
		if not hasattr(type(self), 'server'):
			self.server = server
		if not hasattr(type(self), 'bind_dn'):
			self.bind_dn = bind_dn
		if not hasattr(type(self), 'bind_password'):
			self.bind_password = bind_password
		if not hasattr(type(self), 'session'):
			self.session = base.Session()

		class Model(base.Model):
			ldap_mapper = self

		class Attribute(base.Attribute):
			ldap_mapper = self

		class Relation(base.Relation):
			ldap_mapper = self

		class Backref(base.Backref):
			ldap_mapper = self

		self.Model = Model # pylint: disable=invalid-name
		self.Attribute = Attribute # pylint: disable=invalid-name
		self.Relation = Relation # pylint: disable=invalid-name
		self.Backref = Backref # pylint: disable=invalid-name

	def connect(self):
		return ldap3.Connection(self.server, self.bind_dn, self.bind_password, auto_bind=True)

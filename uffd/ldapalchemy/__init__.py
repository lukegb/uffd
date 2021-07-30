import ldap3

from .core import LDAPCommitError
from . import model, attribute, relationship

__all__ = ['LDAPMapper', 'LDAPCommitError']

class LDAPMapper:
	def __init__(self, server=None, bind_dn=None, bind_password=None):

		class Model(model.Model):
			ldap_mapper = self

		self.Model = Model # pylint: disable=invalid-name
		self.Session = model.Session # pylint: disable=invalid-name
		self.Attribute = attribute.Attribute # pylint: disable=invalid-name
		self.Relationship = relationship.Relationship # pylint: disable=invalid-name
		self.Backreference = relationship.Backreference # pylint: disable=invalid-name

		if not hasattr(type(self), 'server'):
			self.server = server
		if not hasattr(type(self), 'bind_dn'):
			self.bind_dn = bind_dn
		if not hasattr(type(self), 'bind_password'):
			self.bind_password = bind_password
		if not hasattr(type(self), 'session'):
			self.session = self.Session(self.get_connection)

	def get_connection(self):
		return ldap3.Connection(self.server, self.bind_dn, self.bind_password, auto_bind=True)

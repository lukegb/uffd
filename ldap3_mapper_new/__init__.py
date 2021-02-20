import ldap3

from .types import LDAPCommitError
from . import base

class BaseModel(base.SessionObject)::
	def __init__(self, _ldap_response=None, **kwargs):
		super().__init__(_ldap_response)
		for key, value, in kwargs.items():
			if not hasattr(type(self), key):
				raise Exception()
			setattr(self, key, value)

class LDAP3Mapper:
	def __init__(self, server=None, bind_dn=None, bind_password=None):

		class Session(base.Session):
			ldap_mapper = self

		class Model(BaseModel):
			ldap_mapper = self

		self.Session = Session # pylint: disable=invalid-name
		self.Model = Model # pylint: disable=invalid-name

		if not hasattr(type(self), 'server'):
			self.server = server
		if not hasattr(type(self), 'bind_dn'):
			self.bind_dn = bind_dn
		if not hasattr(type(self), 'bind_password'):
			self.bind_password = bind_password
		if not hasattr(type(self), 'session'):
			self.session = self.Session()

	def connect(self):
		return ldap3.Connection(self.server, self.bind_dn, self.bind_password, auto_bind=True)

from copy import deepcopy
from collections.abc import MutableSet

from flask import current_app, request

from ldap3.utils.conv import escape_filter_chars
from ldap3.core.exceptions import LDAPBindError, LDAPCursorError, LDAPPasswordIsMandatoryError
from ldap3 import MODIFY_REPLACE, MODIFY_DELETE, MODIFY_ADD, HASHED_SALTED_SHA512

from ldap3 import Server, Connection, ALL, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, MOCK_SYNC

def fix_connection(conn):
	old_search = conn.search
	def search(*args, **kwargs):
		kwargs.update({'attributes': [ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES]})
		return old_search(*args, **kwargs)
	conn.search = search
	return conn

def get_mock_conn():
	if not current_app.debug:
		raise Exception('LDAP_SERVICE_MOCK cannot be enabled on production instances')
	# Entries are stored in-memory in the mocked `Connection` object. To make
	# changes persistent across requests we reuse the same `Connection` object
	# for all calls to `service_conn()` and `user_conn()`.
	if not hasattr(current_app, 'ldap_mock'):
		server = Server.from_definition('ldap_mock', 'ldap_server_info.json', 'ldap_server_schema.json')
		current_app.ldap_mock = fix_connection(Connection(server, client_strategy=MOCK_SYNC))
		current_app.ldap_mock.strategy.entries_from_json('ldap_server_entries.json')
		current_app.ldap_mock.bind()
	return current_app.ldap_mock

def get_conn():
	if current_app.config.get('LDAP_SERVICE_MOCK', False):
		return get_mock_conn()
	server = Server(current_app.config["LDAP_SERVICE_URL"], get_info=ALL)
	return fix_connection(Connection(server, current_app.config["LDAP_SERVICE_BIND_DN"], current_app.config["LDAP_SERVICE_BIND_PASSWORD"], auto_bind=True))

class LDAPSession:
	def __init__(self):
		self.__objects = {} # dn -> instance
		self.__to_delete = []

	def lookup(self, dn):
		return self.__objects.get(dn)

	def register(self, obj):
		if obj.dn in self.__objects and self.__objects[obj.dn] != obj:
			raise Exception()
		self.__objects[obj.dn] = obj
		return obj

	def add(self, obj):
		if obj.ldap_created:
			raise Exception()
		self.register(obj)

	def delete(self, obj):
		if obj.dn in self.__objects:
			del self.__objects[obj.dn]
		self.__to_delete.append(obj)
		
	def commit(self):
		while self.__to_delete:
			self.__to_delete.pop(0).ldap_delete()
		for obj in self.__objects.values():
			if not obj.ldap_created:
				obj.ldap_create()
			elif obj.ldap_dirty:
				obj.ldap_modify()

	def rollback(self):
		self.__to_delete.clear()
		self.__objects = {dn: obj for dn, obj in self.__objects.items() if obj.ldap_created}
		for obj in self.__objects.values():
			if obj.ldap_dirty:
				obj.ldap_reset()

class FlaskLDAPMapper:
	@property
	def session(self):
		if not hasattr(request, 'ldap_session'):
			request.ldap_session = LDAPSession()
		return request.ldap_session

ldap = FlaskLDAPMapper()

class LDAPSet(MutableSet):
	def __init__(self, getitems, additem, delitem, encode=None, decode=None):
		self.__getitems = getitems
		self.__additem = additem
		self.__delitem = delitem
		self.__encode = encode or (lambda x: x)
		self.__decode = decode or (lambda x: x)

	def __repr__(self):
		return repr(set(self))

	def __contains__(self, value):
		return self.__encode(value) in self.__getitems()
	
	def __iter__(self):
		return iter(map(self.__decode, self.__getitems()))

	def __len__(self):
		return len(self.__getitems())

	def add(self, value):
		if value not in self:
			self.__additem(self.__encode(value))

	def discard(self, value):
		self.__delitem(self.__encode(value))

class LDAPAttribute:
	def __init__(self, name, multi=False, default=None, encode=None, decode=None):
		self.name = name
		self.multi = multi
		self.encode = encode or (lambda x: x)
		self.decode = decode or (lambda x: x)
		def default_wrapper():
			values = default() if callable(default) else default
			if not isinstance(values, list):
				values = [values]
			return [self.encode(value) for value in values]
		self.default = default_wrapper

	def __set_name__(self, cls, name):
		if self.default is None:
			return
		if not cls.ldap_defaults:
			cls.ldap_defaults = {}
		cls.ldap_defaults[self.name] = self.default

	def __get__(self, obj, objtype=None):
		if obj is None:
			return self
		if self.multi:
			return LDAPSet(getitems=lambda: obj.ldap_getattr(self.name),
			               additem=lambda value: obj.ldap_attradd(self.name, value),
			               delitem=lambda value: obj.ldap_attrdel(self.name, value),
			               encode=self.encode, decode=self.decode)
		return self.decode((obj.ldap_getattr(self.name) or [None])[0])

	def __set__(self, obj, values):
		if not self.multi:
			values = [values]
		obj.ldap_setattr(self.name, [self.encode(value) for value in values])

class LDAPRelationBackref:
	def __init__(self, src, srcattr):
		self.src = src
		self.srcattr = srcattr
		self.key = (self.src, self.srcattr)

	def fetch(self, obj):
		if self.key not in obj._relation_data:
			kwargs = {getattr(self.src, self.srcattr).name: obj.dn}
			values = self.src.ldap_filter_by(**kwargs)
			obj._relation_data[self.key] = set(values)
		return obj._relation_data[self.key]

	def add(self, obj, value):
		self.fetch(obj)
		obj._relation_data[self.key].add(value)

	def discard(self, obj, value):
		self.fetch(obj)
		obj._relation_data[self.key].discard(value)

	def __get__(self, obj, objtype=None):
		if obj is None:
			return self
		return LDAPSet(getitems=lambda: self.fetch(obj),
									 additem=lambda value: getattr(value, self.srcattr).add(obj),
									 delitem=lambda value: getattr(value, self.srcattr).discard(obj))

class LDAPRelation:
	def __init__(self, name, dest, backref=None):
		self.name = name
		self.dest = dest
		self.backref = backref

	def __set_name__(self, cls, name):
		if self.backref is not None:
			setattr(self.dest, self.backref, LDAPRelationBackref(cls, name))

	def add(self, obj, destdn):
		destobj = self.dest.ldap_get(destdn) # Always from cache!
		obj.ldap_attradd(self.name, destdn)
		if self.backref is not None:
			getattr(self.dest, self.backref).add(destobj, obj)

	def discard(self, obj, destdn):
		destobj = self.dest.ldap_get(destdn) # Always from cache!
		obj.ldap_attrdel(self.name, destdn)
		if self.backref is not None:
			getattr(self.dest, self.backref).discard(destobj, obj)
	
	def __get__(self, obj, objtype=None):
		if obj is None:
			return self
		return LDAPSet(getitems=lambda: obj.ldap_getattr(self.name),
		               additem=lambda value: self.add(obj, value),
		               delitem=lambda value: self.discard(obj, value),
		               encode=lambda value: value.dn,
		               decode=lambda value: self.dest.ldap_get(value))

class LDAPModel:
	ldap_dn_attribute = None
	ldap_dn_base = None
	ldap_base = None
	ldap_object_classes = None
	ldap_filter = None
	ldap_defaults = None # Populated by LDAPAttribute

	def __init__(self, _ldap_dn=None, _ldap_attributes=None, **kwargs):
		self._relation_data = {}
		self.__ldap_dn = _ldap_dn
		self.__ldap_attributes = {}
		for key, values in (_ldap_attributes or {}).items():
			if isinstance(values, list):
				self.__ldap_attributes[key] = values
			else:
				self.__ldap_attributes[key] = [values]
		self.__attributes = deepcopy(self.__ldap_attributes)
		self.__changes = {}
		for key, value, in kwargs.items():
			if not hasattr(self, key):
				raise Exception()
			setattr(self, key, value)

	def ldap_getattr(self, name):
		return self.__attributes.get(name, [])

	def ldap_setattr(self, name, values):
		self.__changes[name] = [(MODIFY_REPLACE, values)]
		self.__attributes[name] = values

	def ldap_attradd(self, name, item):
		self.__changes[name] = self.__changes.get(name, []) + [(MODIFY_ADD, [item])]
		self.__attributes[name].append(item)

	def ldap_attrdel(self, name, item):
		self.__changes[name] = self.__changes.get(name, []) + [(MODIFY_DELETE, [item])]
		if item in self.__attributes.get(name, []):
			self.__attributes[name].remove(item)

	def __repr__(self):
		name = '%s.%s'%(type(self).__module__, type(self).__name__)
		if self.__ldap_dn is None:
			return '<%s>'%name
		return '<%s %s>'%(name, self.__ldap_dn)

	def build_dn(self):
		return '%s=%s,%s'%(self.ldap_dn_attribute, self.__attributes[self.ldap_dn_attribute][0], self.ldap_dn_base)

	@property
	def dn(self):
		if self.__ldap_dn is not None:
			return self.__ldap_dn
		return self.build_dn()

	@classmethod
	def ldap_get(cls, dn):
		obj = ldap.session.lookup(dn)
		if obj is None:
			conn = get_conn()
			conn.search(dn, cls.ldap_filter)
			if not conn.response:
				return None
			if len(conn.response) != 1:
				raise Exception()
			obj = ldap.session.register(cls(_ldap_dn=conn.response[0]['dn'], _ldap_attributes=conn.response[0]['attributes']))
		return obj

	@classmethod
	def ldap_all(cls):
		conn = get_conn()
		conn.search(cls.ldap_base, cls.ldap_filter)
		res = []
		for entry in conn.response:
			obj = ldap.session.lookup(entry['dn'])
			if obj is None:
				obj = ldap.session.register(cls(_ldap_dn=entry['dn'], _ldap_attributes=entry['attributes']))
			res.append(obj)
		return res

	@classmethod
	def ldap_filter_by(cls, **kwargs):
		filters = [cls.ldap_filter]
		for key, value in kwargs.items():
			filters.append('(%s=%s)'%(key, escape_filter_chars(value)))
		conn = get_conn()
		conn.search(cls.ldap_base, '(&%s)'%(''.join(filters)))
		res = []
		for entry in conn.response:
			obj = ldap.session.lookup(entry['dn'])
			if obj is None:
				obj = ldap.session.register(cls(_ldap_dn=entry['dn'], _ldap_attributes=entry['attributes']))
			res.append(obj)
		return res

	def ldap_reset(self):
		self.__changes = {}
		self.__attributes = deepcopy(self.__ldap_attributes)

	@property
	def ldap_dirty(self):
		return bool(self.__changes)

	@property
	def ldap_created(self):
		return bool(self.__ldap_attributes)

	def ldap_modify(self):
		if not self.ldap_created:
			raise Exception()
		if not self.ldap_dirty:
			return
		conn = get_conn()
		success = conn.modify(self.dn, self.__changes)
		if not success:
			raise Exception()
		self.__changes = {}
		self.__ldap_attributes = deepcopy(self.__attributes)

	def ldap_create(self):
		if self.ldap_created:
			raise Exception()
		conn = get_conn()
		for key, func in (self.ldap_defaults or {}).items():
			if key not in self.__attributes:
				values = func()
				self.__attributes[key] = values
				self.__changes[key] = [(MODIFY_REPLACE, values)]
		success = conn.add(self.dn, self.ldap_object_classes, self.__attributes)
		if not success:
			raise Exception()
		self.__changes = {}
		self.__ldap_attributes = deepcopy(self.__attributes)

	def ldap_delete(self):
		conn = get_conn()
		success = conn.delete(self.dn)
		if not success:
			raise Exception()
		self.__ldap_attributes = {}

from ldap3.utils.hashed import hashed
import secrets

class User(LDAPModel):
	ldap_base = 'ou=users,dc=example,dc=com'
	ldap_dn_attribute = 'uid'
	ldap_dn_base = 'ou=users,dc=example,dc=com'
	ldap_filter = '(objectClass=person)'
	ldap_object_classes = ['top', 'inetOrgPerson', 'organizationalPerson', 'person', 'posixAccount']

	uid = LDAPAttribute('uidNumber')
	loginname = LDAPAttribute('uid')
	displayname = LDAPAttribute('cn')
	mail = LDAPAttribute('mail')
	pwhash = LDAPAttribute('userPassword', default=lambda: hashed(HASHED_SALTED_SHA512, secrets.token_hex(128)))

	def password(self, value):
		self.pwhash = hashed(HASHED_SALTED_SHA512, value)
	password = property(fset=password)

class Group(LDAPModel):
	ldap_base = 'ou=groups,dc=example,dc=com'
	ldap_filter = '(objectClass=groupOfUniqueNames)'

	gid = LDAPAttribute('gidNumber')
	name = LDAPAttribute('cn')
	description = LDAPAttribute('description', default='')

	members = LDAPRelation('uniqueMember', User, backref='groups')

class Mail(LDAPModel):
	ldap_base = 'ou=postfix,dc=example,dc=com'
	ldap_dn_attribute = 'uid'
	ldap_dn_base = 'ou=postfix,dc=example,dc=com'
	ldap_filter = '(objectClass=postfixVirtual)'
	ldap_object_classes = ['top', 'postfixVirtual']


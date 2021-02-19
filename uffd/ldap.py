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

def user_conn(dn, password):
	if current_app.config.get('LDAP_SERVICE_MOCK', False):
		conn = get_mock_conn()
		# Since we reuse the same conn for all calls to `user_conn()` we
		# simulate the password check by rebinding. Note that ldap3's mocking
		# implementation just compares the string in the objects's userPassword
		# field with the password, no support for hashing or OpenLDAP-style
		# password-prefixes ("{PLAIN}..." or "{ssha512}...").
		try:
			if not conn.rebind(dn, password):
				return False
		except (LDAPBindError, LDAPPasswordIsMandatoryError):
			return False
		return get_mock_conn()
	server = Server(current_app.config["LDAP_SERVICE_URL"], get_info=ALL)
	try:
		return fix_connection(Connection(server, dn, password, auto_bind=True))
	except (LDAPBindError, LDAPPasswordIsMandatoryError):
		return False

class LDAPCommitError(Exception):
	pass

class LDAPSession:
	def __init__(self):
		self.__objects = {} # dn -> instance
		self.__to_delete = []
		self.__relations = {} # (srccls, srcattr, dn) -> {srcobj, ...}

	def lookup(self, dn):
		return self.__objects.get(dn)

	def register(self, obj):
		if obj.dn in self.__objects and self.__objects[obj.dn] != obj:
			raise Exception()
		self.__objects[obj.dn] = obj
		return obj

	def lookup_relations(self, srccls, srcattr, dn):
		key = (srccls, srcattr, dn)
		return self.__relations.get(key, set())

	def update_relations(self, srcobj, srcattr, delete_dns=None, add_dns=None):
		for dn in (delete_dns or []):
			key = (type(srcobj), srcattr, dn)
			self.__relations[key] = self.__relations.get(key, set())
			self.__relations[key].discard(srcobj)
		for dn in (add_dns or []):
			key = (type(srcobj), srcattr, dn)
			self.__relations[key] = self.__relations.get(key, set())
			self.__relations[key].add(srcobj)

	def add(self, obj):
		self.register(obj)

	def delete(self, obj):
		if obj.dn in self.__objects:
			del self.__objects[obj.dn]
		self.__to_delete.append(obj)
		
	def commit(self):
		while self.__to_delete:
			self.__to_delete.pop(0).ldap_delete()
		for obj in list(self.__objects.values()):
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
		return value is not None and self.__encode(value) in self.__getitems()
	
	def __iter__(self):
		return iter(filter(lambda obj: obj is not None, map(self.__decode, self.__getitems())))

	def __len__(self):
		return len(set(self))

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

class LDAPBackref:
	def __init__(self, srccls, srcattr):
		self.srccls = srccls
		self.srcattr = srcattr
		if srccls.ldap_relations is None:
			srccls.ldap_relations = set()
		srccls.ldap_relations.add(srcattr)

	def init(self, obj):
		if self.srcattr not in obj.ldap_relation_data and obj.ldap_created:
			# The query instanciates all related objects that in turn add their relations to session
			self.srccls.ldap_filter_by_raw(**{self.srcattr: obj.dn})
		obj.ldap_relation_data.add(self.srcattr)

	def __get__(self, obj, objtype=None):
		if obj is None:
			return self
		self.init(obj)
		return LDAPSet(getitems=lambda: ldap.session.lookup_relations(self.srccls, self.srcattr, obj.dn),
									 additem=lambda value: value.ldap_attradd(self.srcattr, obj.dn),
									 delitem=lambda value: value.ldap_attrdel(self.srcattr, obj.dn))

	def __set__(self, obj, values):
		current = self.__get__(obj)
		current.clear()
		for value in values:
			current.add(value)

class LDAPRelation(LDAPAttribute):
	def __init__(self, name, dest, backref=None):
		super().__init__(name, multi=True, encode=lambda value: value.dn,
		                 decode=lambda value: dest.ldap_get(value))
		self.name = name
		self.dest = dest
		self.backref = backref

	def __set_name__(self, cls, name):
		if self.backref is not None:
			setattr(self.dest, self.backref, LDAPBackref(cls, self.name))

class LDAPModel:
	ldap_dn_attribute = None
	ldap_dn_base = None
	ldap_base = None
	ldap_object_classes = None
	ldap_filter = None
	ldap_defaults = None # Populated by LDAPAttribute
	ldap_relations = None # Populated by LDAPBackref

	def __init__(self, _ldap_dn=None, _ldap_attributes=None, **kwargs):
		self.ldap_relation_data = set()
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
		for name in (self.ldap_relations or []):
			self.__update_relations(name, add_dns=self.__attributes.get(name, []))

	def __update_relations(self, name, delete_dns=None, add_dns=None):
		if name in (self.ldap_relations or []):
			ldap.session.update_relations(self, name, delete_dns, add_dns)

	def ldap_getattr(self, name):
		return self.__attributes.get(name, [])

	def ldap_setattr(self, name, values):
		self.__update_relations(name, delete_dns=self.__attributes.get(name, []))
		self.__changes[name] = [(MODIFY_REPLACE, values)]
		self.__attributes[name] = values
		self.__update_relations(name, add_dns=values)

	def ldap_attradd(self, name, value):
		self.__changes[name] = self.__changes.get(name, []) + [(MODIFY_ADD, [value])]
		self.__attributes[name].append(value)
		self.__update_relations(name, add_dns=[value])

	def ldap_attrdel(self, name, value):
		self.__changes[name] = self.__changes.get(name, []) + [(MODIFY_DELETE, [value])]
		if value in self.__attributes.get(name, []):
			self.__attributes[name].remove(value)
		self.__update_relations(name, delete_dns=[value])

	def __repr__(self):
		name = '%s.%s'%(type(self).__module__, type(self).__name__)
		if self.__ldap_dn is None:
			return '<%s>'%name
		return '<%s %s>'%(name, self.__ldap_dn)

	def build_dn(self):
		if self.ldap_dn_attribute is None:
			return None
		if self.ldap_dn_base is None:
			return None
		if self.__attributes.get(self.ldap_dn_attribute) is None:
			return None
		return '%s=%s,%s'%(self.ldap_dn_attribute, escape_filter_chars(self.__attributes[self.ldap_dn_attribute][0]), self.ldap_dn_base)

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
	def ldap_filter_by_raw(cls, **kwargs):
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

	@classmethod
	def ldap_filter_by(cls, **kwargs):
		_kwargs = {}
		for key, value in kwargs.items():
			attr = getattr(cls, key)
			_kwargs[attr.name] = attr.encode(value)
		return cls.ldap_filter_by_raw(**_kwargs)

	def ldap_reset(self):
		for name in (self.ldap_relations or []):
			self.__update_relations(name, delete_dns=self.__attributes.get(name, []))
		self.__changes = {}
		self.__attributes = deepcopy(self.__ldap_attributes)
		for name in (self.ldap_relations or {}):
			self.__update_relations(name, add_dns=self.__attributes.get(name, []))

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
			raise LDAPCommitError()
		self.__changes = {}
		self.__ldap_attributes = deepcopy(self.__attributes)

	def ldap_delete(self):
		conn = get_conn()
		success = conn.delete(self.dn)
		if not success:
			raise Exception()
		self.__ldap_attributes = {}

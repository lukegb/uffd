from copy import deepcopy

from ldap3.utils.conv import escape_filter_chars
from ldap3 import MODIFY_REPLACE, MODIFY_DELETE, MODIFY_ADD, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES

from .types import LDAPSet, LDAPCommitError

class Session:
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

class Model:
	ldap_mapper = None # Overwritten by LDAP3Mapper

	ldap_dn_attribute = None
	ldap_dn_base = None
	ldap_base = None
	ldap_object_classes = None
	ldap_filter = None
	# Caution: Never mutate ldap_pre_create_hooks and ldap_relations, always reassign!
	ldap_pre_create_hooks = []
	ldap_relations = []

	def __init__(self, _ldap_response=None, **kwargs):
		self.ldap_session = self.ldap_mapper.session
		self.ldap_relation_data = set()
		self.__ldap_dn = None if _ldap_response is None else _ldap_response['dn']
		self.__ldap_attributes = {}
		for key, values in (_ldap_response or {}).get('attributes', {}).items():
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
		for name in self.ldap_relations:
			self.__update_relations(name, add_dns=self.__attributes.get(name, []))

	def __update_relations(self, name, delete_dns=None, add_dns=None):
		if name in self.ldap_relations:
			self.ldap_session.update_relations(self, name, delete_dns, add_dns)

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
		obj = cls.ldap_mapper.session.lookup(dn)
		if obj is None:
			conn = cls.ldap_mapper.connect()
			conn.search(dn, cls.ldap_filter, attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])
			if not conn.response:
				return None
			if len(conn.response) != 1:
				raise Exception()
			obj = cls.ldap_mapper.session.register(cls(_ldap_response=conn.response[0]))
		return obj

	@classmethod
	def ldap_all(cls):
		conn = cls.ldap_mapper.connect()
		conn.search(cls.ldap_base, cls.ldap_filter, attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])
		res = []
		for entry in conn.response:
			obj = cls.ldap_mapper.session.lookup(entry['dn'])
			if obj is None:
				obj = cls.ldap_mapper.session.register(cls(_ldap_response=entry))
			res.append(obj)
		return res

	@classmethod
	def ldap_filter_by_raw(cls, **kwargs):
		filters = [cls.ldap_filter]
		for key, value in kwargs.items():
			filters.append('(%s=%s)'%(key, escape_filter_chars(value)))
		conn = cls.ldap_mapper.connect()
		conn.search(cls.ldap_base, '(&%s)'%(''.join(filters)), attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])
		res = []
		for entry in conn.response:
			obj = cls.ldap_mapper.session.lookup(entry['dn'])
			if obj is None:
				obj = cls.ldap_mapper.session.register(cls(_ldap_response=entry))
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
		for name in self.ldap_relations:
			self.__update_relations(name, delete_dns=self.__attributes.get(name, []))
		self.__changes = {}
		self.__attributes = deepcopy(self.__ldap_attributes)
		for name in self.ldap_relations:
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
		conn = self.ldap_mapper.connect()
		success = conn.modify(self.dn, self.__changes)
		if not success:
			raise Exception()
		self.__changes = {}
		self.__ldap_attributes = deepcopy(self.__attributes)

	def ldap_create(self):
		if self.ldap_created:
			raise Exception()
		conn = self.ldap_mapper.connect()
		for func in self.ldap_pre_create_hooks:
			func(self)
		success = conn.add(self.dn, self.ldap_object_classes, self.__attributes)
		if not success:
			raise LDAPCommitError()
		self.__changes = {}
		self.__ldap_attributes = deepcopy(self.__attributes)

	def ldap_delete(self):
		conn = self.ldap_mapper.connect()
		success = conn.delete(self.dn)
		if not success:
			raise Exception()
		self.__ldap_attributes = {}

class Attribute:
	ldap_mapper = None # Overwritten by LDAP3Mapper

	def __init__(self, name, multi=False, default=None, encode=None, decode=None, aliases=None):
		self.name = name
		self.multi = multi
		self.encode = encode or (lambda x: x)
		self.decode = decode or (lambda x: x)
		self.default_values = default
		self.aliases = aliases or []

	def default(self, obj):
		if obj.ldap_getattr(self.name) == []:
			values = self.default_values
			if callable(values):
				values = values()
			self.__set__(obj, values)

	def additem(self, obj, value):
		obj.ldap_attradd(self.name, value)
		for name in self.aliases:
			obj.ldap_attradd(name, value)

	def delitem(self, obj, value):
		obj.ldap_attradd(self.name, value)
		for name in self.aliases:
			obj.ldap_attradd(name, value)

	def __set_name__(self, cls, name):
		if self.default_values is not None:
			cls.ldap_pre_create_hooks = cls.ldap_pre_create_hooks + [self.default]

	def __get__(self, obj, objtype=None):
		if obj is None:
			return self
		if self.multi:
			return LDAPSet(getitems=lambda: obj.ldap_getattr(self.name),
			               additem=lambda value: self.additem(obj, value),
			               delitem=lambda value: self.delitem(obj, value),
			               encode=self.encode, decode=self.decode)
		return self.decode((obj.ldap_getattr(self.name) or [None])[0])

	def __set__(self, obj, values):
		if not self.multi:
			values = [values]
		obj.ldap_setattr(self.name, [self.encode(value) for value in values])
		for name in self.aliases:
			obj.ldap_setattr(name, [self.encode(value) for value in values])

class Backref:
	ldap_mapper = None # Overwritten by LDAP3Mapper

	def __init__(self, srccls, srcattr):
		self.srccls = srccls
		self.srcattr = srcattr
		srccls.ldap_relations = srccls.ldap_relations + [srcattr]

	def init(self, obj):
		if self.srcattr not in obj.ldap_relation_data and obj.ldap_created:
			# The query instanciates all related objects that in turn add their relations to session
			self.srccls.ldap_filter_by_raw(**{self.srcattr: obj.dn})
		obj.ldap_relation_data.add(self.srcattr)

	def __get__(self, obj, objtype=None):
		if obj is None:
			return self
		self.init(obj)
		return LDAPSet(getitems=lambda: obj.ldap_session.lookup_relations(self.srccls, self.srcattr, obj.dn),
									 additem=lambda value: value.ldap_attradd(self.srcattr, obj.dn),
									 delitem=lambda value: value.ldap_attrdel(self.srcattr, obj.dn))

	def __set__(self, obj, values):
		current = self.__get__(obj)
		current.clear()
		for value in values:
			current.add(value)

class Relation(Attribute):
	ldap_mapper = None # Overwritten by LDAP3Mapper

	def __init__(self, name, dest, backref=None):
		super().__init__(name, multi=True, encode=lambda value: value.dn, decode=dest.ldap_get)
		self.name = name
		self.dest = dest
		self.backref = backref

	def __set_name__(self, cls, name):
		if self.backref is not None:
			setattr(self.dest, self.backref, Backref(cls, self.name))

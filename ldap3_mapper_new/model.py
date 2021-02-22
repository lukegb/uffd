from collections.abc import MutableSet

from ldap3.utils.conv import escape_filter_chars

from . import base

class Session:
	def __init__(self, get_connection):
		self.ldap_session = base.Session(get_connection)

	def add(self, obj):
		self.ldap_session.add(obj.ldap_object, obj.dn, obj.object_classes)

	def delete(self, obj):
		self.ldap_session.delete(obj.ldap_object)

	def commit(self):
		self.ldap_session.commit()

	def rollback(self):
		self.ldap_session.rollback()

def make_modelobj(obj, model):
	if obj is None:
		return None
	if not hasattr(obj, 'model'):
		obj.model = model()
		obj.model.ldap_object = obj
	if not isinstance(obj.model, model):
		return None
	return obj.model

def make_modelobjs(objs, model):
	modelobjs = []
	for obj in objs:
		modelobj = make_modelobj(obj, model)
		if modelobj is not None:
			modelobjs.append(modelobj)
	return modelobjs

class ModelQuery:
	def __init__(self, model):
		self.model = model

	def get(self, dn):
		session = self.model.ldap_mapper.session.ldap_session
		return make_modelobj(session.get(dn, self.model.ldap_filter_params), self.model)

	def all(self):
		session = self.model.ldap_mapper.session.ldap_session
		objs = session.filter(self.model.ldap_search_base, self.model.ldap_filter_params)
		return make_modelobjs(objs, self.model)

	def filter_by(self, **kwargs):
		filter_params = self.model.ldap_filter_params + list(kwargs.items())
		session = self.model.ldap_mapper.session.ldap_session
		objs = session.filter(self.model.ldap_search_base, filter_params)
		return make_modelobjs(objs, self.model)

class ModelQueryWrapper:
	def __get__(self, obj, objtype=None):
		return ModelQuery(objtype)

class Model:
	# Overwritten by mapper
	ldap_mapper = None

	# Overwritten by models
	ldap_search_base = None
	ldap_filter_params = None
	ldap_dn_base = None
	ldap_dn_attribute = None

	query = ModelQueryWrapper()

	def __init__(self, **kwargs):
		self.ldap_object = base.Object()
		for key, value, in kwargs.items():
			if not hasattr(self, key):
				raise Exception()
			setattr(self, key, value)

	@property
	def dn(self):
		if self.ldap_object.dn is not None:
			return self.ldap_object.dn
		if self.ldap_dn_base is None or self.ldap_dn_attribute is None:
			return None
		values = self.ldap_object.getattr(self.ldap_dn_attribute)
		if not values:
			return None
		return '%s=%s,%s'%(self.ldap_dn_attribute, escape_filter_chars(values[0]), self.ldap_dn_base)

	def __repr__(self):
		cls_name = '%s.%s'%(type(self).__module__, type(self).__name__)
		if self.dn is not None:
			return '<%s %s>'%(cls_name, self.dn)
		return '<%s>'%cls_name

class SetView(MutableSet):
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

	def update(self, values):
		for value in values:
			self.add(value)

class Attribute:
	def __init__(self, name, multi=False, encode=None, decode=None, aliases=None):
		self.name = name
		self.multi = multi
		self.encode = encode or (lambda x: x)
		self.decode = decode or (lambda x: x)
		self.aliases = [name] + (aliases or [])

	def additem(self, obj, value):
		for name in self.aliases:
			obj.ldap_object.attradd(name, value)

	def delitem(self, obj, value):
		for name in self.aliases:
			obj.ldap_object.attrdel(name, value)

	def __get__(self, obj, objtype=None):
		if obj is None:
			return self
		if self.multi:
			return SetView(getitems=lambda: obj.ldap_object.getattr(self.name),
			               additem=lambda value: self.additem(obj, value),
			               delitem=lambda value: self.delitem(obj, value),
			               encode=self.encode, decode=self.decode)
		return self.decode((obj.ldap_object.getattr(self.name) or [None])[0])

	def __set__(self, obj, values):
		if not self.multi:
			values = [values]
		values = [self.encode(value) for value in values]
		for name in self.aliases:
			obj.ldap_object.setattr(name, values)

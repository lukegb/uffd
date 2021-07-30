from collections.abc import Sequence

try:
	# Added in v2.5
	from ldap3.utils.dn import escape_rdn
except ImportError:
	# From ldap3 source code, Copyright Giovanni Cannata, LGPL v3 license
	def escape_rdn(rdn):
		# '/' must be handled first or the escape slashes will be escaped!
		for char in ['\\', ',', '+', '"', '<', '>', ';', '=', '\x00']:
			rdn = rdn.replace(char, '\\' + char)
		if rdn[0] == '#' or rdn[0] == ' ':
			rdn = ''.join(('\\', rdn))
		if rdn[-1] == ' ':
			rdn = ''.join((rdn[:-1], '\\ '))
		return rdn

from . import core

def add_to_session(obj, session):
	if obj.ldap_object.session is None:
		for func in obj.ldap_add_hooks:
			func(obj)
	session.add(obj.ldap_object, obj.dn, obj.ldap_object_classes)

class Session:
	def __init__(self, get_connection):
		self.ldap_session = core.Session(get_connection)

	def add(self, obj):
		add_to_session(obj, self.ldap_session)

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

class Query(Sequence):
	def __init__(self, model, filter_params=None):
		self.__model = model
		self.__filter_params = list(model.ldap_filter_params) + (filter_params or [])

	@property
	def __session(self):
		return self.__model.ldap_mapper.session.ldap_session

	def get(self, dn):
		return make_modelobj(self.__session.get(dn, self.__filter_params), self.__model)

	def all(self):
		objs = self.__session.filter(self.__model.ldap_search_base, self.__filter_params)
		objs = sorted(objs, key=lambda obj: obj.dn)
		return make_modelobjs(objs, self.__model)

	def first(self):
		return (self.all() or [None])[0]

	def one(self):
		modelobjs = self.all()
		if len(modelobjs) != 1:
			raise Exception()
		return modelobjs[0]

	def one_or_none(self):
		modelobjs = self.all()
		if len(modelobjs) > 1:
			raise Exception()
		return (modelobjs or [None])[0]

	def __contains__(self, value):
		return value in self.all()

	def __iter__(self):
		return iter(self.all())

	def __len__(self):
		return len(self.all())

	def __getitem__(self, index):
		return self.all()[index]

	def filter_by(self, **kwargs):
		filter_params = [(getattr(self.__model, attr).name, value) for attr, value in kwargs.items()]
		return type(self)(self.__model, self.__filter_params + filter_params)

class QueryWrapper:
	def __get__(self, obj, objtype=None):
		return objtype.query_class(objtype)

class Model:
	# Overwritten by mapper
	ldap_mapper = None
	query_class = Query
	query = QueryWrapper()
	ldap_add_hooks = ()

	# Overwritten by models
	ldap_search_base = None
	ldap_filter_params = ()
	ldap_object_classes = ()
	ldap_dn_base = None
	ldap_dn_attribute = None

	def __init__(self, **kwargs):
		self.ldap_object = core.Object()
		for key, value, in kwargs.items():
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
		# escape_rdn can't handle empty strings
		rdn = escape_rdn(values[0]) if values[0] else ''
		return '%s=%s,%s'%(self.ldap_dn_attribute, rdn, self.ldap_dn_base)

	def __repr__(self):
		cls_name = '%s.%s'%(type(self).__module__, type(self).__name__)
		if self.dn is not None:
			return '<%s %s>'%(cls_name, self.dn)
		return '<%s>'%cls_name

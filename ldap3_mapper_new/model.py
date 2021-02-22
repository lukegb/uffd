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
	query = ModelQueryWrapper()
	ldap_add_hooks = tuple()

	# Overwritten by models
	ldap_search_base = None
	ldap_filter_params = None
	ldap_object_classes = None
	ldap_dn_base = None
	ldap_dn_attribute = None

	def __init__(self, **kwargs):
		self.ldap_object = core.Object()
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
		return '%s=%s,%s'%(self.ldap_dn_attribute, escape_rdn(values[0]), self.ldap_dn_base)

	def __repr__(self):
		cls_name = '%s.%s'%(type(self).__module__, type(self).__name__)
		if self.dn is not None:
			return '<%s %s>'%(cls_name, self.dn)
		return '<%s>'%cls_name

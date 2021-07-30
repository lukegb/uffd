from collections.abc import MutableSet

from .model import make_modelobj, make_modelobjs, add_to_session

class UnboundObjectError(Exception):
	pass

class RelationshipSet(MutableSet):
	def __init__(self, ldap_object, name, model, destmodel):
		self.__ldap_object = ldap_object
		self.__name = name
		self.__model = model # pylint: disable=unused-private-member
		self.__destmodel = destmodel

	def __modify_check(self, value):
		if self.__ldap_object.session is None:
			raise UnboundObjectError()
		if not isinstance(value, self.__destmodel):
			raise TypeError()

	def __repr__(self):
		return repr(set(self))

	def __contains__(self, value):
		if value is None or not isinstance(value, self.__destmodel):
			return False
		return value.ldap_object.dn in self.__ldap_object.getattr(self.__name)

	def __iter__(self):
		def get(dn):
			return make_modelobj(self.__ldap_object.session.get(dn, self.__destmodel.ldap_filter_params), self.__destmodel)
		dns = set(self.__ldap_object.getattr(self.__name))
		return iter(filter(lambda obj: obj is not None, map(get, dns)))

	def __len__(self):
		return len(set(self))

	def add(self, value):
		self.__modify_check(value)
		if value.ldap_object.session is None:
			add_to_session(value, self.__ldap_object.session)
		assert value.ldap_object.session == self.__ldap_object.session
		self.__ldap_object.attr_append(self.__name, value.dn)

	def discard(self, value):
		self.__modify_check(value)
		self.__ldap_object.attr_remove(self.__name, value.dn)

	def update(self, values):
		for value in values:
			self.add(value)

class Relationship:
	def __init__(self, name, destmodel, backref=None):
		self.name = name
		self.destmodel = destmodel
		self.backref = backref

	def __set_name__(self, cls, name):
		if self.backref is not None:
			setattr(self.destmodel, self.backref, Backreference(self.name, cls))

	def __get__(self, obj, objtype=None):
		if obj is None:
			return self
		return RelationshipSet(obj.ldap_object, self.name, type(obj), self.destmodel)

	def __set__(self, obj, values):
		tmp = self.__get__(obj)
		tmp.clear()
		for value in values:
			tmp.add(value)

class BackreferenceSet(MutableSet):
	def __init__(self, ldap_object, name, model, srcmodel):
		self.__ldap_object = ldap_object
		self.__name = name
		self.__model = model # pylint: disable=unused-private-member
		self.__srcmodel = srcmodel

	def __modify_check(self, value):
		if self.__ldap_object.session is None:
			raise UnboundObjectError()
		if not isinstance(value, self.__srcmodel):
			raise TypeError()

	def __get(self):
		if self.__ldap_object.session is None:
			return set()
		filter_params = list(self.__srcmodel.ldap_filter_params) + [(self.__name, self.__ldap_object.dn)]
		objs = self.__ldap_object.session.filter(self.__srcmodel.ldap_search_base, filter_params)
		return set(make_modelobjs(objs, self.__srcmodel))

	def __repr__(self):
		return repr(self.__get())

	def __contains__(self, value):
		return value in self.__get()

	def __iter__(self):
		return iter(self.__get())

	def __len__(self):
		return len(self.__get())

	def add(self, value):
		self.__modify_check(value)
		if value.ldap_object.session is None:
			add_to_session(value, self.__ldap_object.session)
		assert value.ldap_object.session == self.__ldap_object.session
		if self.__ldap_object.dn not in value.ldap_object.getattr(self.__name):
			value.ldap_object.attr_append(self.__name, self.__ldap_object.dn)

	def discard(self, value):
		self.__modify_check(value)
		value.ldap_object.attr_remove(self.__name, self.__ldap_object.dn)

	def update(self, values):
		for value in values:
			self.add(value)

class Backreference:
	def __init__(self, name, srcmodel):
		self.name = name
		self.srcmodel = srcmodel

	def __get__(self, obj, objtype=None):
		if obj is None:
			return self
		return BackreferenceSet(obj.ldap_object, self.name, type(obj), self.srcmodel)

	def __set__(self, obj, values):
		tmp = self.__get__(obj)
		tmp.clear()
		for value in values:
			tmp.add(value)

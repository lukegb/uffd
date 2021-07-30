from collections.abc import MutableSet

from .model import add_to_session

class DBRelationshipSet(MutableSet):
	def __init__(self, dbobj, relattr, ldapcls, mapcls):
		self.__dbobj = dbobj
		self.__relattr = relattr
		self.__ldapcls = ldapcls
		self.__mapcls = mapcls

	def __get_dns(self):
		return [mapobj.dn for mapobj in getattr(self.__dbobj, self.__relattr)]

	def __repr__(self):
		return repr(set(self))

	def __contains__(self, value):
		if value is None or not isinstance(value, self.__ldapcls):
			return False
		return value.ldap_object.dn in self.__get_dns()

	def __iter__(self):
		return iter(filter(lambda obj: obj is not None, [self.__ldapcls.query.get(dn) for dn in self.__get_dns()]))

	def __len__(self):
		return len(set(self))

	def add(self, value):
		if not isinstance(value, self.__ldapcls):
			raise TypeError()
		if value.ldap_object.session is None:
			add_to_session(value, self.__ldapcls.ldap_mapper.session.ldap_session)
		if value.ldap_object.dn not in self.__get_dns():
			getattr(self.__dbobj, self.__relattr).append(self.__mapcls(dn=value.ldap_object.dn))

	def discard(self, value):
		if not isinstance(value, self.__ldapcls):
			raise TypeError()
		rel = getattr(self.__dbobj, self.__relattr)
		for mapobj in list(rel):
			if mapobj.dn == value.ldap_object.dn:
				rel.remove(mapobj)

class DBRelationship:
	def __init__(self, relattr, ldapcls, mapcls=None, backref=None, backattr=None):
		self.relattr = relattr
		self.ldapcls = ldapcls
		self.mapcls = mapcls
		self.backref = backref
		self.backattr = backattr

	def __set_name__(self, cls, name):
		if self.backref:
			setattr(self.ldapcls, self.backref, DBBackreference(cls, self.relattr, self.mapcls, self.backattr))

	def __get__(self, obj, objtype=None):
		if obj is None:
			return self
		if self.mapcls is not None:
			return DBRelationshipSet(obj, self.relattr, self.ldapcls, self.mapcls)
		dn = getattr(obj, self.relattr)
		if dn is not None:
			return self.ldapcls.query.get(dn)
		return None

	def __set__(self, obj, values):
		if self.mapcls is not None:
			tmp = self.__get__(obj)
			tmp.clear()
			for value in values:
				tmp.add(value)
		else:
			if not isinstance(values, self.ldapcls):
				raise TypeError()
			setattr(obj, self.relattr, values.ldap_object.dn)

class DBBackreferenceSet(MutableSet):
	def __init__(self, ldapobj, dbcls, relattr, mapcls, backattr):
		self.__ldapobj = ldapobj
		self.__dbcls = dbcls
		self.__relattr = relattr
		self.__mapcls = mapcls
		self.__backattr = backattr

	@property
	def __dn(self):
		return self.__ldapobj.ldap_object.dn

	def __get(self):
		if self.__mapcls is None:
			return self.__dbcls.query.filter_by(**{self.__relattr: self.__dn}).all()
		return {getattr(mapobj, self.__backattr) for mapobj in self.__mapcls.query.filter_by(dn=self.__dn)}

	def __repr__(self):
		return repr(self.__get())

	def __contains__(self, value):
		return value in self.__get()

	def __iter__(self):
		return iter(self.__get())

	def __len__(self):
		return len(self.__get())

	def add(self, value):
		assert self.__ldapobj.ldap_object.session is not None
		if not isinstance(value, self.__dbcls):
			raise TypeError()
		if self.__mapcls is None:
			setattr(value, self.__relattr, self.__dn)
		else:
			rel = getattr(value, self.__relattr)
			if self.__dn not in {mapobj.dn for mapobj in rel}:
				rel.append(self.__mapcls(dn=self.__dn))

	def discard(self, value):
		if not isinstance(value, self.__dbcls):
			raise TypeError()
		if self.__mapcls is None:
			setattr(value, self.__relattr, None)
		else:
			rel = getattr(value, self.__relattr)
			for mapobj in list(rel):
				if mapobj.dn == self.__dn:
					rel.remove(mapobj)

class DBBackreference:
	def __init__(self, dbcls, relattr, mapcls=None, backattr=None):
		self.dbcls = dbcls
		self.relattr = relattr
		self.mapcls = mapcls
		self.backattr = backattr

	def __get__(self, obj, objtype=None):
		if obj is None:
			return self
		return DBBackreferenceSet(obj, self.dbcls, self.relattr, self.mapcls, self.backattr)

	def __set__(self, obj, values):
		tmp = self.__get__(obj)
		tmp.clear()
		for value in values:
			tmp.add(value)

from .types import LDAPSet

class DB2LDAPBackref:
	def __init__(self, baseattr, mapcls, backattr):
		self.baseattr = baseattr
		self.mapcls = mapcls
		self.backattr = backattr

	def getitems(self, ldapobj):
		return {getattr(mapobj, self.backattr) for mapobj in self.mapcls.query.filter_by(dn=ldapobj.dn)}

	def additem(self, ldapobj, dbobj):
		if dbobj not in self.getitems(ldapobj):
			getattr(dbobj, self.baseattr).append(self.mapcls(dn=ldapobj.dn))

	def delitem(self, ldapobj, dbobj):
		for mapobj in list(getattr(dbobj, self.baseattr)):
			if mapobj.dn == ldapobj.dn:
				getattr(dbobj, self.baseattr).remove(mapobj)

	def __get__(self, ldapobj, objtype=None):
		if ldapobj is None:
			return self
		return LDAPSet(getitems=lambda: self.getitems(ldapobj),
		               additem=lambda dbobj: self.additem(ldapobj, dbobj),
		               delitem=lambda dbobj: self.delitem(ldapobj, dbobj))

	def __set__(self, ldapobj, dbobjs):
		rel = self.__get__(ldapobj)
		rel.clear()
		for dbobj in dbobjs:
			rel.add(dbobj)

class DB2LDAPRelation:
	def __init__(self, baseattr, mapcls, ldapcls, backattr=None, backref=None):
		self.baseattr = baseattr
		self.mapcls = mapcls
		self.ldapcls = ldapcls
		if backref is not None:
			setattr(ldapcls, backref, DB2LDAPBackref(baseattr, mapcls, backattr))

	def getitems(self, dbobj):
		return {mapobj.dn for mapobj in getattr(dbobj, self.baseattr)}

	def additem(self, dbobj, dn):
		if dn not in self.getitems(dbobj):
			getattr(dbobj, self.baseattr).append(self.mapcls(dn=dn))

	def delitem(self, dbobj, dn):
		for mapobj in list(getattr(dbobj, self.baseattr)):
			if mapobj.dn == dn:
				getattr(dbobj, self.baseattr).remove(mapobj)

	def __get__(self, dbobj, objtype=None):
		if dbobj is None:
			return self
		return LDAPSet(getitems=lambda: self.getitems(dbobj),
		               additem=lambda dn: self.additem(dbobj, dn),
		               delitem=lambda dn: self.delitem(dbobj, dn),
		               encode=lambda ldapobj: ldapobj.dn,
		               decode=self.ldapcls.ldap_get)

	def __set__(self, dbobj, ldapobjs):
		getattr(dbobj, self.baseattr).clear()
		for ldapobj in ldapobjs:
			getattr(dbobj, self.baseattr).append(self.mapcls(dn=ldapobj.dn))

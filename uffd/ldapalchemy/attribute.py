from collections.abc import MutableSequence

class AttributeList(MutableSequence):
	def __init__(self, ldap_object, name, aliases):
		self.__ldap_object = ldap_object
		self.__name = name
		self.__aliases = [name] + aliases

	def __get(self):
		return list(self.__ldap_object.getattr(self.__name))

	def __set(self, values):
		for name in self.__aliases:
			self.__ldap_object.setattr(name, values)

	def __repr__(self):
		return repr(self.__get())

	def __setitem__(self, key, value):
		tmp = self.__get()
		tmp[key] = value
		self.__set(tmp)

	def __delitem__(self, key):
		tmp = self.__get()
		del tmp[key]
		self.__set(tmp)

	def __len__(self):
		return len(self.__get())

	def __getitem__(self, key):
		return self.__get()[key]

	def insert(self, index, value):
		tmp = self.__get()
		tmp.insert(index, value)
		self.__set(tmp)

class Attribute:
	def __init__(self, name, aliases=None, multi=False, default=None):
		self.name = name
		self.aliases = aliases if aliases is not None else []
		self.multi = multi
		self.default = default

	def add_hook(self, obj):
		if obj.ldap_object.getattr(self.name) == []:
			self.__set__(obj, self.default() if callable(self.default) else self.default)

	def __set_name__(self, cls, name):
		if self.default is not None:
			cls.ldap_add_hooks = cls.ldap_add_hooks + (self.add_hook,)

	def __get__(self, obj, objtype=None):
		if obj is None:
			return self
		if self.multi:
			return AttributeList(obj.ldap_object, self.name, self.aliases)
		return (obj.ldap_object.getattr(self.name) or [None])[0]

	def __set__(self, obj, values):
		if not self.multi:
			values = [values]
		for name in [self.name] + self.aliases:
			obj.ldap_object.setattr(name, values)

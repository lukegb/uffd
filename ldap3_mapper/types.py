from collections.abc import MutableSet

class LDAPCommitError(Exception):
	pass

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

	def update(self, values):
		for value in values:
			self.add(value)

from collections import UserString, UserList

from flask import current_app

class LazyConfigString(UserString):
	def __init__(self, seq=None, key=None, default=None, error=True):
		# pylint: disable=super-init-not-called
		self.__seq = seq
		self.__key = key
		self.__default = default
		self.__error = error

	@property
	def data(self):
		if self.__seq is not None:
			obj = self.__seq
		elif self.__error:
			obj = current_app.config[self.__key]
		else:
			obj = current_app.config.get(self.__key, self.__default)
		return str(obj)

	def __bytes__(self):
		return self.data.encode()

	def __get__(self, obj, owner=None):
		return self.data

def lazyconfig_str(key, **kwargs):
	return LazyConfigString(None, key, **kwargs)

class LazyConfigList(UserList):
	def __init__(self, seq=None, key=None, default=None, error=True):
		# pylint: disable=super-init-not-called
		self.__seq = seq
		self.__key = key
		self.__default = default
		self.__error = error

	@property
	def data(self):
		if self.__seq is not None:
			obj = self.__seq
		elif self.__error:
			obj = current_app.config[self.__key]
		else:
			obj = current_app.config.get(self.__key, self.__default)
		return obj

	def __get__(self, obj, owner=None):
		return self.data

def lazyconfig_list(key, **kwargs):
	return LazyConfigList(None, key, **kwargs)

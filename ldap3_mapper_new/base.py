from enum import Enum
from copy import deepcopy

class Status(Enum):
	NEW
	ADDED
	DELETED

class State:
	def __init__(self, status=Status.NEW, attributes=None):
		self.status = status
		self.attributes = attributes or {}

	def copy(self):
		return State(self.status, deepcopy(self.attributes))

class Operation:
	def apply(self, state):
		raise NotImplemented()

	def execute(self, conn):
		raise NotImplemented()

	def extend(self, oper):
		return False

class AddOperation(Operation):
	def __init__(self, attributes, ldap_object_classes):
		self.attributes = deepcopy(attributes)
		self.ldap_object_classes = ldap_object_classes

	def apply(self, state):
		state.status = Status.ADDED
		state.attributes = self.attributes

	def execute(self, dn, conn):
		success = conn.add(dn, self.ldap_object_classes, self.attributes)
		if not success:
			raise LDAPCommitError()

class DeleteOperation(Operation):
	def apply(self, state):
		state.status = Status.DELETED

	def execute(self, dn, conn):
		success = conn.delete(dn)
		if not success:
			raise LDAPCommitError()

class ModifyOperation(Operation):
	def __init__(self, changes):
		self.changes = deepcopy(changes)

	def apply(self, state):
		for attr, changes in self.changes.items():
			for action, values in changes:
				if action == MODIFY_REPLACE:
					state.attributes[attr] = values
				elif action == MODIFY_ADD:
					state.attributes[attr] += values
				elif action == MODIFY_DELETE:
					for value in values:
						state.attributes[attr].remove(value)

	def execute(self, dn, conn):
		success = conn.modify(dn, self.changes)
		if not success:
			raise LDAPCommitError()

class Session:
	ldap_mapper = None

	def __init__(self):
		self.__objects = {}
		self.__operations = []

	def record(self, obj, oper):
		if not self.__operations or self.__operations[0][0] != obj or not self.__operations[0][1].extend(oper):
			self.__operations.append((obj, oper))

	# TODO: maybe move the implementation to SessionObjectState?
	def add(self, obj):
		if obj.ldap_state.current.status != Status.NEW:
			return
		oper = AddOperation(obj.ldap_state.current.attributes, obj.ldap_object_classes)
		oper.apply(obj.ldap_state.current)
		self.__operations.append((obj, oper))

	# TODO: maybe move the implementation to SessionObjectState?
	def delete(self, obj):
		if obj.ldap_state.current.status != Status.ADDED:
			return
		oper = DeleteOperation()
		oper.apply(obj.ldap_state.current)
		self.__operations.append((obj, oper))

	def commit(self):
		conn = self.mapper.connect()
		while self.__operations:
			obj, oper = self.__operations.pop(0)
			try:
				oper.execute(obj.dn, conn)
			except e:
				self.__operations.insert(0, (obj, oper))
				raise e
			oper.apply(obj.ldap_state.committed)

	def rollback(self):
		while self.__operations:
			obj, oper = self.__operations.pop(0)
			obj.ldap_state.current = obj.ldap_state.committed.copy()

	def query_get(self, cls, dn):
		if dn in self.__objects:
			return self.__objects[dn]
		if dn in self.__deleted_objects:
			return None
		conn = self.mapper.connect()
		conn.search(dn, cls.ldap_filter, attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])
		if not conn.response:
			return None
		self.__objects[dn] = cls(__ldap_response=conn.response[0])
		return self.__objects[dn]

	def query_search(self, cls, filters=None):
		filters = [cls.ldap_filter] + (filters or [])
		if len(filters) == 1:
			expr = filters[0]
		else:
			expr = '(&%s)'%(''.join(filters))
		conn = self.mapper.connect()
		conn.search(cls.ldap_base, cls.ldap_filter, attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])
		res = []
		for response in conn.response:
			dn = response['dn']
			if dn in self.__objects:
				res.append(self.__objects[dn])
			elif dn in self.__deleted_objects:
				continue
			else:
				self.__objects[dn] = cls(__ldap_response=response)
				res.append(self.__objects[dn])
		return res

# This is only a seperate class to keep SessionObject's namespace cleaner
class SessionObjectState:
	def __init__(self, obj, response=None):
		self.obj = obj
		self.session = obj.ldap_mapper.session
		if response is not None:
			self.commited = State()
		else:
			self.commited = State(Status.ADDED, response['attributes'])
		self.current = self.commited.copy()

	def getattr(self, name):
		return self.current.attributes.get(name, [])

	def setattr(self, name, values):
		oper = ModifyOperation({name: [(MODIFY_REPLACE, [values])]})
		if self.current.status == Status.ADDED:
			self.session.record(self.obj, oper)
		oper.apply(self.current)

	def attr_append(self, name, value):
		oper = ModifyOperation({name: [(MODIFY_ADD, [value])]})
		if self.current.status == Status.ADDED:
			self.session.record(self.obj, oper)
		oper.apply(self.current)

	def attr_remove(self, name, value):
		# TODO: how does LDAP handle MODIFY_DELETE ops with non-existant values?
		oper = ModifyOperation({name: [(MODIFY_DELETE, [value])]})
		if self.current.status == Status.ADDED:
			self.session.record(self.obj, oper)
		oper.apply(self.current)

# This is only a seperate class to keep SessionObject's namespace cleaner
class SessionObject:
	ldap_mapper = None
	ldap_object_classes = None
	ldap_base = None
	ldap_filter = None

	def __init__(self, __ldap_response=None):
		self.ldap_state = SessionObjectState(self, __ldap_response)

	@property
	def dn(self):
		raise NotImplemented()

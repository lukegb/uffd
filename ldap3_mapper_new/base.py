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
		conn = self.ldap_mapper.connect()
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

class SessionObject:
	ldap_mapper = None
	ldap_object_classes = None

	def __init__(self, response=None):
		self.ldap_state = SessionObjectState(self, response)

	@property
	def dn(self):
		raise NotImplemented()

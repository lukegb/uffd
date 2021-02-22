from copy import deepcopy

from ldap3 import MODIFY_REPLACE, MODIFY_DELETE, MODIFY_ADD, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
from ldap3.utils.conv import escape_filter_chars

def encode_filter(params):
	return '(&%s)'%(''.join(['(%s=%s)'%(attr, escape_filter_chars(value)) for attr, value in params]))

def match_dn(dn, base):
	return dn.endswith(base) # Probably good enougth for all valid dns

class LDAPCommitError(Exception):
	pass

class SessionState:
	def __init__(self, objects=None, deleted_objects=None, references=None):
		self.objects = objects or {}
		self.deleted_objects = deleted_objects or {}
		self.references = references or {} # {(attr_name, value): {srcobj, ...}, ...}

	def copy(self):
		return SessionState(deepcopy(self.objects), deepcopy(self.deleted_objects), deepcopy(self.references))

	def ref(self, obj, attr, values):
		for value in values:
			key = (attr, value)
			if key not in self.references:
				self.references[key] = {obj}
			else:
				self.references[key].add(obj)

	def unref(self, obj, attr, values):
		for value in values:
			self.references.get((attr, value), set()).discard(obj)

class ObjectState:
	def __init__(self, session=None, attributes=None, dn=None):
		self.session = session
		self.attributes = attributes or {}
		self.dn = dn

	def copy(self):
		return ObjectState(attributes=deepcopy(self.attributes), dn=self.dn, session=self.session)

class AddOperation:
	def __init__(self, obj, dn, object_classes):
		self.obj = obj
		self.dn = dn
		self.object_classes = object_classes
		self.attributes = deepcopy(obj.state.attributes)

	def apply_object(self, obj_state):
		obj_state.dn = self.dn
		obj_state.attributes = deepcopy(self.attributes)

	def apply_session(self, session_state):
		assert self.dn not in session_state.objects
		session_state.objects[self.dn] = self.obj
		for name, values in self.attributes.items():
			session_state.ref(self.obj, name, values)

	def apply_ldap(self, conn):
		success = conn.add(self.dn, self.object_classes, self.attributes)
		if not success:
			raise LDAPCommitError()

class DeleteOperation:
	def __init__(self, obj):
		self.dn = obj.state.dn
		self.obj = obj
		self.attributes = deepcopy(obj.state.attributes)

	def apply_object(self, obj_state):
		obj_state.dn = None

	def apply_session(self, session_state):
		assert self.dn in session_state.objects
		del session_state.objects[self.dn]
		session_state.deleted_objects[self.dn] = self.obj
		for name, values in self.attributes.items():
			session_state.unref(self.obj, name, values)

	def apply_ldap(self, conn):
		success = conn.delete(self.dn)
		if not success:
			raise LDAPCommitError()

class ModifyOperation:
	def __init__(self, obj, changes):
		self.obj = obj
		self.attributes = deepcopy(obj.state.attributes)
		self.changes = deepcopy(changes)

	def apply_object(self, obj_state):
		for attr, changes in self.changes.items():
			for action, values in changes:
				if action == MODIFY_REPLACE:
					obj_state.attributes[attr] = values
				elif action == MODIFY_ADD:
					obj_state.attributes[attr] += values
				elif action == MODIFY_DELETE:
					for value in values:
						if value in obj_state.attributes[attr]:
							obj_state.attributes[attr].remove(value)

	def apply_session(self, session_state):
		for attr, changes in self.changes.items():
			for action, values in changes:
				if action == MODIFY_REPLACE:
					session_state.unref(self.obj, attr, self.attributes.get(attr, []))
					session_state.ref(self.obj, attr, values)
				elif action == MODIFY_ADD:
					session_state.ref(self.obj, attr, values)
				elif action == MODIFY_DELETE:
					session_state.unref(self.obj, attr, values)

	def apply_ldap(self, conn):
		success = conn.modify(self.obj.state.dn, self.changes)
		if not success:
			raise LDAPCommitError()

class Session:
	def __init__(self, get_connection):
		self.get_connection = get_connection
		self.committed_state = SessionState()
		self.state = SessionState()
		self.changes = []

	def add(self, obj, dn, object_classes):
		if self.state.objects.get(dn) == obj:
			return
		assert obj.state.session is None
		oper = AddOperation(obj, dn, object_classes)
		oper.apply_object(obj.state)
		obj.state.session = self
		oper.apply_session(self.state)
		self.changes.append(oper)

	def delete(self, obj):
		if obj.state.dn not in self.state.objects:
			return
		assert obj.state.session == self
		oper = DeleteOperation(obj)
		oper.apply_object(obj.state)
		obj.state.session = None
		oper.apply_session(self.state)
		self.changes.append(oper)

	def record(self, oper):
		assert oper.obj.state.session == self
		self.changes.append(oper)

	def commit(self):
		conn = self.get_connection()
		while self.changes:
			oper = self.changes.pop(0)
			try:
				oper.apply_ldap(conn)
			except Exception as err:
				self.changes.insert(0, oper)
				raise err
			oper.apply_object(oper.obj.committed_state)
			oper.apply_session(self.committed_state)
		self.committed_state = self.state.copy()

	def rollback(self):
		for obj in self.state.objects.values():
			obj.state = obj.committed_state.copy()
		for obj in self.state.deleted_objects.values():
			obj.state = obj.committed_state.copy()
		self.state = self.committed_state.copy()
		self.changes.clear()

	def get(self, dn, filter_params):
		if dn in self.state.objects:
			obj = self.state.objects[dn]
			return obj if obj.matches(filter_params) else None
		if dn in self.state.deleted_objects:
			return None
		conn = self.get_connection()
		conn.search(dn, encode_filter(filter_params), attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])
		if not conn.response:
			return None
		assert len(conn.response) == 1
		assert conn.response[0]['dn'] == dn
		obj = Object(self, conn.response[0])
		self.state.objects[dn] = obj
		self.committed_state.objects[dn] = obj
		for attr, values in obj.state.attributes.items():
			self.state.ref(obj, attr, values)
		return obj

	def filter_local(self, search_base, filter_params):
		if not filter_params:
			matches = self.state.objects.values()
		else:
			submatches = [self.state.references.get((attr, value), set()) for attr, value in filter_params]
			matches = submatches.pop(0)
			while submatches:
				matches = matches.intersection(submatches.pop(0))
		return [obj for obj in matches if match_dn(obj.state.dn, search_base)]

	def filter(self, search_base, filter_params):
		conn = self.get_connection()
		conn.search(search_base, encode_filter(filter_params), attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])
		res = []
		for response in conn.response:
			dn = response['dn']
			if dn in self.state.objects or dn in self.state.deleted_objects:
				continue
			obj = Object(self, response)
			self.state.objects[dn] = obj
			self.committed_state.objects[dn] = obj
			for attr, values in obj.state.attributes.items():
				self.state.ref(obj, attr, values)
			res.append(obj)
		return res + self.filter_local(search_base, filter_params)

class Object:
	def __init__(self, session=None, response=None):
		if response is None:
			self.committed_state = ObjectState()
		else:
			assert session is not None
			attrs = {attr: value if isinstance(value, list) else [value] for attr, value in response['attributes'].items()}
			self.committed_state = ObjectState(session, attrs, response['dn'])
		self.state = self.committed_state.copy()

	@property
	def dn(self):
		return self.state.dn

	@property
	def session(self):
		return self.state.session

	def getattr(self, name):
		return self.state.attributes.get(name, [])

	def setattr(self, name, values):
		oper = ModifyOperation(self, {name: [(MODIFY_REPLACE, values)]})
		oper.apply_object(self.state)
		if self.state.session:
			oper.apply_session(self.state.session.state)
			self.state.session.changes.append(oper)

	def attr_append(self, name, value):
		oper = ModifyOperation(self, {name: [(MODIFY_ADD, [value])]})
		oper.apply_object(self.state)
		if self.state.session:
			oper.apply_session(self.state.session.state)
			self.state.session.changes.append(oper)

	def attr_remove(self, name, value):
		oper = ModifyOperation(self, {name: [(MODIFY_DELETE, [value])]})
		oper.apply_object(self.state)
		if self.state.session:
			oper.apply_session(self.state.session.state)
			self.state.session.changes.append(oper)

	def match(self, filter_params):
		for attr, value in filter_params:
			if value not in self.getattr(attr):
				return False
		return True

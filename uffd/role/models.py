from operator import attrgetter

from sqlalchemy import Column, String, Integer, Text, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declared_attr

from uffd.database import db
from uffd.user import User, Group

class Role(db.Model):
	__tablename__ = 'role'
	id = Column(Integer(), primary_key=True, autoincrement=True)
	name = Column(String(32), unique=True)
	description = Column(Text())
	members = relationship("RoleUser", backref="role", cascade="all, delete-orphan")
	groups = relationship("RoleGroup", backref="role", cascade="all, delete-orphan")

	def __init__(self, name='', description=''):
		self.name = name
		self.description = description

	def group_dns(self):
		return map(attrgetter('dn'), self.groups)
	def member_dns(self):
		return map(attrgetter('dn'), self.members)

class LdapMapping():
	id = Column(Integer(), primary_key=True, autoincrement=True)
	dn = Column(String(128))
	__table_args__ = (
		db.UniqueConstraint('dn', 'role_id'),
	)
	@declared_attr
	def role_id(self):
		return Column(ForeignKey('role.id'))
	ldapclass = None

	def get_ldap(self):
		return self.ldapclass.from_ldap_dn(self.dn)

	def set_ldap(self, value):
		self.dn = value['dn']

class RoleGroup(LdapMapping, db.Model):
	__tablename__ = 'role-group'
	ldapclass = User

class RoleUser(LdapMapping, db.Model):
	__tablename__ = 'role-user'
	ldapclass = Group

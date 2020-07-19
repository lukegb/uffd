from operator import attrgetter

from sqlalchemy import Column, String, Integer, Text, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declared_attr

from uffd.database import db
from uffd.user.models import User, Group

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

	@classmethod
	def get_for_user(cls, user):
		return Role.query.join(Role.members, aliased=True).filter_by(dn=user.dn)

	def member_ldap(self):
		result = []
		for dn in self.member_dns():
			result.append(User.from_ldap_dn(dn))
		return result
	def member_dns(self):
		return list(map(attrgetter('dn'), self.members))
	def add_member(self, member):
		newmapping = RoleUser(member.dn, self)
		self.members.append(newmapping)
	def del_member(self, member):
		for i in self.members:
			if i.dn == member.dn:
				self.members.remove(i)
				break

	def group_dns(self):
		return list(map(attrgetter('dn'), self.groups))
	def add_group(self, group):
		newmapping = RoleGroup(group.dn, self)
		self.groups.append(newmapping)
	def del_group(self, group):
		for i in self.groups:
			if i.dn == group.dn:
				self.groups.remove(i)
				break

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

	def __init__(self, dn='', role=''):
		self.dn = dn
		self.role = role

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

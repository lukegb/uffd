from sqlalchemy import Column, String, Integer, Text, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declared_attr

from uffd.database import db
from uffd.ldap import DB2LDAPRelation
from uffd.user.models import User, Group

class LdapMapping:
	id = Column(Integer(), primary_key=True, autoincrement=True)
	dn = Column(String(128))
	__table_args__ = (
		db.UniqueConstraint('dn', 'role_id'),
	)
	@declared_attr
	def role_id(self):
		return Column(ForeignKey('role.id'))

class RoleGroup(LdapMapping, db.Model):
	pass

class RoleUser(LdapMapping, db.Model):
	pass

def update_user_groups(user):
	user.groups.clear()
	for role in user.roles:
		user.groups.update(role.groups)

User.update_groups = update_user_groups

class Role(db.Model):
	__tablename__ = 'role'
	id = Column(Integer(), primary_key=True, autoincrement=True)
	name = Column(String(32), unique=True)
	description = Column(Text(), default='')

	db_members = relationship("RoleUser", backref="role", cascade="all, delete-orphan")
	members = DB2LDAPRelation('db_members', RoleUser, User, backattr='role', backref='roles')

	db_groups = relationship("RoleGroup", backref="role", cascade="all, delete-orphan")
	groups = DB2LDAPRelation('db_groups', RoleGroup, Group, backattr='role', backref='roles')

	def update_member_groups(self):
		for user in self.members:
			user.update_groups()

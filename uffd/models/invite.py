import datetime

from flask_babel import gettext as _
from flask import current_app
from sqlalchemy import Column, String, Integer, ForeignKey, DateTime, Boolean
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import relationship

from uffd.utils import token_urlfriendly
from uffd.database import db
from .signup import Signup

invite_roles = db.Table('invite_roles',
	Column('invite_id', Integer(), ForeignKey('invite.id', onupdate='CASCADE', ondelete='CASCADE'), primary_key=True),
	Column('role_id', Integer, ForeignKey('role.id', onupdate='CASCADE', ondelete='CASCADE'), primary_key=True)
)

class Invite(db.Model):
	__tablename__ = 'invite'
	id = Column(Integer(), primary_key=True, autoincrement=True)
	token = Column(String(128), unique=True, nullable=False, default=token_urlfriendly)
	created = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
	creator_id = Column(Integer(), ForeignKey('user.id', onupdate='CASCADE'), nullable=True)
	creator = relationship('User')
	valid_until = Column(DateTime, nullable=False)
	single_use = Column(Boolean(create_constraint=True), default=True, nullable=False)
	allow_signup = Column(Boolean(create_constraint=True), default=True, nullable=False)
	used = Column(Boolean(create_constraint=True), default=False, nullable=False)
	disabled = Column(Boolean(create_constraint=True), default=False, nullable=False)
	roles = relationship('Role', secondary=invite_roles)
	signups = relationship('InviteSignup', back_populates='invite', lazy=True, cascade='all, delete-orphan')
	grants = relationship('InviteGrant', back_populates='invite', lazy=True, cascade='all, delete-orphan')

	@hybrid_property
	def expired(self):
		return self.valid_until < datetime.datetime.utcnow().replace(second=0, microsecond=0)

	@hybrid_property
	def voided(self):
		return self.single_use and self.used

	@property
	def permitted(self):
		if self.creator is None:
			return False # Creator does not exist (anymore)
		if self.creator.is_deactivated:
			return False
		if self.creator.is_in_group(current_app.config['ACL_ADMIN_GROUP']):
			return True
		if self.allow_signup and not self.creator.is_in_group(current_app.config['ACL_SIGNUP_GROUP']):
			return False
		for role in self.roles:
			if role.moderator_group is None or role.moderator_group not in self.creator.groups:
				return False
		return True

	@property
	def active(self):
		return not self.disabled and not self.voided and not self.expired and self.permitted

	@property
	def short_token(self):
		if len(self.token) < 30:
			return '<too short>'
		return self.token[:10] + '…'

	def disable(self):
		self.disabled = True

	def reset(self):
		self.disabled = False
		self.used = False

class InviteGrant(db.Model):
	__tablename__ = 'invite_grant'
	id = Column(Integer(), primary_key=True, autoincrement=True)
	invite_id = Column(Integer(), ForeignKey('invite.id', onupdate='CASCADE', ondelete='CASCADE'), nullable=False)
	invite = relationship('Invite', back_populates='grants')
	user_id = Column(Integer(), ForeignKey('user.id', onupdate='CASCADE', ondelete='CASCADE'), nullable=False)
	user = relationship('User')

	def apply(self):
		if not self.invite.active:
			return False, _('Invite link is invalid')
		if not self.invite.roles:
			return False, _('Invite link does not grant any roles')
		if set(self.invite.roles).issubset(self.user.roles):
			return False, _('Invite link does not grant any new roles')
		for role in self.invite.roles:
			self.user.roles.append(role)
		self.user.update_groups()
		self.invite.used = True
		return True, _('Success')

class InviteSignup(Signup):
	__tablename__ = 'invite_signup'
	id = Column(Integer(), ForeignKey('signup.id', onupdate='CASCADE', ondelete='CASCADE'), primary_key=True)
	invite_id = Column(Integer(), ForeignKey('invite.id', onupdate='CASCADE', ondelete='CASCADE'), nullable=False)
	invite = relationship('Invite', back_populates='signups')

	__mapper_args__ = {
		'polymorphic_identity': 'InviteSignup'
	}

	def validate(self):
		if not self.invite.active or not self.invite.allow_signup:
			return False, _('Invite link is invalid')
		return super().validate()

	def finish(self, password):
		if not self.invite.active or not self.invite.allow_signup:
			return None, _('Invite link is invalid')
		user, msg = super().finish(password)
		if user is not None:
			for role in self.invite.roles:
				user.roles.append(role)
			user.update_groups()
			self.invite.used = True
		return user, msg

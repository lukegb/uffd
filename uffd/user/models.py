import secrets
import string
import re
import hashlib
import base64

from flask import current_app, escape
from flask_babel import lazy_gettext
from sqlalchemy import Column, Integer, String, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.sql.expression import func

from uffd.database import db

# Interface inspired by argon2-cffi
class PasswordHasher:
	# pylint: disable=no-self-use
	def hash(self, password):
		salt = secrets.token_bytes(8)
		ctx = hashlib.sha512()
		ctx.update(password.encode())
		ctx.update(salt)
		return '{ssha512}'+base64.b64encode(ctx.digest()+salt).decode()

	def verify(self, hash, password):
		if hash is None:
			return False
		if hash.startswith('{ssha512}'):
			data = base64.b64decode(hash[len('{ssha512}'):].encode())
			ctx = hashlib.sha512()
			digest = data[:ctx.digest_size]
			salt = data[ctx.digest_size:]
			ctx.update(password.encode())
			ctx.update(salt)
			return secrets.compare_digest(digest, ctx.digest())
		return False

	# pylint: disable=unused-argument
	def check_needs_rehash(self, hash):
		return False

def get_next_unix_uid(context):
	is_service_user = bool(context.get_current_parameters().get('is_service_user', False))
	if is_service_user:
		min_uid = current_app.config['USER_SERVICE_MIN_UID']
		max_uid = current_app.config['USER_SERVICE_MAX_UID']
	else:
		min_uid = current_app.config['USER_MIN_UID']
		max_uid = current_app.config['USER_MAX_UID']
	next_uid = max(min_uid,
	               db.session.query(func.max(User.unix_uid + 1))\
	                         .filter(User.is_service_user==is_service_user)\
	                         .scalar() or 0)
	if next_uid > max_uid:
		raise Exception('No free uid found')
	return next_uid

# pylint: disable=E1101
user_groups = db.Table('user_groups',
	Column('user_id', Integer(), ForeignKey('user.id', onupdate='CASCADE', ondelete='CASCADE'), primary_key=True),
	Column('group_id', Integer(), ForeignKey('group.id', onupdate='CASCADE', ondelete='CASCADE'), primary_key=True)
)

class User(db.Model):
	# Allows 8 to 256 ASCII letters (lower and upper case), digits, spaces and
	# symbols/punctuation characters. It disallows control characters and
	# non-ASCII characters to prevent setting passwords considered invalid by
	# SASLprep.
	#
	# This REGEX ist used both in Python and JS.
	PASSWORD_REGEX = '[ -~]*'
	PASSWORD_MINLEN = 8
	PASSWORD_MAXLEN = 256
	PASSWORD_DESCRIPTION = lazy_gettext('At least %(minlen)d and at most %(maxlen)d characters. ' + \
	                                    'Only letters, digits, spaces and some symbols (<code>%(symbols)s</code>) allowed. ' + \
	                                    'Please use a password manager.',
	                                    minlen=PASSWORD_MINLEN, maxlen=PASSWORD_MAXLEN, symbols=escape('!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'))

	__tablename__ = 'user'
	id = Column(Integer(), primary_key=True, autoincrement=True)
	unix_uid = Column(Integer(), unique=True, nullable=False, default=get_next_unix_uid)
	loginname = Column(String(32), unique=True, nullable=False)
	displayname = Column(String(128), nullable=False)
	mail = Column(String(128), nullable=False)
	pwhash = Column(String(256), nullable=True)
	is_service_user = Column(Boolean(), default=False, nullable=False)
	groups = relationship('Group', secondary='user_groups')
	roles = relationship('Role', secondary='role_members', back_populates='members')

	@property
	def unix_gid(self):
		return current_app.config['USER_GID']

	# Write-only property
	def password(self, value):
		self.pwhash = PasswordHasher().hash(value)
	password = property(fset=password)

	def check_password(self, value):
		return PasswordHasher().verify(self.pwhash, value)

	def is_in_group(self, name):
		if not name:
			return True
		for group in self.groups:
			if group.name == name:
				return True
		return False

	def has_permission(self, required_group=None):
		if not required_group:
			return True
		group_names = {group.name for group in self.groups}
		group_sets = required_group
		if isinstance(group_sets, str):
			group_sets = [group_sets]
		for group_set in group_sets:
			if isinstance(group_set, str):
				group_set = [group_set]
			if set(group_set) - group_names == set():
				return True
		return False

	def set_loginname(self, value, ignore_blocklist=False):
		if len(value) > 32 or len(value) < 1:
			return False
		for char in value:
			if not char in string.ascii_lowercase + string.digits + '_-':
				return False
		if not ignore_blocklist:
			for expr in current_app.config['LOGINNAME_BLOCKLIST']:
				if re.match(expr, value):
					return False
		self.loginname = value
		return True

	def set_displayname(self, value):
		if len(value) > 128 or len(value) < 1:
			return False
		self.displayname = value
		return True

	def set_password(self, value):
		if len(value) < self.PASSWORD_MINLEN or len(value) > self.PASSWORD_MAXLEN or not re.fullmatch(self.PASSWORD_REGEX, value):
			return False
		self.password = value
		return True

	def set_mail(self, value):
		if len(value) < 3 or '@' not in value:
			return False
		self.mail = value
		return True

	# Somehow pylint non-deterministically fails to detect that .update_groups is set in invite.modes
	def update_groups(self):
		pass

def get_next_unix_gid():
	next_gid = max(current_app.config['GROUP_MIN_GID'],
	               db.session.query(func.max(Group.unix_gid + 1)).scalar() or 0)
	if next_gid > current_app.config['GROUP_MAX_GID']:
		raise Exception('No free gid found')
	return next_gid

class Group(db.Model):
	__tablename__ = 'group'
	id = Column(Integer(), primary_key=True, autoincrement=True)
	unix_gid = Column(Integer(), unique=True, nullable=False, default=get_next_unix_gid)
	name = Column(String(32), unique=True, nullable=False)
	description = Column(String(128), nullable=False, default='')
	members = relationship('User', secondary='user_groups')

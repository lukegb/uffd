import string
import re
import datetime
import unicodedata

from flask import current_app, escape
from flask_babel import lazy_gettext
from sqlalchemy import Column, Integer, String, ForeignKey, Boolean, Text, DateTime
from sqlalchemy.orm import relationship, validates
from sqlalchemy.ext.hybrid import hybrid_property

from uffd.database import db
from uffd.remailer import remailer
from uffd.utils import token_urlfriendly
from uffd.password_hash import PasswordHashAttribute, LowEntropyPasswordHash, HighEntropyPasswordHash
from .misc import FeatureFlag

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
	# Default is set in event handler below
	unix_uid = Column(Integer(), unique=True, nullable=False)
	loginname = Column(String(32), unique=True, nullable=False)
	displayname = Column(String(128), nullable=False)

	all_emails = relationship(
		'UserEmail',
		foreign_keys='UserEmail.user_id',
		cascade='all, delete-orphan',
		back_populates='user',
		post_update=True,
	)
	verified_emails = relationship(
		'UserEmail',
		foreign_keys='UserEmail.user_id',
		viewonly=True,
		primaryjoin='and_(User.id == UserEmail.user_id, UserEmail.verified)',
	)

	primary_email_id = Column(Integer(), ForeignKey('user_email.id', onupdate='CASCADE'), nullable=False)
	primary_email = relationship('UserEmail', foreign_keys='User.primary_email_id')

	# recovery_email_id == NULL -> use primary email
	recovery_email_id = Column(Integer(), ForeignKey('user_email.id', onupdate='CASCADE', ondelete='SET NULL'))
	recovery_email = relationship('UserEmail', foreign_keys='User.recovery_email_id')

	@validates('primary_email', 'recovery_email')
	def validate_email(self, key, value):
		if value is not None:
			if not value.user:
				value.user = self
			if value.user != self:
				raise ValueError(f'UserEmail assigned to User.{key} is not associated with user')
			if not value.verified:
				raise ValueError(f'UserEmail assigned to User.{key} is not verified')
		return  value

	_password = Column('pwhash', Text(), nullable=True)
	password = PasswordHashAttribute('_password', LowEntropyPasswordHash)
	is_service_user = Column(Boolean(), default=False, nullable=False)
	groups = relationship('Group', secondary='user_groups', back_populates='members')
	roles = relationship('Role', secondary='role_members', back_populates='members')

	service_users = relationship('ServiceUser', viewonly=True)

	def __init__(self, primary_email_address=None, **kwargs):
		super().__init__(**kwargs)
		if primary_email_address is not None:
			self.primary_email = UserEmail(address=primary_email_address, verified=True)

	@property
	def unix_gid(self):
		return current_app.config['USER_GID']

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

	def set_primary_email_address(self, address):
		# UserEmail.query.filter_by(user=self, address=address).first() would cause
		# a flush, so we do this in python. A flush would cause an IntegrityError if
		# this method is used a new User object, since primary_email_id is not
		# nullable.
		email = ([item for item in self.all_emails if item.address == address] or [None])[0]
		if not email:
			email = UserEmail()
			if not email.set_address(address):
				return False
		email.verified = True
		self.primary_email = email
		return True

	# Somehow pylint non-deterministically fails to detect that .update_groups is set in role.models
	def update_groups(self):
		pass

class UserEmail(db.Model):
	__tablename__ = 'user_email'
	id = Column(Integer(), primary_key=True, autoincrement=True)

	# We have a cyclic dependency between User.primary_email and UserEmail.user.
	# To solve this, we make UserEmail.user nullable, add validators, and set
	# post_update=True here and for the backref.
	user_id = Column(Integer(), ForeignKey('user.id', onupdate='CASCADE', ondelete='CASCADE', use_alter=True))
	user = relationship('User', foreign_keys='UserEmail.user_id', back_populates='all_emails', post_update=True)

	@validates('user')
	def validate_user(self, key, value): # pylint: disable=unused-argument
		if self.user is not None and self.user != value:
			raise ValueError('UserEmail.user cannot be changed once set')
		return value

	@classmethod
	def normalize_address(cls, value):
		return unicodedata.normalize('NFKC', value).lower().strip()

	address = Column(String(128), nullable=False)
	address_normalized = Column(String(128), nullable=False)

	@validates('address')
	def validate_address(self, key, value): # pylint: disable=unused-argument
		if self.address is not None and self.address != value:
			raise ValueError('UserEmail.address cannot be changed once set')
		self.address_normalized = self.normalize_address(value)
		return value

	# True or None/NULL (not False, see constraints below)
	_verified = Column('verified', Boolean(), nullable=True)

	@hybrid_property
	def verified(self):
		# pylint: disable=singleton-comparison
		return self._verified != None

	@verified.setter
	def verified(self, value):
		if self._verified and not value:
			raise ValueError('UserEmail cannot be unverified once verified')
		self._verified = True if value else None

	verification_legacy_id = Column(Integer()) # id of old MailToken
	_verification_secret = Column('verification_secret', Text())
	verification_secret = PasswordHashAttribute('_verification_secret', HighEntropyPasswordHash)
	verification_expires = Column(DateTime)

	# Until uffd v3, we make the stricter unique constraints optional, by having
	# enable_strict_constraints act as a switch to enable/disable the constraints
	# on a per-row basis.
	# True or None/NULL if disabled (not False, see constraints below)
	enable_strict_constraints = Column(
		Boolean(),
		nullable=True,
		default=db.select([db.case([(FeatureFlag.unique_email_addresses.expr, True)], else_=None)])
	)

	# The unique constraints rely on the common interpretation of SQL92, that if
	# any column in a unique constraint is NULL, the unique constraint essentially
	# does not apply to the row. This is how SQLite, MySQL/MariaDB, PostgreSQL and
	# other common databases behave. A few others like Microsoft SQL Server do not
	# follow this, but we don't support them anyway.
	__table_args__ = (
		# A user cannot have the same address more than once, regardless of verification status
		db.UniqueConstraint('user_id', 'address', name='uq_user_email_user_id_address'), # Legacy, to be removed in v3
		# Same unique constraint as uq_user_email_user_id_address, but with
		# address_normalized instead of address. Only active if
		# enable_strict_constraints is not NULL.
		db.UniqueConstraint('user_id', 'address_normalized', 'enable_strict_constraints',
			name='uq_user_email_user_id_address_normalized'),
		# The same verified address can only exist once. Only active if
		# enable_strict_constraints is not NULL. Unverified addresses are ignored,
		# since verified is NULL in that case.
		db.UniqueConstraint('address_normalized', 'verified', 'enable_strict_constraints',
			name='uq_user_email_address_normalized_verified'),
	)

	def set_address(self, value):
		if len(value) < 3 or '@' not in value:
			return False
		domain = value.rsplit('@', 1)[-1]
		if remailer.is_remailer_domain(domain):
			return False
		self.address = value
		return True

	def start_verification(self):
		if self.verified:
			raise Exception('UserEmail.start_verification must not be called if address is already verified')
		self.verification_legacy_id = None
		secret = token_urlfriendly()
		self.verification_secret = secret
		self.verification_expires = datetime.datetime.utcnow() + datetime.timedelta(days=2)
		return secret

	@hybrid_property
	def verification_expired(self):
		if self.verification_expires is None:
			return True
		return self.verification_expires < datetime.datetime.utcnow()

	def finish_verification(self, secret):
		# pylint: disable=using-constant-test
		if self.verification_expired:
			return False
		if not self.verification_secret.verify(secret):
			return False
		self.verification_legacy_id = None
		self.verification_secret = None
		self.verification_expires = None
		self.verified = True
		return True

@FeatureFlag.unique_email_addresses.enable_hook
def enable_unique_email_addresses():
	UserEmail.query.update({UserEmail.enable_strict_constraints: True})

@FeatureFlag.unique_email_addresses.disable_hook
def disable_unique_email_addresses():
	UserEmail.query.update({UserEmail.enable_strict_constraints: None})

def next_id_expr(column, min_value, max_value):
	# db.func.max(column) + 1: highest used value in range + 1, NULL if no values in range
	# db.func.min(..., max_value): clip to range
	# db.func.coalesce(..., min_value): if NULL use min_value
	# if range is exhausted, evaluates to max_value that violates the UNIQUE constraint
	return db.select([db.func.coalesce(db.func.min(db.func.max(column) + 1, max_value), min_value)])\
	         .where(column >= min_value)\
	         .where(column <= max_value)

# Emulates the behaviour of Column.default. We cannot use a static SQL
# expression like we do for Group.unix_gid, because we need context
# information. We also cannot set Column.default to a callable, because
# SQLAlchemy always treats the return value as a literal value and does
# not allow SQL expressions.
@db.event.listens_for(User, 'before_insert')
def set_default_unix_uid(mapper, connect, target):
	# pylint: disable=unused-argument
	if target.unix_uid is not None:
		return
	if target.is_service_user:
		min_uid = current_app.config['USER_SERVICE_MIN_UID']
		max_uid = current_app.config['USER_SERVICE_MAX_UID']
	else:
		min_uid = current_app.config['USER_MIN_UID']
		max_uid = current_app.config['USER_MAX_UID']
	target.unix_uid = next_id_expr(User.unix_uid, min_uid, max_uid)

group_table = db.table('group', db.column('unix_gid'))
min_gid = db.bindparam('min_gid', unique=True, callable_=lambda: current_app.config['GROUP_MIN_GID'], type_=db.Integer)
max_gid = db.bindparam('max_gid', unique=True, callable_=lambda: current_app.config['GROUP_MAX_GID'], type_=db.Integer)

class Group(db.Model):
	__tablename__ = 'group'
	id = Column(Integer(), primary_key=True, autoincrement=True)
	unix_gid = Column(Integer(), unique=True, nullable=False, default=next_id_expr(group_table.c.unix_gid, min_gid, max_gid))
	name = Column(String(32), unique=True, nullable=False)
	description = Column(String(128), nullable=False, default='')
	members = relationship('User', secondary='user_groups', back_populates='groups')

	def set_name(self, value):
		if len(value) > 32 or len(value) < 1:
			return False
		for char in value:
			if not char in string.ascii_lowercase + string.digits + '_-':
				return False
		self.name = value
		return True

import datetime
from crypt import crypt

from sqlalchemy import Column, String, Text, DateTime

from uffd.ldapalchemy.dbutils import DBRelationship
from uffd.database import db
from uffd.ldap import ldap
from uffd.user.models import User
from uffd.utils import token_urlfriendly

class Signup(db.Model):
	'''Model that represents a self-signup request

	When a person tries to sign up, an instance with user-provided loginname,
	displayname, mail and password is created. Signup.validate is called to
	validate the request. To ensure that person is in control of the provided
	mail address, a mail with Signup.token is sent to that address. To complete
	the signup, Signup.finish is called with a user-provided password that must
	be equal to the initial password.

	Signup.token requires the password again so that a mistyped-but-valid mail
	address does not allow a third party to complete the signup procedure and
	set a new password with the (also mail-based) password reset functionality.

	As long as they are not completed, signup requests have no effect each other
	or different parts of the application.'''
	__tablename__ = 'signup'
	token = Column(String(128), primary_key=True, default=token_urlfriendly)
	created = Column(DateTime, default=datetime.datetime.now, nullable=False)
	loginname = Column(Text)
	displayname = Column(Text)
	mail = Column(Text)
	pwhash = Column(Text)
	user_dn = Column(String(128)) # Set after successful confirmation
	user = DBRelationship('user_dn', User, backref='signups')

	type = Column(String(50))
	__mapper_args__ = {
		'polymorphic_identity': 'Signup',
		'polymorphic_on': type
	}

	# Write-only property
	def password(self, value):
		if not User().set_password(value):
			return
		self.pwhash = crypt(value)
	password = property(fset=password)

	def check_password(self, value):
		return self.pwhash is not None and crypt(value, self.pwhash) == self.pwhash

	@property
	def expired(self):
		return self.created is not None and datetime.datetime.now() >= self.created + datetime.timedelta(hours=48)

	@property
	def completed(self):
		return self.user_dn is not None

	def validate(self): # pylint: disable=too-many-return-statements
		'''Return whether the signup request is valid and Signup.finish is likely to succeed

		:returns: Tuple (valid, errmsg), if the signup request is invalid, `valid`
		          is False and `errmsg` contains a string describing why. Otherwise
		          `valid` is True.'''
		if self.completed or self.expired:
			return False, 'Invalid signup request'
		if not User().set_loginname(self.loginname):
			return False, 'Login name is invalid'
		if not User().set_displayname(self.displayname):
			return False, 'Display name is invalid'
		if not User().set_mail(self.mail):
			return False, 'Mail address is invalid'
		if self.pwhash is None:
			return False, 'Invalid password'
		if User.query.filter_by(loginname=self.loginname).all():
			return False, 'A user with this login name already exists'
		return True, 'Valid'

	def finish(self, password):
		'''Complete the signup procedure and return the new user

		Signup.finish should only be called on an object that was (at some point)
		successfully validated with Signup.validate!

		:param password: User password

		:returns: Tuple (user, errmsg), if the operation fails, `user` is None and
		          `errmsg` contains a string describing why. Otherwise `user` is a
		          User object.'''
		if self.completed or self.expired:
			return None, 'Invalid signup request'
		if not self.check_password(password):
			return None, 'Wrong password'
		if User.query.filter_by(loginname=self.loginname).all():
			return None, 'A user with this login name already exists'
		user = User(loginname=self.loginname, displayname=self.displayname, mail=self.mail, password=password)
		ldap.session.add(user)
		user.update_groups()
		self.user = user
		self.loginname = None
		self.displayname = None
		self.mail = None
		self.pwhash = None
		return user, 'Success'

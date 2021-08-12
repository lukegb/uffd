import datetime
import secrets
import enum

from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.ext.hybrid import hybrid_property

from uffd.ldapalchemy.dbutils import DBRelationship
from uffd.database import db
from uffd.user.models import User
from uffd.utils import token_typeable

# Device login provides a convenient and secure way to log into SSO-enabled
# services on a secondary device without entering the user password or
# completing 2FA challenges.
#
# Use-cases:
# * A user wants to log into a single OAuth2-enabled web service on his
#   mobile phone without trusting the device enough to expose his full
#   credentials.
# * A user wants to log into an OAuth2-enabled web service on a secondary
#   device at a busy event location with too little privacy to securly enter
#   his credentials but already has a login session on his laptop.
# * A user wants to log into an OAuth2-enabled service via the web browser
#   on a native mobile app on his phone and cannot use his 2FA method on that
#   device (e.g. FIDO2 token with USB-A) or in the app's web view.

# The mechanism uses two random codes: When the user attempts to authenticate
# with an SSO-enabled service and chooses the "Device Login" option on the SSO
# login page, the SSO generates and displays an initiation code. That code is
# securly bound to the browser session that is used to request it. The user
# logs into the SSO on another device using his credentials and 2FA methods and
# opens a page to authorize the device login attempt. There he enteres the
# initiation code. The SSO displays the details of the device login attempt
# (i.e. the name of the service to log into). Once the user authorizes the
# login attempt, the SSO generates a confirmation code and displays it to the
# user. The user enters the confirmation code on the device he wants to log
# in with and proceeds with the authentication.
#
# An attacker might
# * generate initiation codes,
# * observe the displayed/entered initiation code,
# * observe the displayed/entered confirmation code and
# * possibly divert the victims attention and provoke typing errors.
#
# An attacker must not be able to
# * authenticate with an SSO-enabled service as another user or
# * trick a user to authenticate with an SSO-enabled service as the attacker.
#
# An example for the second case would be the Nextcloud mobile app: The app
# integrates closely with the phone's OS and provides features like
# auto-upload of photos, contacts and more. If the app would authenticate
# with an attacker-controlled account, the attacker would have access to
# this data.

class DeviceLoginType(enum.Enum):
	OAUTH2 = 0

class DeviceLoginInitiation(db.Model):
	'''Abstract initiation code class

	An initiation code is generated and displayed when a user chooses
	"Device Login" on the login page. Instances are always bound to a
	specific service, e.g. a client id in case of OAuth2.

	The code attribute is formed out of two indepentently unique parts
	to ensure that at any time all existing codes differ in at least two
	characters (i.e. mistyping one character can not result in another
	existing and possibly attacker-controlled code).

	An initiation code is securly bound to the session that it was created
	with by storing both id and secret in the encrypted and authenticated
	session cookie.'''
	__tablename__ = 'device_login_initiation'

	id = Column(Integer(), primary_key=True, autoincrement=True)
	type = Column(Enum(DeviceLoginType), nullable=False)
	code0 = Column(String(32), unique=True, nullable=False, default=lambda: token_typeable(3))
	code1 = Column(String(32), unique=True, nullable=False, default=lambda: token_typeable(3))
	secret = Column(String(128), nullable=False, default=lambda: secrets.token_hex(64))
	confirmations = relationship('DeviceLoginConfirmation', back_populates='initiation', cascade='all, delete-orphan')
	created = Column(DateTime, default=datetime.datetime.now, nullable=False)

	__mapper_args__ = {
		'polymorphic_on': type,
	}

	@hybrid_property
	def code(self):
		# Split into two parts, each unique, to ensure that every code differs
		# in more than one character from other existing codes.
		return self.code0 + self.code1

	@hybrid_property
	def expired(self):
		return self.created < datetime.datetime.now() - datetime.timedelta(minutes=30)

	@property
	def description(self):
		raise NotImplementedError()

class DeviceLoginConfirmation(db.Model):
	'''Confirmation code class

	A confirmation code is generated and displayed when an authenticated user
	enters an initiation code and confirms the device login attempt. Every
	instance is bound to both an initiation code and a user.

	The code attribute is formed out of two indepentently unique parts
	to ensure that at any time all existing codes differ in at least two
	characters (i.e. mistyping one character can not result in another
	existing and possibly attacker-controlled code).'''
	__tablename__ = 'device_login_confirmation'

	id = Column(Integer(), primary_key=True, autoincrement=True)
	initiation_id = Column(Integer(), ForeignKey('device_login_initiation.id'), nullable=False)
	initiation = relationship('DeviceLoginInitiation', back_populates='confirmations')
	user_dn = Column(String(128), nullable=False, unique=True)
	user = DBRelationship('user_dn', User)
	code0 = Column(String(32), nullable=False, default=lambda: token_typeable(1))
	code1 = Column(String(32), nullable=False, default=lambda: token_typeable(1))

	__table_args__ = (
		db.UniqueConstraint('initiation_id', 'code0', name='uq_device_login_confirmation_initiation_id_code0'),
		db.UniqueConstraint('initiation_id', 'code1', name='uq_device_login_confirmation_initiation_id_code1'),
	)

	@hybrid_property
	def code(self):
		# Split into two parts, each unique, to ensure that every code differs
		# in more than one character from other existing codes.
		return self.code0 + self.code1

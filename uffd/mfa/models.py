import enum
import datetime
import secrets, time, struct, hmac, hashlib, base64, urllib.parse

from flask import request, current_app
from sqlalchemy import Column, Integer, Enum, Boolean, String, DateTime, Text

from fido2.ctap2 import AuthenticatorData

from uffd.database import db
from uffd.user.models import User

class MFAType(enum.Enum):
	TOTP = 1
	WEBAUTHN = 2

class MFAMethod(db.Model):
	__tablename__ = 'mfa_method'
	id = Column(Integer(), primary_key=True, autoincrement=True)
	type = Column(Enum(MFAType))
	created = Column(DateTime())
	name = Column(String(128))
	dn = Column(String(128))

	__mapper_args__ = {
		'polymorphic_on': type,
	}

	def __init__(self, user, name=None):
		self.user = user
		self.name = name
		self.created = datetime.datetime.now();

	@property
	def user(self):
		return User.from_ldap_dn(self.dn)
	
	@user.setter
	def user(self, u):
		self.dn = u.dn

def _hotp(counter, key, digits=6):
	'''Generates HMAC-based one-time password according to RFC4226
	
	:param counter: Positive integer smaller than 2**64
	:param key: Bytes object of arbitrary length (should be at least 160 bits)
	:param digits: Length of resulting value (integer between 1 and 9, minimum
	               of 6 is recommended)

	:returns: String object representing human-readable HOTP value'''
	msg = struct.pack('>Q', counter)
	digest = hmac.new(key, msg=msg, digestmod=hashlib.sha1).digest()
	offset = digest[19] & 0x0f
	snum = struct.unpack('>L', digest[offset:offset+4])[0] & 0x7fffffff
	return str(snum % (10**digits)).zfill(digits)

class TOTPMethod(MFAMethod):
	key = Column('totp_key', String(64))

	__mapper_args__ = {
		'polymorphic_identity': MFAType.TOTP
	}

	def __init__(self, user, name=None, key=None):
		super().__init__(user, name)
		if key is None:
			key = base64.b32encode(secrets.token_bytes(16)).rstrip(b'=').decode()
		self.key = key

	@property
	def raw_key(self):
		s = self.key + '='*(8 - (len(self.key) % 8))
		return base64.b32decode(s.encode())

	@property
	def key_uri(self):
		issuer = urllib.parse.quote(urllib.parse.urlsplit(request.url).netloc)
		accountname = urllib.parse.quote(self.user.loginname.encode())
		params = {'secret': self.key, 'issuer': issuer}
		if 'MFA_ICON_URL' in current_app.config:
			params['image'] = current_app.config['MFA_ICON_URL']
		return 'otpauth://totp/%s:%s?%s'%(issuer, accountname, urllib.parse.urlencode(params))

	def verify(self, code):
		'''Verify that code is valid

		Code verification must be rate-limited!

		:param code: String of digits (as entered by the user)

		:returns: True if code is valid, False otherwise'''
		counter = int(time.time()/30)
		if _hotp(counter-1, self.raw_key) == code or _hotp(counter, self.raw_key) == code:
			return True
		return False

class WebauthnMethod(MFAMethod):
	_cred = Column('webauthn_cred', Text())

	__mapper_args__ = {
		'polymorphic_identity': MFAType.WEBAUTHN
	}

	def __init__(self, user, cred_data, name=None):
		super().__init__(user, name)
		self.cred_data = cred_data

	@property
	def cred_data(self):
		return AuthenticatorData(base64.b64decode(self._cred))

	@cred_data.setter
	def cred_data(self, d):
		self._cred = base64.b64encode(bytes(d))


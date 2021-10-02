from flask import current_app
from flask_babel import get_locale, gettext as _
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship

from uffd.database import db
from uffd.session.models import DeviceLoginInitiation, DeviceLoginType

class OAuth2Client:
	def __init__(self, client_id, client_secret, redirect_uris, required_group=None, logout_urls=None, **kwargs):
		self.client_id = client_id
		self.client_secret = client_secret
		# We only support the Authorization Code Flow for confidential (server-side) clients
		self.client_type = 'confidential'
		self.redirect_uris = redirect_uris
		self.default_scopes = ['profile']
		self.required_group = required_group
		self.logout_urls = []
		for url in (logout_urls or []):
			if isinstance(url, str):
				self.logout_urls.append(['GET', url])
			else:
				self.logout_urls.append(url)
		self.kwargs = kwargs

	@property
	def login_message(self):
		return self.kwargs.get('login_message_' + get_locale().language,
		                       self.kwargs.pop('login_message', _('You need to login to access this service')))

	@classmethod
	def from_id(cls, client_id):
		return OAuth2Client(client_id, **current_app.config['OAUTH2_CLIENTS'][client_id])

	@property
	def default_redirect_uri(self):
		return self.redirect_uris[0]

	def access_allowed(self, user):
		return user.has_permission(self.required_group)

class OAuth2Grant(db.Model):
	__tablename__ = 'oauth2grant'
	id = Column(Integer, primary_key=True, autoincrement=True)

	user_id = Column(Integer(), ForeignKey('user.id', onupdate='CASCADE', ondelete='CASCADE'), nullable=False)
	user = relationship('User')

	client_id = Column(String(40), nullable=False)

	@property
	def client(self):
		return OAuth2Client.from_id(self.client_id)

	@client.setter
	def client(self, newclient):
		self.client_id = newclient.client_id

	code = Column(String(255), index=True, nullable=False)
	redirect_uri = Column(String(255), nullable=False)
	expires = Column(DateTime, nullable=False)

	_scopes = Column(Text, nullable=False, default='')
	@property
	def scopes(self):
		if self._scopes:
			return self._scopes.split()
		return []

	def delete(self):
		db.session.delete(self)
		db.session.commit()
		return self

class OAuth2Token(db.Model):
	__tablename__ = 'oauth2token'
	id = Column(Integer, primary_key=True, autoincrement=True)

	user_id = Column(Integer(), ForeignKey('user.id', onupdate='CASCADE', ondelete='CASCADE'), nullable=False)
	user = relationship('User')

	client_id = Column(String(40), nullable=False)

	@property
	def client(self):
		return OAuth2Client.from_id(self.client_id)

	@client.setter
	def client(self, newclient):
		self.client_id = newclient.client_id

	# currently only bearer is supported
	token_type = Column(String(40), nullable=False)
	access_token = Column(String(255), unique=True, nullable=False)
	refresh_token = Column(String(255), unique=True, nullable=False)
	expires = Column(DateTime, nullable=False)

	_scopes = Column(Text, nullable=False, default='')
	@property
	def scopes(self):
		if self._scopes:
			return self._scopes.split()
		return []

	def delete(self):
		db.session.delete(self)
		db.session.commit()
		return self

class OAuth2DeviceLoginInitiation(DeviceLoginInitiation):
	__mapper_args__ = {
		'polymorphic_identity': DeviceLoginType.OAUTH2
	}
	oauth2_client_id = Column(String(40))

	@property
	def oauth2_client(self):
		return OAuth2Client.from_id(self.oauth2_client_id)

	@property
	def description(self):
		return self.oauth2_client.client_id

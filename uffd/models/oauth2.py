import datetime
import json

from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.ext.associationproxy import association_proxy

from uffd.database import db, CommaSeparatedList
from uffd.tasks import cleanup_task
from uffd.password_hash import PasswordHashAttribute, HighEntropyPasswordHash
from .session import DeviceLoginInitiation, DeviceLoginType
from .service import ServiceUser

class OAuth2Client(db.Model):
	__tablename__ = 'oauth2client'
	# Inconsistently named "db_id" instead of "id" because of the naming conflict
	# with "client_id" in the OAuth2 standard
	db_id = Column(Integer, primary_key=True, autoincrement=True)

	service_id = Column(Integer, ForeignKey('service.id', onupdate='CASCADE', ondelete='CASCADE'), nullable=False)
	service = relationship('Service', back_populates='oauth2_clients')

	client_id = Column(String(40), unique=True, nullable=False)
	_client_secret = Column('client_secret', Text(), nullable=False)
	client_secret = PasswordHashAttribute('_client_secret', HighEntropyPasswordHash)
	_redirect_uris = relationship('OAuth2RedirectURI', cascade='all, delete-orphan')
	redirect_uris = association_proxy('_redirect_uris', 'uri')
	logout_uris = relationship('OAuth2LogoutURI', cascade='all, delete-orphan')

	@property
	def client_type(self):
		return 'confidential'

	@property
	def default_scopes(self):
		return ['profile']

	@property
	def default_redirect_uri(self):
		return self.redirect_uris[0]

	def access_allowed(self, user):
		service_user = ServiceUser.query.get((self.service_id, user.id))
		return service_user and service_user.has_access

	@property
	def logout_uris_json(self):
		return json.dumps([[item.method, item.uri] for item in self.logout_uris])

class OAuth2RedirectURI(db.Model):
	__tablename__ = 'oauth2redirect_uri'
	id = Column(Integer, primary_key=True, autoincrement=True)
	client_db_id = Column(Integer, ForeignKey('oauth2client.db_id', onupdate='CASCADE', ondelete='CASCADE'), nullable=False)
	uri = Column(String(255), nullable=False)

	def __init__(self, uri):
		self.uri = uri

class OAuth2LogoutURI(db.Model):
	__tablename__ = 'oauth2logout_uri'
	id = Column(Integer, primary_key=True, autoincrement=True)
	client_db_id = Column(Integer, ForeignKey('oauth2client.db_id', onupdate='CASCADE', ondelete='CASCADE'), nullable=False)
	method = Column(String(40), nullable=False, default='GET')
	uri = Column(String(255), nullable=False)

@cleanup_task.delete_by_attribute('expired')
class OAuth2Grant(db.Model):
	__tablename__ = 'oauth2grant'
	id = Column(Integer, primary_key=True, autoincrement=True)

	user_id = Column(Integer(), ForeignKey('user.id', onupdate='CASCADE', ondelete='CASCADE'), nullable=False)
	user = relationship('User')

	client_db_id = Column(Integer, ForeignKey('oauth2client.db_id', onupdate='CASCADE', ondelete='CASCADE'), nullable=False)
	client = relationship('OAuth2Client')

	code = Column(String(255), index=True, nullable=False)
	redirect_uri = Column(String(255), nullable=False)
	expires = Column(DateTime, nullable=False, default=lambda: datetime.datetime.utcnow() + datetime.timedelta(seconds=100))
	scopes = Column('_scopes', CommaSeparatedList(), nullable=False, default=tuple())

	@hybrid_property
	def expired(self):
		if self.expires is None:
			return False
		return self.expires < datetime.datetime.utcnow()

@cleanup_task.delete_by_attribute('expired')
class OAuth2Token(db.Model):
	__tablename__ = 'oauth2token'
	id = Column(Integer, primary_key=True, autoincrement=True)

	user_id = Column(Integer(), ForeignKey('user.id', onupdate='CASCADE', ondelete='CASCADE'), nullable=False)
	user = relationship('User')

	client_db_id = Column(Integer, ForeignKey('oauth2client.db_id', onupdate='CASCADE', ondelete='CASCADE'), nullable=False)
	client = relationship('OAuth2Client')

	# currently only bearer is supported
	token_type = Column(String(40), nullable=False)
	access_token = Column(String(255), unique=True, nullable=False)
	refresh_token = Column(String(255), unique=True, nullable=False)
	expires = Column(DateTime, nullable=False)
	scopes = Column('_scopes', CommaSeparatedList(), nullable=False, default=tuple())

	@hybrid_property
	def expired(self):
		return self.expires < datetime.datetime.utcnow()

	def set_expires_in_seconds(self, seconds):
		self.expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=seconds)
	expires_in_seconds = property(fset=set_expires_in_seconds)

class OAuth2DeviceLoginInitiation(DeviceLoginInitiation):
	__mapper_args__ = {
		'polymorphic_identity': DeviceLoginType.OAUTH2
	}
	client_db_id = Column('oauth2_client_db_id', Integer, ForeignKey('oauth2client.db_id', onupdate='CASCADE', ondelete='CASCADE'))
	client = relationship('OAuth2Client')

	@property
	def description(self):
		return self.client.service.name

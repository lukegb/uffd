from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.associationproxy import association_proxy

from uffd.database import db

class Mail(db.Model):
	__tablename__ = 'mail'
	id = Column(Integer(), primary_key=True, autoincrement=True)
	uid = Column(String(32), unique=True, nullable=False)
	_receivers = relationship('MailReceiveAddress', cascade='all, delete-orphan')
	receivers = association_proxy('_receivers', 'address')
	_destinations = relationship('MailDestinationAddress', cascade='all, delete-orphan')
	destinations = association_proxy('_destinations', 'address')

class MailReceiveAddress(db.Model):
	__tablename__ = 'mail_receive_address'
	id = Column(Integer(), primary_key=True, autoincrement=True)
	mail_id = Column(Integer(), ForeignKey('mail.id', onupdate='CASCADE', ondelete='CASCADE'), nullable=False)
	address = Column(String(128), nullable=False)

	def __init__(self, address):
		self.address = address

class MailDestinationAddress(db.Model):
	__tablename__ = 'mail_destination_address'
	id = Column(Integer(), primary_key=True, autoincrement=True)
	mail_id = Column(Integer(), ForeignKey('mail.id', onupdate='CASCADE', ondelete='CASCADE'), nullable=False)
	address = Column(String(128), nullable=False)

	def __init__(self, address):
		self.address = address

import datetime

from sqlalchemy import Column, String, DateTime, Integer, ForeignKey
from sqlalchemy.orm import relationship

from uffd.database import db
from uffd.utils import token_urlfriendly

class PasswordToken(db.Model):
	__tablename__ = 'passwordToken'
	id = Column(Integer(), primary_key=True, autoincrement=True)
	token = Column(String(128), default=token_urlfriendly, nullable=False)
	created = Column(DateTime, default=datetime.datetime.now, nullable=False)
	user_id = Column(Integer(), ForeignKey('user.id', onupdate='CASCADE', ondelete='CASCADE'), nullable=False)
	user = relationship('User')

class MailToken(db.Model):
	__tablename__ = 'mailToken'
	id = Column(Integer(), primary_key=True, autoincrement=True)
	token = Column(String(128), default=token_urlfriendly, nullable=False)
	created = Column(DateTime, default=datetime.datetime.now)
	user_id = Column(Integer(), ForeignKey('user.id', onupdate='CASCADE', ondelete='CASCADE'), nullable=False)
	user = relationship('User')
	newmail = Column(String(255))

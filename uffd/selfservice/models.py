import datetime

from sqlalchemy import Column, String, DateTime, Integer

from uffd.database import db
from uffd.utils import token_urlfriendly

class PasswordToken(db.Model):
	__tablename__ = 'passwordToken'
	id = Column(Integer(), primary_key=True, autoincrement=True)
	token = Column(String(128), default=token_urlfriendly, nullable=False)
	created = Column(DateTime, default=datetime.datetime.now)
	loginname = Column(String(32))

class MailToken(db.Model):
	__tablename__ = 'mailToken'
	id = Column(Integer(), primary_key=True, autoincrement=True)
	token = Column(String(128), default=token_urlfriendly, nullable=False)
	created = Column(DateTime, default=datetime.datetime.now)
	loginname = Column(String(32))
	newmail = Column(String(255))

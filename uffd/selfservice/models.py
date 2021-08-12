import datetime

from sqlalchemy import Column, String, DateTime

from uffd.database import db
from uffd.utils import token_urlfriendly

class Token():
	token = Column(String(128), primary_key=True, default=token_urlfriendly)
	created = Column(DateTime, default=datetime.datetime.now)

class PasswordToken(Token, db.Model):
	__tablename__ = 'passwordToken'
	loginname = Column(String(32))

class MailToken(Token, db.Model):
	__tablename__ = 'mailToken'
	loginname = Column(String(32))
	newmail = Column(String(255))

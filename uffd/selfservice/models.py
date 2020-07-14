import datetime
import secrets

from sqlalchemy import Column, Integer, String, Text, LargeBinary, DateTime, Boolean, ForeignKey

from uffd.database import db

def random_token():
	return secrets.token_hex(128)

class Token():
	token = Column(String(128), primary_key=True, default=random_token)
	created = Column(DateTime, default=datetime.datetime.now)

class PasswordToken(Token, db.Model):
	__tablename__ = 'passwortToken'
	loginname = Column(String(32))

class MailToken(Token, db.Model):
	__tablename__ = 'mailToken'
	loginname = Column(String(32))
	newmail = Column(String(255))

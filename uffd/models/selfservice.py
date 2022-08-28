import datetime

from sqlalchemy import Column, String, DateTime, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.hybrid import hybrid_property

from uffd.database import db
from uffd.utils import token_urlfriendly
from uffd.tasks import cleanup_task

@cleanup_task.delete_by_attribute('expired')
class PasswordToken(db.Model):
	__tablename__ = 'passwordToken'
	id = Column(Integer(), primary_key=True, autoincrement=True)
	token = Column(String(128), default=token_urlfriendly, nullable=False)
	created = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
	user_id = Column(Integer(), ForeignKey('user.id', onupdate='CASCADE', ondelete='CASCADE'), nullable=False)
	user = relationship('User')

	@hybrid_property
	def expired(self):
		if self.created is None:
			return False
		return self.created < datetime.datetime.utcnow() - datetime.timedelta(days=2)

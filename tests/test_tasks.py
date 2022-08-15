import unittest

from flask import Flask
from flask_sqlalchemy import SQLAlchemy

from uffd.tasks import CleanupTask

class TestCleanupTask(unittest.TestCase):
	def test(self):
		app = Flask(__name__)
		app.testing = True
		app.debug = True
		app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
		db = SQLAlchemy(app)
		cleanup_task = CleanupTask()

		@cleanup_task.delete_by_attribute('delete_me')
		class TestModel(db.Model):
			id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
			delete_me = db.Column(db.Boolean(), default=False, nullable=False)

		with app.test_request_context():
			db.create_all()
			db.session.add(TestModel(delete_me=True))
			db.session.add(TestModel(delete_me=True))
			db.session.add(TestModel(delete_me=True))
			db.session.add(TestModel(delete_me=False))
			db.session.add(TestModel(delete_me=False))
			db.session.commit()
			db.session.expire_all()
			self.assertEqual(TestModel.query.count(), 5)

		with app.test_request_context():
			cleanup_task.run()
			db.session.commit()
			db.session.expire_all()

		with app.test_request_context():
			self.assertEqual(TestModel.query.count(), 2)

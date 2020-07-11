from collections import OrderedDict

from flask_sqlalchemy import SQLAlchemy
from flask.json import JSONEncoder

# pylint: disable=C0103
db = SQLAlchemy()
# pylint: enable=C0103

class SQLAlchemyJSON(JSONEncoder):
	def default(self, o):
		if isinstance(o, db.Model):
			result = OrderedDict()
			for key in o.__mapper__.c.keys():
				result[key] = getattr(o, key)
			return result
		return JSONEncoder.default(self, o)

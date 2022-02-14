from collections import OrderedDict

from sqlalchemy import MetaData, event
from flask_sqlalchemy import SQLAlchemy
from flask.json import JSONEncoder

convention = {
	'ix': 'ix_%(column_0_label)s',
	'uq': 'uq_%(table_name)s_%(column_0_name)s',
	'ck': 'ck_%(table_name)s_%(column_0_name)s',
	'fk': 'fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s',
	'pk': 'pk_%(table_name)s'
}
metadata = MetaData(naming_convention=convention)

db = SQLAlchemy(metadata=metadata)

def enable_sqlite_foreign_key_support(dbapi_connection, connection_record):
	# pylint: disable=unused-argument
	cursor = dbapi_connection.cursor()
	cursor.execute('PRAGMA foreign_keys=ON')
	cursor.close()

# We want to enable SQLite foreign key support for app and test code, but not
# for migrations.
# The common way to add the handler to the Engine class (so it applies to all
# instances) would also affect the migrations. With flask_sqlalchemy v2.4 and
# newer we could overwrite SQLAlchemy.create_engine and add our handler there.
# However Debian Buster and Bullseye ship v2.1, so we do this here and call
# this function in create_app.
def customize_db_engine(engine):
	if engine.name == 'sqlite':
		event.listen(engine, 'connect', enable_sqlite_foreign_key_support)

class SQLAlchemyJSON(JSONEncoder):
	def default(self, o):
		if isinstance(o, db.Model):
			result = OrderedDict()
			for key in o.__mapper__.c.keys():
				result[key] = getattr(o, key)
			return result
		return JSONEncoder.default(self, o)

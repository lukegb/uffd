from uffd.database import db

# pylint completely fails to understand SQLAlchemy's query functions
# pylint: disable=no-member

feature_flag_table = db.Table('feature_flag',
	db.Column('name', db.String(32), primary_key=True),
)

class FeatureFlag:
	def __init__(self, name):
		self.name = name
		self.enable_hooks = []
		self.disable_hooks = []

	@property
	def expr(self):
		return db.exists().where(feature_flag_table.c.name == self.name)

	def __bool__(self):
		return db.session.execute(db.select([self.expr])).scalar()

	def enable_hook(self, func):
		self.enable_hooks.append(func)
		return func

	def enable(self):
		db.session.execute(db.insert(feature_flag_table).values(name=self.name))
		for func in self.enable_hooks:
			func()

	def disable_hook(self, func):
		self.disable_hooks.append(func)
		return func

	def disable(self):
		db.session.execute(db.delete(feature_flag_table).where(feature_flag_table.c.name == self.name))
		for func in self.disable_hooks:
			func()

FeatureFlag.unique_email_addresses = FeatureFlag('unique-email-addresses')

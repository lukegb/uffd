class CleanupTask:
	def __init__(self, *init_args):
		self.handlers = []
		if init_args:
			self.init_app(*init_args)

	def init_app(self, app, db):
		@app.cli.command('cleanup', help='Cleanup expired data')
		def cleanup(): #pylint: disable=unused-variable
			self.run()
			db.session.commit()

	def handler(self, func):
		self.handlers.append(func)
		return func

	def delete_by_attribute(self, attribute):
		def decorator(cls):
			@self.handler
			def handler():
				cls.query.filter(getattr(cls, attribute)).delete()
			return cls
		return decorator

	def run(self):
		for handler in self.handlers:
			handler()

cleanup_task = CleanupTask()

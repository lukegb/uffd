class CleanupTask:
	def __init__(self):
		self.handlers = []

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

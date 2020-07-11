import random
from datetime import timedelta, datetime

# debian ships jinja2 without this test...
def equalto(a, b):
	return a == b

def register_template_helper(app):
	app.jinja_env.trim_blocks = True
	app.jinja_env.lstrip_blocks = True
	app.add_template_global(random.randint, name='randint')
	app.add_template_global(datetime, name='datetime')
	app.add_template_global(timedelta, name='timedelta')
	app.add_template_global(min, name='min')
	app.add_template_global(max, name='max')
	app.add_template_global(equalto, name='equalto')

import random
import subprocess
from datetime import timedelta, datetime

def register_template_helper(app):
	# debian ships jinja2 without this test...
	def equalto(a, b):
		return a == b

	@app.url_defaults
	def static_version_inject(endpoint, values):
		if endpoint == 'static':
			values['v'] = app.jinja_env.globals['gitversion']['longhash'] #pylint: disable=no-member

	app.jinja_env.trim_blocks = True
	app.jinja_env.lstrip_blocks = True

	app.add_template_global(random.randint, name='randint')
	app.add_template_global(datetime, name='datetime')
	app.add_template_global(timedelta, name='timedelta')
	app.add_template_global(min, name='min')
	app.add_template_global(max, name='max')
	app.add_template_global(equalto, name='equalto')

	# get git commit
	GITOUTPUT = subprocess.check_output(['git', "log", "-g", "-1", "--pretty=%H#%h#%d#%s"]).decode('UTF-8').split('#', 3)
	app.jinja_env.globals['gitversion'] = {'hash': GITOUTPUT[1], 'longhash': GITOUTPUT[0], 'branch': GITOUTPUT[2], 'msg': GITOUTPUT[3]} #pylint: disable=no-member

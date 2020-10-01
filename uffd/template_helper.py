from flask import Markup

import qrcode, qrcode.image.svg

import random
import subprocess
from datetime import timedelta, datetime
import io

def register_template_helper(app):
	# debian ships jinja2 without this test...
	def equalto(a, b):
		return a == b

	@app.template_filter()
	def qrcode_svg(content, **attrs):
		img = qrcode.make(content, image_factory=qrcode.image.svg.SvgPathImage)
		svg = img.get_image()
		for key, value, in attrs.items():
			svg.set(key, value)
		buf = io.BytesIO()
		img.save(buf)
		return Markup(buf.getvalue().decode())

	@app.url_defaults
	def static_version_inject(endpoint, values): #pylint: disable=unused-variable
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
	git_output = subprocess.check_output(['git', "log", "-g", "-1", "--pretty=%H#%h#%d#%s"]).decode('UTF-8').split('#', 3)
	app.jinja_env.globals['gitversion'] = {'hash': git_output[1], 'longhash': git_output[0], 'branch': git_output[2], 'msg': git_output[3]} #pylint: disable=no-member

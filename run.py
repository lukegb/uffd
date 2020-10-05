#!/usr/bin/env python3
from werkzeug.serving import make_ssl_devcert

from uffd import *

if __name__ == '__main__':
	app = create_app()
	init_db(app)
	print(app.url_map)
	if not os.path.exists('devcert.crt') or not os.path.exists('devcert.key'):
		make_ssl_devcert('devcert')
	# WebAuthn requires https and a hostname (not just an IP address). If you
	# don't want to test U2F/FIDO2 device registration/authorization, you can
	# safely remove `host` and `ssl_context`.
	app.run(threaded=True, debug=True, host='localhost', ssl_context=('devcert.crt', 'devcert.key'))

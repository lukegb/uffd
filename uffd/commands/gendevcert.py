import os

import click
from werkzeug.serving import make_ssl_devcert

@click.command("gendevcert", help='Generates a self-signed TLS certificate for development')
def gendevcert_command(): #pylint: disable=unused-variable
	if os.path.exists('devcert.crt') or os.path.exists('devcert.key'):
		print('Refusing to overwrite existing "devcert.crt"/"devcert.key" file!')
		return
	make_ssl_devcert('devcert')
	print('Certificate written to "devcert.crt", private key to "devcert.key".')
	print('Run `flask run --cert devcert.crt --key devcert.key` to use it.')

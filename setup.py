from setuptools import setup, find_packages
import os

with open('README.md', 'r', encoding='utf-8') as f:
	long_description = f.read()
	long_description = '**DO NOT INSTALL FROM PIP FOR PRODUCTION DEPLOYMENTS**, see [Deployment](#Deployment) for more information.\n\n\n\n' + long_description

setup(
	name='uffd',
	version=os.environ.get('PACKAGE_VERSION', 'local'),
	description='Ldap based single sign on and user management web software',
	long_description=long_description,
	long_description_content_type='text/markdown',
	url='https://git.cccv.de/uffd/uffd',
	classifiers=[
		'Programming Language :: Python :: 3',
		'Development Status :: 5 - Production/Stable',
		'License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)',
		'Operating System :: OS Independent',
		'Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP',
		'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
		'Environment :: Web Environment',
		'Framework :: Flask',
	],
	author='CCCV',
	author_email='it@cccv.de',
	license='AGPL3',
	packages=find_packages(),
	include_package_data=True,
	zip_safe=False,
	python_requires='>=3.7',
	install_requires=[
		# Versions Debian Buster packages are based on.
		# DO NOT USE FOR PRODUCTION, those in the setup.py are not updated regularly
		'ldap3==2.4.1',
		'flask==1.0.2',
		'Flask-SQLAlchemy==2.1',
		'qrcode==6.1',
		'fido2==0.5.0',
		'Flask-OAuthlib==0.9.5',
		'Flask-Migrate==2.1.1',
		'Flask-Babel==0.11.2',
		'alembic==1.0.0',

		# The main dependencies on their own lead to version collisions and pip is
		# not very good at resolving them, so we pin the versions from Debian Buster
		# for all dependencies.
		'certifi==2018.8.24',
		#cffi==1.12.2'
		'cffi # v1.12.2 no longer works with python3.9. Newer versions seem to work fine.',
		'chardet==3.0.4',
		'click==7.0',
		'cryptography==2.6.1',
		'idna==2.6',
		'itsdangerous==0.24',
		'Jinja2==2.10',
		'MarkupSafe==1.1.0',
		'oauthlib==2.1.0',
		'pyasn1==0.4.2',
		'pycparser==2.19',
		'requests==2.21.0',
		'requests-oauthlib==1.0.0',
		'six==1.12.0',
		'SQLAlchemy==1.2.18',
		'urllib3==1.24.1',
		'Werkzeug==0.14.1',
		'python-dateutil==2.7.3',
		#editor==1.0.3
		'Mako==1.0.7',
	],
)

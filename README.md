# uffd

This is the UserFerwaltungsFrontend.
A web service to manage LDAP users, groups and permissions.

## dependencies
- python3
- python3-ldap3
- python3-flask
- python3-flask-sqlalchemy
- python3-qrcode
- git (cli utility, musst be in path)

## development

During development, you may want to enable LDAP mocking, as you otherwise need to have access to an actual LDAP server with the required schema.
You can do so by setting `LDAP_SERVICE_MOCK=True` in the config.
Afterwards you can login as a normal user with "testuser" and "userpassword", or as an admin with "testadmin" and "adminpassword".
Please note that the mocked LDAP functionality is very limited and many uffd features do not work correctly without a real LDAP server.

## deployment

Use uwsgi.

## python style conventions

tabs.

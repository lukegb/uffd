# uffd

This is the UserFerwaltungsFrontend.
A web service to manage LDAP users, groups and permissions.

## dependencies
- python3
- python3-ldap3
- python3-flask
- python3-flask-sqlalchemy
- python3-qrcode
- python3-fido2 (version 0.5.0, optional)
- python3-flask-oauthlib
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

## OAuth2 Single-Sign-On Provider

Other services can use uffd as an OAuth2.0-based authentication provider.
The required credentials (client_id, client_secret and redirect_uris) for these services are defined in the config.
The services need to be setup to use the following URLs with the Authorization Code Flow:

* `/oauth2/authorize`: authorization endpoint
* `/oauth2/token`: token request endpoint
* `/oauth2/userinfo`: endpoint that provides information about the current user

The userinfo endpoint returns json data with the following structure:

```
{
  "id": 10000,
  "name": "Test User",
  "nickname": "testuser"
  "email": "testuser@example.com",
  "groups": [
    "uffd_access",
    "users"
  ],
}
```

`id` is the uidNumber, `name` the display name (cn) and `nickname` the uid of the user's LDAP object.

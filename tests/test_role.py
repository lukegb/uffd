import datetime
import time

from flask import url_for, session

# These imports are required, because otherwise we get circular imports?!
from uffd import ldap, user

from uffd.user.models import Group
from uffd.role.models import Role
from uffd import create_app, db

from utils import dump, UffdTestCase

class TestRoleViews(UffdTestCase):
	def setUp(self):
		super().setUp()
		self.client.post(path=url_for('session.login'),
			data={'loginname': 'testadmin', 'password': 'adminpassword'}, follow_redirects=True)

	def test_index(self):
		db.session.add(Role('base', 'Base role description'))
		db.session.add(Role('test1', 'Test1 role description'))
		db.session.commit()
		r = self.client.get(path=url_for('role.index'), follow_redirects=True)
		dump('role_index', r)
		self.assertEqual(r.status_code, 200)

	def test_index_empty(self):
		r = self.client.get(path=url_for('role.index'), follow_redirects=True)
		dump('role_index_empty', r)
		self.assertEqual(r.status_code, 200)

	def test_show(self):
		role = Role('base', 'Base role description')
		db.session.add(role)
		db.session.commit()
		r = self.client.get(path=url_for('role.show', roleid=role.id), follow_redirects=True)
		dump('role_show', r)
		self.assertEqual(r.status_code, 200)

	def test_new(self):
		r = self.client.get(path=url_for('role.show'), follow_redirects=True)
		dump('role_new', r)
		self.assertEqual(r.status_code, 200)

	def test_update(self):
		role = Role('base', 'Base role description')
		db.session.add(role)
		db.session.commit()
		role.add_group(Group.from_ldap_dn('cn=uffd_admin,ou=groups,dc=example,dc=com'))
		db.session.commit()
		self.assertEqual(role.name, 'base')
		self.assertEqual(role.description, 'Base role description')
		self.assertEqual(role.group_dns(), ['cn=uffd_admin,ou=groups,dc=example,dc=com'])
		r = self.client.post(path=url_for('role.update', roleid=role.id),
			data={'name': 'base1', 'description': 'Base role description1', 'group-20001': '1', 'group-20002': '1'},
			follow_redirects=True)
		dump('role_update', r)
		self.assertEqual(r.status_code, 200)
		role = Role.query.get(role.id)
		self.assertEqual(role.name, 'base1')
		self.assertEqual(role.description, 'Base role description1')
		self.assertEqual(sorted(role.group_dns()), ['cn=uffd_access,ou=groups,dc=example,dc=com',
			'cn=users,ou=groups,dc=example,dc=com'])
		# TODO: verify that group memberships are updated (currently not possible with ldap mock!)

	def test_create(self):
		self.assertIsNone(Role.query.filter_by(name='base').first())
		r = self.client.post(path=url_for('role.update'),
			data={'name': 'base', 'description': 'Base role description', 'group-20001': '1', 'group-20002': '1'},
			follow_redirects=True)
		dump('role_create', r)
		self.assertEqual(r.status_code, 200)
		role = Role.query.filter_by(name='base').first()
		self.assertIsNotNone(role)
		self.assertEqual(role.name, 'base')
		self.assertEqual(role.description, 'Base role description')
		self.assertEqual(sorted(role.group_dns()), ['cn=uffd_access,ou=groups,dc=example,dc=com',
			'cn=users,ou=groups,dc=example,dc=com'])
		# TODO: verify that group memberships are updated (currently not possible with ldap mock!)

	def test_delete(self):
		role = Role('base', 'Base role description')
		db.session.add(role)
		db.session.commit()
		role_id = role.id
		self.assertIsNotNone(Role.query.get(role_id))
		r = self.client.get(path=url_for('role.delete', roleid=role.id), follow_redirects=True)
		dump('role_delete', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(Role.query.get(role_id))
		# TODO: verify that group memberships are updated (currently not possible with ldap mock!)

class TestRoleViewsOL(TestRoleViews):
	use_openldap = True

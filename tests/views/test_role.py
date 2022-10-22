from flask import url_for

from uffd.database import db
from uffd.models import User, Role, RoleGroup

from tests.utils import dump, UffdTestCase

class TestRoleViews(UffdTestCase):
	def setUp(self):
		super().setUp()
		self.login_as('admin')

	def test_index(self):
		db.session.add(Role(name='base', description='Base role description'))
		db.session.add(Role(name='test1', description='Test1 role description'))
		db.session.commit()
		r = self.client.get(path=url_for('role.index'), follow_redirects=True)
		dump('role_index', r)
		self.assertEqual(r.status_code, 200)

	def test_index_empty(self):
		r = self.client.get(path=url_for('role.index'), follow_redirects=True)
		dump('role_index_empty', r)
		self.assertEqual(r.status_code, 200)

	def test_show(self):
		role = Role(name='base', description='Base role description')
		db.session.add(role)
		db.session.commit()
		r = self.client.get(path=url_for('role.show', roleid=role.id), follow_redirects=True)
		dump('role_show', r)
		self.assertEqual(r.status_code, 200)

	def test_new(self):
		r = self.client.get(path=url_for('role.new'), follow_redirects=True)
		dump('role_new', r)
		self.assertEqual(r.status_code, 200)

	def test_update(self):
		role = Role(name='base', description='Base role description')
		db.session.add(role)
		db.session.commit()
		role.groups[self.get_admin_group()] = RoleGroup()
		db.session.commit()
		self.assertEqual(role.name, 'base')
		self.assertEqual(role.description, 'Base role description')
		self.assertSetEqual(set(role.groups), {self.get_admin_group()})
		r = self.client.post(path=url_for('role.update', roleid=role.id),
			data={'name': 'base1', 'description': 'Base role description1', 'moderator-group': '', 'group-%d'%self.get_users_group().id: '1', 'group-%d'%self.get_access_group().id: '1'},
			follow_redirects=True)
		dump('role_update', r)
		self.assertEqual(r.status_code, 200)
		role = Role.query.get(role.id)
		self.assertEqual(role.name, 'base1')
		self.assertEqual(role.description, 'Base role description1')
		self.assertSetEqual(set(role.groups), {self.get_access_group(), self.get_users_group()})
		# TODO: verify that group memberships are updated

	def test_create(self):
		self.assertIsNone(Role.query.filter_by(name='base').first())
		r = self.client.post(path=url_for('role.update'),
			data={'name': 'base', 'description': 'Base role description', 'moderator-group': '', 'group-%d'%self.get_users_group().id: '1', 'group-%d'%self.get_access_group().id: '1'},
			follow_redirects=True)
		dump('role_create', r)
		self.assertEqual(r.status_code, 200)
		role = Role.query.filter_by(name='base').first()
		self.assertIsNotNone(role)
		self.assertEqual(role.name, 'base')
		self.assertEqual(role.description, 'Base role description')
		self.assertSetEqual(set(role.groups), {self.get_access_group(), self.get_users_group()})
		# TODO: verify that group memberships are updated (currently not possible with ldap mock!)

	def test_create_with_moderator_group(self):
		self.assertIsNone(Role.query.filter_by(name='base').first())
		r = self.client.post(path=url_for('role.update'),
			data={'name': 'base', 'description': 'Base role description', 'moderator-group': self.get_admin_group().id, 'group-%d'%self.get_users_group().id: '1', 'group-%d'%self.get_access_group().id: '1'},
			follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		role = Role.query.filter_by(name='base').first()
		self.assertIsNotNone(role)
		self.assertEqual(role.name, 'base')
		self.assertEqual(role.description, 'Base role description')
		self.assertEqual(role.moderator_group.name, 'uffd_admin')
		self.assertSetEqual(set(role.groups), {self.get_access_group(), self.get_users_group()})
		# TODO: verify that group memberships are updated (currently not possible with ldap mock!)

	def test_delete(self):
		role = Role(name='base', description='Base role description')
		db.session.add(role)
		db.session.commit()
		role_id = role.id
		self.assertIsNotNone(Role.query.get(role_id))
		r = self.client.get(path=url_for('role.delete', roleid=role.id), follow_redirects=True)
		dump('role_delete', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(Role.query.get(role_id))
		# TODO: verify that group memberships are updated (currently not possible with ldap mock!)

	def test_set_default(self):
		db.session.add(User(loginname='service', is_service_user=True, primary_email_address='service@example.com', displayname='Service'))
		db.session.commit()
		role = Role(name='test')
		db.session.add(role)
		role.groups[self.get_admin_group()] = RoleGroup()
		user1 = self.get_user()
		user2 = self.get_admin()
		service_user = User.query.filter_by(loginname='service').one_or_none()
		self.assertSetEqual(set(self.get_user().roles_effective), set())
		self.assertSetEqual(set(self.get_admin().roles_effective), set())
		self.assertSetEqual(set(service_user.roles_effective), set())
		role.members.append(self.get_user())
		role.members.append(service_user)
		self.assertSetEqual(set(self.get_user().roles_effective), {role})
		self.assertSetEqual(set(self.get_admin().roles_effective), set())
		self.assertSetEqual(set(service_user.roles_effective), {role})
		db.session.commit()
		role_id = role.id
		self.assertSetEqual(set(role.members), {self.get_user(), service_user})
		r = self.client.get(path=url_for('role.set_default', roleid=role.id), follow_redirects=True)
		dump('role_set_default', r)
		self.assertEqual(r.status_code, 200)
		role = Role.query.get(role_id)
		service_user = User.query.filter_by(loginname='service').one_or_none()
		self.assertSetEqual(set(role.members), {service_user})
		self.assertSetEqual(set(self.get_user().roles_effective), {role})
		self.assertSetEqual(set(self.get_admin().roles_effective), {role})

	def test_unset_default(self):
		admin_role = Role(name='admin', is_default=True)
		db.session.add(admin_role)
		admin_role.groups[self.get_admin_group()] = RoleGroup()
		db.session.add(User(loginname='service', is_service_user=True, primary_email_address='service@example.com', displayname='Service'))
		db.session.commit()
		role = Role(name='test', is_default=True)
		db.session.add(role)
		service_user = User.query.filter_by(loginname='service').one_or_none()
		role.members.append(service_user)
		self.assertSetEqual(set(self.get_user().roles_effective), {role, admin_role})
		self.assertSetEqual(set(self.get_admin().roles_effective), {role, admin_role})
		self.assertSetEqual(set(service_user.roles_effective), {role})
		db.session.commit()
		role_id = role.id
		admin_role_id = admin_role.id
		self.assertSetEqual(set(role.members), {service_user})
		r = self.client.get(path=url_for('role.unset_default', roleid=role.id), follow_redirects=True)
		dump('role_unset_default', r)
		self.assertEqual(r.status_code, 200)
		role = Role.query.get(role_id)
		admin_role = Role.query.get(admin_role_id)
		service_user = User.query.filter_by(loginname='service').one_or_none()
		self.assertSetEqual(set(role.members), {service_user})
		self.assertSetEqual(set(self.get_user().roles_effective), {admin_role})
		self.assertSetEqual(set(self.get_admin().roles_effective), {admin_role})

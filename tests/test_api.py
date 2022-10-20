import base64

from flask import url_for

from uffd.password_hash import PlaintextPasswordHash
from uffd.remailer import remailer
from uffd.database import db
from uffd.models import APIClient, Service, User, RemailerMode
from uffd.views.api import apikey_required
from utils import UffdTestCase, db_flush

def basic_auth(username, password):
	return ('Authorization', 'Basic ' + base64.b64encode(f'{username}:{password}'.encode()).decode())

class TestAPIAuth(UffdTestCase):
	def setUpApp(self):
		@self.app.route('/test/endpoint1')
		@apikey_required()
		def testendpoint1():
			return 'OK', 200

		@self.app.route('/test/endpoint2')
		@apikey_required('users')
		def testendpoint2():
			return 'OK', 200

	def setUpDB(self):
		db.session.add(APIClient(service=Service(name='test1'), auth_username='test1', auth_password='testsecret1', perm_users=True))
		db.session.add(APIClient(service=Service(name='test2'), auth_username='test2', auth_password='testsecret2'))

	def test_basic(self):
		r = self.client.get(path=url_for('testendpoint1'), headers=[basic_auth('test1', 'testsecret1')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		r = self.client.get(path=url_for('testendpoint2'), headers=[basic_auth('test1', 'testsecret1')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		r = self.client.get(path=url_for('testendpoint1'), headers=[basic_auth('test2', 'testsecret2')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)

	def test_basic_invalid_credentials(self):
		r = self.client.get(path=url_for('testendpoint1'), headers=[basic_auth('test-none', 'testsecret-none')], follow_redirects=True)
		self.assertEqual(r.status_code, 401)
		r = self.client.get(path=url_for('testendpoint1'), headers=[basic_auth('test1', 'testsecret2')], follow_redirects=True)
		self.assertEqual(r.status_code, 401)

	def test_basic_missing_scope(self):
		r = self.client.get(path=url_for('testendpoint2'), headers=[basic_auth('test2', 'testsecret2')], follow_redirects=True)
		self.assertEqual(r.status_code, 403)

	def test_no_auth(self):
		r = self.client.get(path=url_for('testendpoint1'), follow_redirects=True)
		self.assertEqual(r.status_code, 401)

	def test_auth_password_rehash(self):
		db.session.add(APIClient(service=Service(name='test3'), auth_username='test3', auth_password=PlaintextPasswordHash.from_password('testsecret3')))
		db.session.commit()
		self.assertIsInstance(APIClient.query.filter_by(auth_username='test3').one().auth_password, PlaintextPasswordHash)
		r = self.client.get(path=url_for('testendpoint1'), headers=[basic_auth('test3', 'testsecret3')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		api_client = APIClient.query.filter_by(auth_username='test3').one()
		self.assertIsInstance(api_client.auth_password, APIClient.auth_password.method_cls)
		self.assertTrue(api_client.auth_password.verify('testsecret3'))
		r = self.client.get(path=url_for('testendpoint1'), headers=[basic_auth('test3', 'testsecret3')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)

class TestAPIGetmails(UffdTestCase):
	def setUpDB(self):
		db.session.add(APIClient(service=Service(name='test'), auth_username='test', auth_password='test', perm_mail_aliases=True))

	def test_lookup(self):
		r = self.client.get(path=url_for('api.getmails', receive_address='test1@example.com'), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.json, [{'name': 'test', 'receive_addresses': ['test1@example.com', 'test2@example.com'], 'destination_addresses': ['testuser@mail.example.com']}])
		r = self.client.get(path=url_for('api.getmails', receive_address='test2@example.com'), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.json, [{'name': 'test', 'receive_addresses': ['test1@example.com', 'test2@example.com'], 'destination_addresses': ['testuser@mail.example.com']}])

	def test_lookup_notfound(self):
		r = self.client.get(path=url_for('api.getmails', receive_address='test3@example.com'), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.json, [])

	def test_lookup_case_folding(self):
		r = self.client.get(path=url_for('api.getmails', receive_address='Test1@example.com'), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.json, [{'name': 'test', 'receive_addresses': ['test1@example.com', 'test2@example.com'], 'destination_addresses': ['testuser@mail.example.com']}])

class TestAPICheckPassword(UffdTestCase):
	def setUpDB(self):
		db.session.add(APIClient(service=Service(name='test'), auth_username='test', auth_password='test', perm_checkpassword=True))

	def test(self):
		r = self.client.post(path=url_for('api.checkpassword'), data={'loginname': 'testuser', 'password': 'userpassword'}, headers=[basic_auth('test', 'test')])
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.json['loginname'], 'testuser')

	def test_password_rehash(self):
		self.get_user().password = PlaintextPasswordHash.from_password('userpassword')
		db.session.commit()
		self.assertIsInstance(self.get_user().password, PlaintextPasswordHash)
		db_flush()
		r = self.client.post(path=url_for('api.checkpassword'), data={'loginname': 'testuser', 'password': 'userpassword'}, headers=[basic_auth('test', 'test')])
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.json['loginname'], 'testuser')
		self.assertIsInstance(self.get_user().password, User.password.method_cls)
		self.assertTrue(self.get_user().password.verify('userpassword'))

	def test_wrong_password(self):
		r = self.client.post(path=url_for('api.checkpassword'), data={'loginname': 'testuser', 'password': 'wrongpassword'}, headers=[basic_auth('test', 'test')])
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.json, None)

class TestAPIGetusers(UffdTestCase):
	def setUpDB(self):
		db.session.add(APIClient(service=Service(name='test'), auth_username='test', auth_password='test', perm_users=True))

	def fix_result(self, result):
		result.sort(key=lambda user: user['id'])
		for user in result:
			user['groups'].sort()
		return result

	def test_all(self):
		r = self.client.get(path=url_for('api.getusers'), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(self.fix_result(r.json), [
			{'displayname': 'Test User', 'email': 'test@example.com', 'id': 10000, 'loginname': 'testuser', 'groups': ['uffd_access', 'users']},
			{'displayname': 'Test Admin', 'email': 'admin@example.com', 'id': 10001, 'loginname': 'testadmin', 'groups': ['uffd_access', 'uffd_admin', 'users']}
		])

	def test_id(self):
		r = self.client.get(path=url_for('api.getusers', id=10000), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(self.fix_result(r.json), [
			{'displayname': 'Test User', 'email': 'test@example.com', 'id': 10000, 'loginname': 'testuser', 'groups': ['uffd_access', 'users']},
		])

	def test_id_empty(self):
		r = self.client.get(path=url_for('api.getusers', id=0), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.json, [])

	def test_with_remailer(self):
		service = Service.query.filter_by(name='test').one()
		service.remailer_mode = RemailerMode.ENABLED_V1
		db.session.commit()
		user = self.get_user()
		self.app.config['REMAILER_DOMAIN'] = 'remailer.example.com'
		r = self.client.get(path=url_for('api.getusers', id=10000), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		service = Service.query.filter_by(name='test').one()
		self.assertEqual(self.fix_result(r.json), [
			{'displayname': 'Test User', 'email': remailer.build_v1_address(service.id, user.id), 'id': 10000, 'loginname': 'testuser', 'groups': ['uffd_access', 'users']},
		])

	def test_loginname(self):
		r = self.client.get(path=url_for('api.getusers', loginname='testuser'), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(self.fix_result(r.json), [
			{'displayname': 'Test User', 'email': 'test@example.com', 'id': 10000, 'loginname': 'testuser', 'groups': ['uffd_access', 'users']},
		])

	def test_loginname_empty(self):
		r = self.client.get(path=url_for('api.getusers', loginname='notauser'), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.json, [])

	def test_email(self):
		r = self.client.get(path=url_for('api.getusers', email='admin@example.com'), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(self.fix_result(r.json), [
			{'displayname': 'Test Admin', 'email': 'admin@example.com', 'id': 10001, 'loginname': 'testadmin', 'groups': ['uffd_access', 'uffd_admin', 'users']}
		])

	def test_email_with_remailer(self):
		service = Service.query.filter_by(name='test').one()
		service.remailer_mode = RemailerMode.ENABLED_V1
		db.session.commit()
		user = self.get_admin()
		self.app.config['REMAILER_DOMAIN'] = 'remailer.example.com'
		r = self.client.get(path=url_for('api.getusers', email=remailer.build_v1_address(service.id, user.id)), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		service = Service.query.filter_by(name='test').one()
		self.assertEqual(self.fix_result(r.json), [
			{'displayname': 'Test Admin', 'email': remailer.build_v1_address(service.id, user.id), 'id': 10001, 'loginname': 'testadmin', 'groups': ['uffd_access', 'uffd_admin', 'users']}
		])

	def test_email_empty(self):
		r = self.client.get(path=url_for('api.getusers', email='foo@bar'), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.json, [])

	def test_group(self):
		r = self.client.get(path=url_for('api.getusers', group='uffd_admin'), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(self.fix_result(r.json), [
			{'displayname': 'Test Admin', 'email': 'admin@example.com', 'id': 10001, 'loginname': 'testadmin', 'groups': ['uffd_access', 'uffd_admin', 'users']}
		])

	def test_group_empty(self):
		r = self.client.get(path=url_for('api.getusers', group='notagroup'), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.json, [])

class TestAPIGetgroups(UffdTestCase):
	def setUpDB(self):
		db.session.add(APIClient(service=Service(name='test'), auth_username='test', auth_password='test', perm_users=True))

	def fix_result(self, result):
		result.sort(key=lambda group: group['id'])
		for group in result:
			group['members'].sort()
		return result

	def test_all(self):
		r = self.client.get(path=url_for('api.getgroups'), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(self.fix_result(r.json), [
			{'id': 20001, 'members': ['testadmin', 'testuser'], 'name': 'users'},
			{'id': 20002, 'members': ['testadmin', 'testuser'], 'name': 'uffd_access'},
			{'id': 20003, 'members': ['testadmin'], 'name': 'uffd_admin'}
		])

	def test_id(self):
		r = self.client.get(path=url_for('api.getgroups', id=20002), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(self.fix_result(r.json), [
			{'id': 20002, 'members': ['testadmin', 'testuser'], 'name': 'uffd_access'},
		])

	def test_id_empty(self):
		r = self.client.get(path=url_for('api.getgroups', id=0), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.json, [])

	def test_name(self):
		r = self.client.get(path=url_for('api.getgroups', name='uffd_admin'), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(self.fix_result(r.json), [
			{'id': 20003, 'members': ['testadmin'], 'name': 'uffd_admin'}
		])

	def test_name_empty(self):
		r = self.client.get(path=url_for('api.getgroups', name='notagroup'), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.json, [])

	def test_member(self):
		r = self.client.get(path=url_for('api.getgroups', member='testuser'), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(self.fix_result(r.json), [
			{'id': 20001, 'members': ['testadmin', 'testuser'], 'name': 'users'},
			{'id': 20002, 'members': ['testadmin', 'testuser'], 'name': 'uffd_access'},
		])

	def test_member_empty(self):
		r = self.client.get(path=url_for('api.getgroups', member='notauser'), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.json, [])

class TestAPIRemailerResolve(UffdTestCase):
	def setUpDB(self):
		db.session.add(APIClient(service=Service(name='test'), auth_username='test', auth_password='test', perm_remailer=True))
		db.session.add(Service(name='service1'))
		db.session.add(Service(name='service2', remailer_mode=RemailerMode.ENABLED_V1))

	def test(self):
		self.app.config['REMAILER_DOMAIN'] = 'remailer.example.com'
		service = Service.query.filter_by(name='service2').one()
		r = self.client.get(path=url_for('api.resolve_remailer', orig_address=remailer.build_v1_address(service.id, self.get_user().id)), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.json, {'address': self.get_user().primary_email.address})
		r = self.client.get(path=url_for('api.resolve_remailer', orig_address='foo@bar'), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.json, {'address': None})

	def test_invalid(self):
		r = self.client.get(path=url_for('api.resolve_remailer', orig_address=['foo', 'bar']), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 400)
		r = self.client.get(path=url_for('api.resolve_remailer'), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 400)
		r = self.client.get(path=url_for('api.resolve_remailer', foo='bar'), headers=[basic_auth('test', 'test')], follow_redirects=True)
		self.assertEqual(r.status_code, 400)

class TestAPIMetricsPrometheus(UffdTestCase):
	def setUpDB(self):
		db.session.add(APIClient(service=Service(name='test'), auth_username='test', auth_password='test', perm_metrics=True))

	def test(self):
		r = self.client.get(path=url_for('api.prometheus_metrics'), headers=[basic_auth('test', 'test')])
		self.assertEqual(r.status_code, 200)
		self.assertTrue("uffd_version_info" in r.data.decode())

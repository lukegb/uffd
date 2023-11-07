import time

from flask import url_for, session, request

from uffd.database import db
from uffd.models import Role, RoleGroup, MFAMethod, RecoveryCodeMethod, TOTPMethod, WebauthnMethod
from uffd.models.mfa import _hotp

from tests.utils import dump, UffdTestCase, db_flush

def get_fido2_test_cred(self):
	try:
		from uffd.fido2_compat import AttestedCredentialData
	except ImportError:
		self.skipTest('fido2 could not be imported')
	# Example public key from webauthn spec 6.5.1.1
	return AttestedCredentialData(bytes.fromhex('00000000000000000000000000000000'+'0040'+'053cbcc9d37a61d3bac87cdcc77ee326256def08ab15775d3a720332e4101d14fae95aeee3bc9698781812e143c0597dc6e180595683d501891e9dd030454c0a'+'A501020326200121582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c'))

class TestMfaViews(UffdTestCase):
	def setUp(self):
		super().setUp()
		db.session.add(RecoveryCodeMethod(user=self.get_admin()))
		db.session.add(TOTPMethod(user=self.get_admin(), name='Admin Phone'))
		# We don't want to skip all tests only because fido2 is not installed!
		#db.session.add(WebauthnMethod(user=get_testadmin(), cred=get_fido2_test_cred(self), name='Admin FIDO2 dongle'))
		db.session.commit()

	def add_recovery_codes(self, count=10):
		user = self.get_user()
		for _ in range(count):
			db.session.add(RecoveryCodeMethod(user=user))
		db.session.commit()

	def add_totp(self):
		db.session.add(TOTPMethod(user=self.get_user(), name='My phone'))
		db.session.commit()

	def add_webauthn(self):
		db.session.add(WebauthnMethod(user=self.get_user(), cred=get_fido2_test_cred(self), name='My FIDO2 dongle'))
		db.session.commit()

	def test_setup_disabled(self):
		self.login_as('user')
		r = self.client.get(path=url_for('mfa.setup'), follow_redirects=True)
		dump('mfa_setup_disabled', r)
		self.assertEqual(r.status_code, 200)

	def test_setup_recovery_codes(self):
		self.login_as('user')
		self.add_recovery_codes()
		r = self.client.get(path=url_for('mfa.setup'), follow_redirects=True)
		dump('mfa_setup_only_recovery_codes', r)
		self.assertEqual(r.status_code, 200)

	def test_setup_enabled(self):
		self.login_as('user')
		self.add_recovery_codes()
		self.add_totp()
		self.add_webauthn()
		r = self.client.get(path=url_for('mfa.setup'), follow_redirects=True)
		dump('mfa_setup_enabled', r)
		self.assertEqual(r.status_code, 200)

	def test_setup_few_recovery_codes(self):
		self.login_as('user')
		self.add_totp()
		self.add_recovery_codes(1)
		r = self.client.get(path=url_for('mfa.setup'), follow_redirects=True)
		dump('mfa_setup_few_recovery_codes', r)
		self.assertEqual(r.status_code, 200)

	def test_setup_no_recovery_codes(self):
		self.login_as('user')
		self.add_totp()
		r = self.client.get(path=url_for('mfa.setup'), follow_redirects=True)
		dump('mfa_setup_no_recovery_codes', r)
		self.assertEqual(r.status_code, 200)

	def test_disable(self):
		baserole = Role(name='baserole', is_default=True)
		db.session.add(baserole)
		baserole.groups[self.get_access_group()] = RoleGroup()
		db.session.commit()
		self.login_as('user')
		self.add_recovery_codes()
		self.add_totp()
		admin_methods = len(MFAMethod.query.filter_by(user=self.get_admin()).all())
		r = self.client.get(path=url_for('mfa.disable'), follow_redirects=True)
		dump('mfa_disable', r)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('mfa.disable_confirm'), follow_redirects=True)
		dump('mfa_disable_submit', r)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(len(MFAMethod.query.filter_by(user=request.user).all()), 0)
		self.assertEqual(len(MFAMethod.query.filter_by(user=self.get_admin()).all()), admin_methods)

	def test_disable_recovery_only(self):
		baserole = Role(name='baserole', is_default=True)
		db.session.add(baserole)
		baserole.groups[self.get_access_group()] = RoleGroup()
		db.session.commit()
		self.login_as('user')
		self.add_recovery_codes()
		admin_methods = len(MFAMethod.query.filter_by(user=self.get_admin()).all())
		self.assertNotEqual(len(MFAMethod.query.filter_by(user=request.user).all()), 0)
		r = self.client.get(path=url_for('mfa.disable'), follow_redirects=True)
		dump('mfa_disable_recovery_only', r)
		self.assertEqual(r.status_code, 200)
		r = self.client.post(path=url_for('mfa.disable_confirm'), follow_redirects=True)
		dump('mfa_disable_recovery_only_submit', r)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(len(MFAMethod.query.filter_by(user=request.user).all()), 0)
		self.assertEqual(len(MFAMethod.query.filter_by(user=self.get_admin()).all()), admin_methods)

	def test_admin_disable(self):
		for method in MFAMethod.query.filter_by(user=self.get_admin()).all():
			if not isinstance(method, RecoveryCodeMethod):
				db.session.delete(method)
		db.session.commit()
		self.add_recovery_codes()
		self.add_totp()
		self.login_as('admin')
		self.assertIsNotNone(request.user)
		admin_methods = len(MFAMethod.query.filter_by(user=self.get_admin()).all())
		r = self.client.get(path=url_for('mfa.admin_disable', id=self.get_user().id), follow_redirects=True)
		dump('mfa_admin_disable', r)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(len(MFAMethod.query.filter_by(user=self.get_user()).all()), 0)
		self.assertEqual(len(MFAMethod.query.filter_by(user=self.get_admin()).all()), admin_methods)

	def test_setup_recovery(self):
		self.login_as('user')
		self.assertEqual(len(RecoveryCodeMethod.query.filter_by(user=request.user).all()), 0)
		r = self.client.post(path=url_for('mfa.setup_recovery'), follow_redirects=True)
		dump('mfa_setup_recovery', r)
		self.assertEqual(r.status_code, 200)
		methods = RecoveryCodeMethod.query.filter_by(user=request.user).all()
		self.assertNotEqual(len(methods), 0)
		r = self.client.post(path=url_for('mfa.setup_recovery'), follow_redirects=True)
		dump('mfa_setup_recovery_reset', r)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(len(RecoveryCodeMethod.query.filter_by(id=methods[0].id).all()), 0)
		self.assertNotEqual(len(methods), 0)

	def test_setup_totp(self):
		self.login_as('user')
		self.add_recovery_codes()
		r = self.client.get(path=url_for('mfa.setup_totp', name='My TOTP Authenticator'), follow_redirects=True)
		dump('mfa_setup_totp', r)
		self.assertEqual(r.status_code, 200)
		self.assertNotEqual(len(session.get('mfa_totp_key', '')), 0)

	def test_setup_totp_without_recovery(self):
		self.login_as('user')
		r = self.client.get(path=url_for('mfa.setup_totp', name='My TOTP Authenticator'), follow_redirects=True)
		dump('mfa_setup_totp_without_recovery', r)
		self.assertEqual(r.status_code, 200)

	def test_setup_totp_finish(self):
		baserole = Role(name='baserole', is_default=True)
		db.session.add(baserole)
		baserole.groups[self.get_access_group()] = RoleGroup()
		db.session.commit()
		self.login_as('user')
		self.add_recovery_codes()
		self.assertEqual(len(TOTPMethod.query.filter_by(user=request.user).all()), 0)
		r = self.client.get(path=url_for('mfa.setup_totp', name='My TOTP Authenticator'), follow_redirects=True)
		method = TOTPMethod(request.user, key=session.get('mfa_totp_key', ''))
		code = _hotp(int(time.time()/30), method.raw_key)
		r = self.client.post(path=url_for('mfa.setup_totp_finish', name='My TOTP Authenticator'), data={'code': code}, follow_redirects=True)
		dump('mfa_setup_totp_finish', r)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(len(TOTPMethod.query.filter_by(user=request.user).all()), 1)

	def test_setup_totp_finish_without_recovery(self):
		self.login_as('user')
		self.assertEqual(len(TOTPMethod.query.filter_by(user=request.user).all()), 0)
		r = self.client.get(path=url_for('mfa.setup_totp', name='My TOTP Authenticator'), follow_redirects=True)
		method = TOTPMethod(request.user, key=session.get('mfa_totp_key', ''))
		code = _hotp(int(time.time()/30), method.raw_key)
		r = self.client.post(path=url_for('mfa.setup_totp_finish', name='My TOTP Authenticator'), data={'code': code}, follow_redirects=True)
		dump('mfa_setup_totp_finish_without_recovery', r)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(len(TOTPMethod.query.filter_by(user=request.user).all()), 0)

	def test_setup_totp_finish_wrong_code(self):
		self.login_as('user')
		self.add_recovery_codes()
		self.assertEqual(len(TOTPMethod.query.filter_by(user=request.user).all()), 0)
		r = self.client.get(path=url_for('mfa.setup_totp', name='My TOTP Authenticator'), follow_redirects=True)
		method = TOTPMethod(request.user, key=session.get('mfa_totp_key', ''))
		code = _hotp(int(time.time()/30), method.raw_key)
		code = str(int(code[0])+1)[-1] + code[1:]
		r = self.client.post(path=url_for('mfa.setup_totp_finish', name='My TOTP Authenticator'), data={'code': code}, follow_redirects=True)
		dump('mfa_setup_totp_finish_wrong_code', r)
		self.assertEqual(r.status_code, 200)
		db_flush()
		self.assertEqual(len(TOTPMethod.query.filter_by(user=request.user).all()), 0)

	def test_setup_totp_finish_empty_code(self):
		self.login_as('user')
		self.add_recovery_codes()
		self.assertEqual(len(TOTPMethod.query.filter_by(user=request.user).all()), 0)
		r = self.client.get(path=url_for('mfa.setup_totp', name='My TOTP Authenticator'), follow_redirects=True)
		r = self.client.post(path=url_for('mfa.setup_totp_finish', name='My TOTP Authenticator'), data={'code': ''}, follow_redirects=True)
		dump('mfa_setup_totp_finish_empty_code', r)
		self.assertEqual(r.status_code, 200)
		db_flush()
		self.assertEqual(len(TOTPMethod.query.filter_by(user=request.user).all()), 0)

	def test_delete_totp(self):
		baserole = Role(name='baserole', is_default=True)
		db.session.add(baserole)
		baserole.groups[self.get_access_group()] = RoleGroup()
		db.session.commit()
		self.login_as('user')
		self.add_recovery_codes()
		self.add_totp()
		method = TOTPMethod(request.user, name='test')
		db.session.add(method)
		db.session.commit()
		self.assertEqual(len(TOTPMethod.query.filter_by(user=request.user).all()), 2)
		r = self.client.get(path=url_for('mfa.delete_totp', id=method.id), follow_redirects=True)
		dump('mfa_delete_totp', r)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(len(TOTPMethod.query.filter_by(id=method.id).all()), 0)
		self.assertEqual(len(TOTPMethod.query.filter_by(user=request.user).all()), 1)

	# TODO: webauthn setup tests

	def test_auth_integration(self):
		self.add_recovery_codes()
		self.add_totp()
		db.session.commit()
		self.assertIsNone(request.user)
		r = self.login_as('user')
		dump('mfa_auth_redirected', r)
		self.assertEqual(r.status_code, 200)
		self.assertIn(b'/mfa/auth', r.data)
		self.assertIsNone(request.user)
		r = self.client.get(path=url_for('mfa.auth'), follow_redirects=False)
		dump('mfa_auth', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(request.user)

	def test_auth_disabled(self):
		self.assertIsNone(request.user)
		self.login_as('user')
		r = self.client.get(path=url_for('mfa.auth', ref='/redirecttarget'), follow_redirects=False)
		self.assertEqual(r.status_code, 302)
		self.assertTrue(r.location.endswith('/redirecttarget'))
		self.assertIsNotNone(request.user)

	def test_auth_recovery_only(self):
		self.add_recovery_codes()
		self.assertIsNone(request.user)
		self.login_as('user')
		r = self.client.get(path=url_for('mfa.auth', ref='/redirecttarget'), follow_redirects=False)
		self.assertEqual(r.status_code, 302)
		self.assertTrue(r.location.endswith('/redirecttarget'))
		self.assertIsNotNone(request.user)

	def test_auth_recovery_code(self):
		self.add_recovery_codes()
		self.add_totp()
		method = RecoveryCodeMethod(user=self.get_user())
		db.session.add(method)
		db.session.commit()
		method_id = method.id
		self.login_as('user')
		r = self.client.get(path=url_for('mfa.auth'), follow_redirects=False)
		dump('mfa_auth_recovery_code', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(request.user)
		r = self.client.post(path=url_for('mfa.auth_finish', ref='/redirecttarget'), data={'code': method.code})
		self.assertEqual(r.status_code, 302)
		self.assertTrue(r.location.endswith('/redirecttarget'))
		self.assertIsNotNone(request.user)
		self.assertEqual(len(RecoveryCodeMethod.query.filter_by(id=method_id).all()), 0)

	def test_auth_totp_code(self):
		self.add_recovery_codes()
		self.add_totp()
		method = TOTPMethod(user=self.get_user(), name='testname')
		raw_key = method.raw_key
		db.session.add(method)
		db.session.commit()
		self.login_as('user')
		r = self.client.get(path=url_for('mfa.auth'), follow_redirects=False)
		dump('mfa_auth_totp_code', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(request.user)
		code = _hotp(int(time.time()/30), raw_key)
		r = self.client.post(path=url_for('mfa.auth_finish'), data={'code': code}, follow_redirects=True)
		dump('mfa_auth_totp_code_submit', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNotNone(request.user)

	def test_auth_totp_code_reuse(self):
		self.add_recovery_codes()
		self.add_totp()
		method = TOTPMethod(user=self.get_user(), name='testname')
		raw_key = method.raw_key
		db.session.add(method)
		db.session.commit()
		self.login_as('user')
		r = self.client.get(path=url_for('mfa.auth'), follow_redirects=False)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(request.user)
		code = _hotp(int(time.time()/30), raw_key)
		r = self.client.post(path=url_for('mfa.auth_finish'), data={'code': code}, follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertIsNotNone(request.user)
		self.login_as('user')
		r = self.client.get(path=url_for('mfa.auth'), follow_redirects=False)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(request.user)
		r = self.client.post(path=url_for('mfa.auth_finish'), data={'code': code}, follow_redirects=True)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(request.user)

	def test_auth_empty_code(self):
		self.add_recovery_codes()
		self.add_totp()
		self.login_as('user')
		r = self.client.get(path=url_for('mfa.auth'), follow_redirects=False)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(request.user)
		r = self.client.post(path=url_for('mfa.auth_finish'), data={'code': ''}, follow_redirects=True)
		dump('mfa_auth_empty_code', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(request.user)

	def test_auth_invalid_code(self):
		self.add_recovery_codes()
		self.add_totp()
		method = TOTPMethod(user=self.get_user(), name='testname')
		raw_key = method.raw_key
		db.session.add(method)
		db.session.commit()
		self.login_as('user')
		r = self.client.get(path=url_for('mfa.auth'), follow_redirects=False)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(request.user)
		code = _hotp(int(time.time()/30), raw_key)
		code = str(int(code[0])+1)[-1] + code[1:]
		r = self.client.post(path=url_for('mfa.auth_finish'), data={'code': code}, follow_redirects=True)
		dump('mfa_auth_invalid_code', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(request.user)

	def test_auth_ratelimit(self):
		self.add_recovery_codes()
		self.add_totp()
		method = TOTPMethod(user=self.get_user(), name='testname')
		raw_key = method.raw_key
		db.session.add(method)
		db.session.commit()
		self.login_as('user')
		self.assertIsNone(request.user)
		code = _hotp(int(time.time()/30), raw_key)
		inv_code = str(int(code[0])+1)[-1] + code[1:]
		for i in range(20):
			r = self.client.post(path=url_for('mfa.auth_finish'), data={'code': inv_code}, follow_redirects=True)
			self.assertEqual(r.status_code, 200)
			self.assertIsNone(request.user)
		r = self.client.post(path=url_for('mfa.auth_finish'), data={'code': code}, follow_redirects=True)
		dump('mfa_auth_ratelimit', r)
		self.assertEqual(r.status_code, 200)
		self.assertIsNone(request.user)

	# TODO: webauthn auth tests

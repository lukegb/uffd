import functools

from flask import Blueprint, jsonify, request, abort

from uffd.database import db
from uffd.models import User, remailer, Group, Mail, MailReceiveAddress, MailDestinationAddress, APIClient
from .session import login_get_user, login_ratelimit

bp = Blueprint('api', __name__, template_folder='templates', url_prefix='/api/v1/')

def apikey_required(permission=None):
	# pylint: disable=too-many-return-statements
	if permission is not None:
		assert APIClient.permission_exists(permission)
	def wrapper(func):
		@functools.wraps(func)
		def decorator(*args, **kwargs):
			if not request.authorization or not request.authorization.password:
				return 'Unauthorized', 401, {'WWW-Authenticate': ['Basic realm="api"']}
			client = APIClient.query.filter_by(auth_username=request.authorization.username).first()
			if not client:
				return 'Unauthorized', 401, {'WWW-Authenticate': ['Basic realm="api"']}
			if not client.auth_password.verify(request.authorization.password):
				return 'Unauthorized', 401, {'WWW-Authenticate': ['Basic realm="api"']}
			if client.auth_password.needs_rehash:
				client.auth_password = request.authorization.password
				db.session.commit()
			if permission is not None and not client.has_permission(permission):
				return 'Forbidden', 403
			request.api_client = client
			return func(*args, **kwargs)
		return decorator
	return wrapper

def generate_group_dict(group):
	return {
		'id': group.unix_gid,
		'name': group.name,
		'members': [user.loginname for user in group.members]
	}

@bp.route('/getgroups', methods=['GET', 'POST'])
@apikey_required('users')
def getgroups():
	if len(request.values) > 1:
		abort(400)
	key = (list(request.values.keys()) or [None])[0]
	values = request.values.getlist(key)
	query = Group.query
	if key is None:
		pass
	elif key == 'id' and len(values) == 1:
		query = query.filter(Group.unix_gid == values[0])
	elif key == 'name' and len(values) == 1:
		query = query.filter(Group.name == values[0])
	elif key == 'member' and len(values) == 1:
		query = query.join(Group.members).filter(User.loginname == values[0])
	else:
		abort(400)
	# Single-result queries perform better without joinedload
	if key is None or key == 'member':
		query = query.options(db.joinedload(Group.members))
	return jsonify([generate_group_dict(group) for group in query])

def generate_user_dict(user):
	return {
		'id': user.unix_uid,
		'loginname': user.loginname,
		'email': user.get_service_mail(request.api_client.service),
		'displayname': user.displayname,
		'groups': [group.name for group in user.groups]
	}

@bp.route('/getusers', methods=['GET', 'POST'])
@apikey_required('users')
def getusers():
	if len(request.values) > 1:
		abort(400)
	key = (list(request.values.keys()) or [None])[0]
	values = request.values.getlist(key)
	query = User.query
	if key is None:
		pass
	elif key == 'id' and len(values) == 1:
		query = query.filter(User.unix_uid == values[0])
	elif key == 'loginname' and len(values) == 1:
		query = query.filter(User.loginname == values[0])
	elif key == 'email' and len(values) == 1:
		query = query.filter(User.filter_by_service_mail(request.api_client.service, values[0]))
	elif key == 'group' and len(values) == 1:
		query = query.join(User.groups).filter(Group.name == values[0])
	else:
		abort(400)
	# Single-result queries perform better without joinedload
	if key is None or key == 'group':
		query = query.options(db.joinedload(User.groups))
	return jsonify([generate_user_dict(user) for user in query])

@bp.route('/checkpassword', methods=['POST'])
@apikey_required('checkpassword')
def checkpassword():
	if set(request.values.keys()) != {'loginname', 'password'}:
		abort(400)
	username = request.form['loginname'].lower()
	password = request.form['password']
	login_delay = login_ratelimit.get_delay(username)
	if login_delay:
		return 'Too Many Requests', 429, {'Retry-After': '%d'%login_delay}
	user = login_get_user(username, password)
	if user is None:
		login_ratelimit.log(username)
		return jsonify(None)
	if user.password.needs_rehash:
		user.password = password
		db.session.commit()
	return jsonify(generate_user_dict(user))

def generate_mail_dict(mail):
	return {
		'name': mail.uid,
		'receive_addresses': list(mail.receivers),
		'destination_addresses': list(mail.destinations)
	}

@bp.route('/getmails', methods=['GET', 'POST'])
@apikey_required('mail_aliases')
def getmails():
	if len(request.values) > 1:
		abort(400)
	key = (list(request.values.keys()) or [None])[0]
	values = request.values.getlist(key)
	if key is None:
		mails = Mail.query.all()
	elif key == 'name' and len(values) == 1:
		mails = Mail.query.filter_by(uid=values[0]).all()
	elif key == 'receive_address' and len(values) == 1:
		mails = Mail.query.filter(Mail.receivers.any(MailReceiveAddress.address==values[0].lower())).all()
	elif key == 'destination_address' and len(values) == 1:
		mails = Mail.query.filter(Mail.destinations.any(MailDestinationAddress.address==values[0])).all()
	else:
		abort(400)
	return jsonify([generate_mail_dict(mail) for mail in mails])

@bp.route('/resolve-remailer', methods=['GET', 'POST'])
@apikey_required('remailer')
def resolve_remailer():
	if list(request.values.keys()) != ['orig_address']:
		abort(400)
	values = request.values.getlist('orig_address')
	if len(values) != 1:
		abort(400)
	remailer_address = remailer.parse_address(values[0])
	if not remailer_address:
		return jsonify(address=None)
	return jsonify(address=remailer_address.user.mail)

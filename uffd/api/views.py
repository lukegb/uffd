import functools

from flask import Blueprint, jsonify, current_app, request, abort

from uffd.user.models import User, Group
from uffd.mail.models import Mail
from uffd.session.views import login_get_user, login_ratelimit

bp = Blueprint('api', __name__, template_folder='templates', url_prefix='/api/v1/')

def apikey_required(scope=None):
	def wrapper(func):
		@functools.wraps(func)
		def decorator(*args, **kwargs):
			if 'Authorization' not in request.headers or not request.headers['Authorization'].startswith('Bearer '):
				return 'Unauthorized', 401, {'WWW-Authenticate': 'Bearer'}
			token = request.headers['Authorization'][7:].strip()
			request.api_client = current_app.config['API_CLIENTS'].get(token)
			if request.api_client is None:
				return 'Unauthorized', 401, {'WWW-Authenticate': 'Bearer error="invalid_token"'}
			if scope is not None and scope not in request.api_client.get('scopes', []):
				return 'Unauthorized', 401, {'WWW-Authenticate': 'Bearer error="insufficient_scope",scope="%s"'%scope}
			return func(*args, **kwargs)
		return decorator
	return wrapper

def generate_group_dict(group):
	return {'id': group.gid, 'name': group.name,
	        'members': [user.loginname for user in group.members]}

@bp.route('/getgroups', methods=['GET', 'POST'])
@apikey_required()
def getgroups():
	if len(request.values) > 1:
		abort(400)
	key = (list(request.values.keys()) or [None])[0]
	values = request.values.getlist(key)
	if key is None:
		groups = Group.query.all()
	elif key == 'id' and len(values) == 1:
		groups = Group.query.filter_by(gid=values[0]).all()
	elif key == 'name' and len(values) == 1:
		groups = Group.query.filter_by(name=values[0]).all()
	elif key == 'member' and len(values) == 1:
		user = User.query.filter_by(loginname=values[0]).one_or_none()
		groups = [] if user is None else user.groups
	else:
		abort(400)
	return jsonify([generate_group_dict(group) for group in groups])

def generate_user_dict(user, all_groups=None):
	if all_groups is None:
		all_groups = user.groups
	return {'id': user.uid, 'loginname': user.loginname, 'email': user.mail, 'displayname': user.displayname,
	        'groups': [group.name for group in all_groups if user in group.members]}

@bp.route('/getusers', methods=['GET', 'POST'])
@apikey_required()
def getusers():
	if len(request.values) > 1:
		abort(400)
	key = (list(request.values.keys()) or [None])[0]
	values = request.values.getlist(key)
	if key is None:
		users = User.query.all()
	elif key == 'id' and len(values) == 1:
		users = User.query.filter_by(uid=values[0]).all()
	elif key == 'loginname' and len(values) == 1:
		users = User.query.filter_by(loginname=values[0]).all()
	elif key == 'email' and len(values) == 1:
		users = User.query.filter_by(mail=values[0]).all()
	elif key == 'group' and len(values) == 1:
		group = Group.query.filter_by(name=values[0]).one_or_none()
		users = [] if group is None else group.members
	else:
		abort(400)
	all_groups = None
	if len(users) > 1:
		all_groups = Group.query.all()
	return jsonify([generate_user_dict(user, all_groups) for user in users])

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
	return jsonify(generate_user_dict(user))

def generate_mail_dict(mail):
	return {'name': mail.uid, 'receive_addresses': list(mail.receivers),
	        'destination_addresses': list(mail.destinations)}

@bp.route('/getmails', methods=['GET', 'POST'])
@apikey_required('getmails')
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
		mails = Mail.query.filter_by(receivers=values[0]).all()
	elif key == 'destination_address' and len(values) == 1:
		mails = Mail.query.filter_by(destinations=values[0]).all()
	else:
		abort(400)
	return jsonify([generate_mail_dict(mail) for mail in mails])

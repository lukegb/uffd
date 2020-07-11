from functools import wraps

from flask import Blueprint, request, session

bp = Blueprint("csrf", __name__)

# pylint: disable=invalid-name
csrfEndpoints = []
# pylint: enable=invalid-name

def csrf_protect(func):
	csrfEndpoints.append(func.__name__)
	@wraps(func)
	def decorator(*args, **kwargs):
		if '_csrf_token' in request.values:
			token = request.values['_csrf_token']
		elif request.get_json() and ('_csrf_token' in request.get_json()):
			token = request.get_json()['_csrf_token']
		else:
			token = None
		if ('_csrf_token' not in session) or (session['_csrf_token'] != token) or not token:
			return 'csrf test failed', 403
		return func(*args, **kwargs)
	return decorator

@bp.url_defaults
def csrf_inject(endpoint, values):
	if endpoint not in csrfEndpoints or not session.get('_csrf_token'):
		return
	values['_csrf_token'] = session['_csrf_token']

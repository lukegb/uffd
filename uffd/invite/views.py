import datetime
import functools

from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, jsonify

from uffd.csrf import csrf_protect
from uffd.database import db
from uffd.ldap import ldap
from uffd.session import get_current_user, login_required, is_valid_session
from uffd.role.models import Role
from uffd.invite.models import Invite, InviteSignup, InviteGrant
from uffd.user.models import User
from uffd.sendmail import sendmail
from uffd.navbar import register_navbar
from uffd.ratelimit import host_ratelimit, format_delay
from uffd.signup.views import signup_ratelimit


bp = Blueprint('invite', __name__, template_folder='templates', url_prefix='/invite/')

def invite_acl():
	return is_valid_session() and get_current_user().is_in_group(current_app.config['ACL_ADMIN_GROUP'])

def invite_acl_required(func):
	@functools.wraps(func)
	@login_required()
	def decorator(*args, **kwargs):
		if not invite_acl():
			flash('Access denied')
			return redirect(url_for('index'))
		return func(*args, **kwargs)
	return decorator

@bp.route('/')
@register_navbar('Invites', icon='link', blueprint=bp, visible=invite_acl)
@invite_acl_required
def index():
	return render_template('invite/list.html', invites=Invite.query.all())

@bp.route('/new')
@invite_acl_required
def new():
	return render_template('invite/new.html', roles=Role.query.all())

@bp.route('/new', methods=['POST'])
@invite_acl_required
@csrf_protect(blueprint=bp)
def new_submit():
	invite = Invite(single_use=(request.values['single-use'] == '1'),
	                valid_until=datetime.datetime.fromisoformat(request.values['valid-until']),
	                allow_signup=(request.values['allow-signup'] == '1'))
	for key, value in request.values.items():
		if key.startswith('role-') and value == '1':
			role = Role.query.get(key[5:])
			invite.roles.append(role)
	db.session.add(invite)
	db.session.commit()
	return redirect(url_for('invite.index'))

@bp.route('/<int:invite_id>/disable', methods=['POST'])
@invite_acl_required
@csrf_protect(blueprint=bp)
def disable(invite_id):
	Invite.query.get_or_404(invite_id).disable()
	db.session.commit()
	return redirect(url_for('.index'))

@bp.route('/<int:invite_id>/reset', methods=['POST'])
@invite_acl_required
@csrf_protect(blueprint=bp)
def reset(invite_id):
	Invite.query.get_or_404(invite_id).reset()
	db.session.commit()
	return redirect(url_for('.index'))

@bp.route('/<token>')
def use(token):
	invite = Invite.query.filter_by(token=token).first_or_404()
	if not invite.active:
		flash('Invalid invite link')
		return redirect('/')
	return render_template('invite/use.html', invite=invite)

@bp.route('/<token>/grant', methods=['POST'])
@login_required()
def grant(token):
	invite = Invite.query.filter_by(token=token).first_or_404()
	invite_grant = InviteGrant(invite=invite, user=get_current_user())
	db.session.add(invite_grant)
	success, msg = invite_grant.apply()
	if not success:
		flash(msg)
		return redirect(url_for('selfservice.index'))
	ldap.session.commit()
	db.session.commit()
	flash('Roles successfully updated')
	return redirect(url_for('selfservice.index'))

@bp.url_defaults
def inject_invite_token(endpoint, values):
	if endpoint in ['invite.signup_submit', 'invite.signup_check'] and 'token' in request.view_args:
		values['token'] = request.view_args['token']

@bp.route('/<token>/signup')
def signup_start(token):
	invite = Invite.query.filter_by(token=token).first_or_404()
	if not invite.active:
		flash('Invalid invite link')
		return redirect('/')
	if not invite.allow_signup:
		flash('Invite link does not allow signup')
		return redirect('/')
	return render_template('signup/start.html')

@bp.route('/<token>/signupcheck', methods=['POST'])
def signup_check(token):
	if host_ratelimit.get_delay():
		return jsonify({'status': 'ratelimited'})
	host_ratelimit.log()
	invite = Invite.query.filter_by(token=token).first_or_404()
	if not invite.active or not invite.allow_signup:
		return jsonify({'status': 'error'}), 403
	if not User().set_loginname(request.form['loginname']):
		return jsonify({'status': 'invalid'})
	if User.query.filter_by(loginname=request.form['loginname']).all():
		return jsonify({'status': 'exists'})
	return jsonify({'status': 'ok'})

@bp.route('/<token>/signup', methods=['POST'])
def signup_submit(token):
	invite = Invite.query.filter_by(token=token).first_or_404()
	if request.form['password1'] != request.form['password2']:
		return render_template('signup/start.html', error='Passwords do not match')
	signup_delay = signup_ratelimit.get_delay(request.form['mail'])
	host_delay = host_ratelimit.get_delay()
	if signup_delay and signup_delay > host_delay:
		return render_template('signup/start.html', error='Too many signup requests with this mail address! Please wait %s.'%format_delay(signup_delay))
	if host_delay:
		return render_template('signup/start.html', error='Too many requests! Please wait %s.'%format_delay(host_delay))
	host_ratelimit.log()
	signup = InviteSignup(invite=invite, loginname=request.form['loginname'],
	                      displayname=request.form['displayname'],
	                      mail=request.form['mail'],
	                      password=request.form['password1'])
	valid, msg = signup.validate()
	if not valid:
		return render_template('signup/start.html', error=msg)
	db.session.add(signup)
	db.session.commit()
	sent = sendmail(signup.mail, 'Confirm your mail address', 'signup/mail.txt', signup=signup)
	if not sent:
		return render_template('signup/start.html', error='Cound not send mail')
	signup_ratelimit.log(request.form['mail'])
	return render_template('signup/submitted.html', signup=signup)

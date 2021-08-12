import datetime
import functools

from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, jsonify
from flask_babel import gettext as _, lazy_gettext
import sqlalchemy

from uffd.csrf import csrf_protect
from uffd.database import db
from uffd.ldap import ldap
from uffd.session import login_required
from uffd.role.models import Role
from uffd.invite.models import Invite, InviteSignup, InviteGrant
from uffd.user.models import User
from uffd.sendmail import sendmail
from uffd.navbar import register_navbar
from uffd.ratelimit import host_ratelimit, format_delay
from uffd.signup.views import signup_ratelimit

bp = Blueprint('invite', __name__, template_folder='templates', url_prefix='/invite/')

def invite_acl():
	if not request.user:
		return False
	if request.user.is_in_group(current_app.config['ACL_ADMIN_GROUP']):
		return True
	if request.user.is_in_group(current_app.config['ACL_SIGNUP_GROUP']):
		return True
	if Role.query.filter(Role.moderator_group_dn.in_(request.user.group_dns)).count():
		return True
	return False

def invite_acl_required(func):
	@functools.wraps(func)
	@login_required()
	def decorator(*args, **kwargs):
		if not invite_acl():
			flash('Access denied')
			return redirect(url_for('index'))
		return func(*args, **kwargs)
	return decorator

def view_acl_filter(user):
	if user.is_in_group(current_app.config['ACL_ADMIN_GROUP']):
		return sqlalchemy.true()
	creator_filter = (Invite.creator_dn == user.dn)
	rolemod_filter = Invite.roles.any(Role.moderator_group_dn.in_(user.group_dns))
	return creator_filter | rolemod_filter

def reset_acl_filter(user):
	if user.is_in_group(current_app.config['ACL_ADMIN_GROUP']):
		return sqlalchemy.true()
	return Invite.creator_dn == user.dn

@bp.route('/')
@register_navbar(14, lazy_gettext('Invites'), icon='link', blueprint=bp, visible=invite_acl)
@invite_acl_required
def index():
	invites = Invite.query.filter(view_acl_filter(request.user)).all()
	return render_template('invite/list.html', invites=invites)

@bp.route('/new')
@invite_acl_required
def new():
	if request.user.is_in_group(current_app.config['ACL_ADMIN_GROUP']):
		allow_signup = True
		roles = Role.query.all()
	else:
		allow_signup = request.user.is_in_group(current_app.config['ACL_SIGNUP_GROUP'])
		roles = Role.query.filter(Role.moderator_group_dn.in_(request.user.group_dns)).all()
	return render_template('invite/new.html', roles=roles, allow_signup=allow_signup)

@bp.route('/new', methods=['POST'])
@invite_acl_required
@csrf_protect(blueprint=bp)
def new_submit():
	invite = Invite(creator=request.user,
	                single_use=(request.values['single-use'] == '1'),
	                valid_until=datetime.datetime.fromisoformat(request.values['valid-until']),
	                allow_signup=(request.values.get('allow-signup', '0') == '1'))
	for key, value in request.values.items():
		if key.startswith('role-') and value == '1':
			invite.roles.append(Role.query.get(key[5:]))
	if invite.valid_until > datetime.datetime.now() + datetime.timedelta(days=current_app.config['INVITE_MAX_VALID_DAYS']):
		flash(_('The "Expires After" date is too far in the future'))
		return redirect(url_for('invite.new'))
	if not invite.permitted:
		flash(_('You are not allowed to create invite links with these permissions'))
		return redirect(url_for('invite.new'))
	if not invite.allow_signup and not invite.roles:
		flash(_('Invite link must either allow signup or grant at least one role'))
		return redirect(url_for('invite.new'))
	db.session.add(invite)
	db.session.commit()
	return redirect(url_for('invite.index'))

@bp.route('/<int:invite_id>/disable', methods=['POST'])
@invite_acl_required
@csrf_protect(blueprint=bp)
def disable(invite_id):
	invite = Invite.query.filter(view_acl_filter(request.user)).filter_by(id=invite_id).first_or_404()
	invite.disable()
	db.session.commit()
	return redirect(url_for('.index'))

@bp.route('/<int:invite_id>/reset', methods=['POST'])
@invite_acl_required
@csrf_protect(blueprint=bp)
def reset(invite_id):
	invite = Invite.query.filter(reset_acl_filter(request.user)).filter_by(id=invite_id).first_or_404()
	invite.reset()
	db.session.commit()
	return redirect(url_for('.index'))

@bp.route('/<token>')
def use(token):
	invite = Invite.query.filter_by(token=token).first_or_404()
	if not invite.active:
		flash(_('Invalid invite link'))
		return redirect('/')
	return render_template('invite/use.html', invite=invite)

@bp.route('/<token>/grant', methods=['POST'])
@login_required()
@csrf_protect(blueprint=bp)
def grant(token):
	invite = Invite.query.filter_by(token=token).first_or_404()
	invite_grant = InviteGrant(invite=invite, user=request.user)
	db.session.add(invite_grant)
	success, msg = invite_grant.apply()
	if not success:
		flash(msg)
		return redirect(url_for('selfservice.index'))
	ldap.session.commit()
	db.session.commit()
	flash(_('Roles successfully updated'))
	return redirect(url_for('selfservice.index'))

@bp.url_defaults
def inject_invite_token(endpoint, values):
	if endpoint in ['invite.signup_submit', 'invite.signup_check'] and 'token' in request.view_args:
		values['token'] = request.view_args['token']

@bp.route('/<token>/signup')
def signup_start(token):
	invite = Invite.query.filter_by(token=token).first_or_404()
	if not invite.active:
		flash(_('Invalid invite link'))
		return redirect('/')
	if not invite.allow_signup:
		flash(_('Invite link does not allow signup'))
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
		return render_template('signup/start.html', error=_('Passwords do not match'))
	signup_delay = signup_ratelimit.get_delay(request.form['mail'])
	host_delay = host_ratelimit.get_delay()
	if signup_delay and signup_delay > host_delay:
		return render_template('signup/start.html', error=_('Too many signup requests with this mail address! Please wait %(delay)s.',
		                                                    delay=format_delay(signup_delay)))
	if host_delay:
		return render_template('signup/start.html', error=_('Too many requests! Please wait %(delay)s.', delay=format_delay(host_delay)))
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
		return render_template('signup/start.html', error=_('Cound not send mail'))
	signup_ratelimit.log(request.form['mail'])
	return render_template('signup/submitted.html', signup=signup)

import functools

from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, jsonify
from flask_babel import gettext as _

from uffd.database import db
from uffd.ldap import ldap
from uffd.session import set_session
from uffd.user.models import User
from uffd.sendmail import sendmail
from uffd.signup.models import Signup
from uffd.ratelimit import Ratelimit, host_ratelimit, format_delay

bp = Blueprint('signup', __name__, template_folder='templates', url_prefix='/signup/')

signup_ratelimit = Ratelimit('signup', 24*60, 3)
confirm_ratelimit = Ratelimit('signup_confirm', 10*60, 3)

def signup_enabled(func):
	@functools.wraps(func)
	def decorator(*args, **kwargs):
		if not current_app.config['SELF_SIGNUP']:
			flash(_('Singup not enabled'))
			return redirect(url_for('index'))
		return func(*args, **kwargs)
	return decorator

@bp.route('/')
@signup_enabled
def signup_start():
	return render_template('signup/start.html')

@bp.route('/check', methods=['POST'])
@signup_enabled
def signup_check():
	if host_ratelimit.get_delay():
		return jsonify({'status': 'ratelimited'})
	host_ratelimit.log()
	if not User().set_loginname(request.form['loginname']):
		return jsonify({'status': 'invalid'})
	if User.query.filter_by(loginname=request.form['loginname']).all():
		return jsonify({'status': 'exists'})
	return jsonify({'status': 'ok'})

@bp.route('/', methods=['POST'])
@signup_enabled
def signup_submit():
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
	signup = Signup(loginname=request.form['loginname'],
	                displayname=request.form['displayname'],
	                mail=request.form['mail'], password=request.form['password1'])
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

# signup_confirm* views are always accessible so other modules (e.g. invite) can reuse them
@bp.route('/confirm/<token>')
def signup_confirm(token):
	signup = Signup.query.get(token)
	if not signup or signup.expired or signup.completed:
		flash(_('Invalid signup link'))
		return redirect(url_for('index'))
	return render_template('signup/confirm.html', signup=signup)

@bp.route('/confirm/<token>', methods=['POST'])
def signup_confirm_submit(token):
	signup = Signup.query.get(token)
	if not signup or signup.expired or signup.completed:
		flash(_('Invalid signup link'))
		return redirect(url_for('index'))
	confirm_delay = confirm_ratelimit.get_delay(token)
	host_delay = host_ratelimit.get_delay()
	if confirm_delay and confirm_delay > host_delay:
		return render_template('signup/confirm.html', signup=signup, error=_('Too many failed attempts! Please wait %(delay)s.', delay=format_delay(confirm_delay)))
	if host_delay:
		return render_template('signup/confirm.html', signup=signup, error=_('Too many requests! Please wait %(delay)s.', delay=format_delay(host_delay)))
	if not signup.check_password(request.form['password']):
		host_ratelimit.log()
		confirm_ratelimit.log(token)
		return render_template('signup/confirm.html', signup=signup, error=_('Wrong password'))
	user, msg = signup.finish(request.form['password'])
	if user is None:
		return render_template('signup/confirm.html', signup=signup, error=msg)
	db.session.commit()
	ldap.session.commit()
	set_session(user, password=request.form['password'], skip_mfa=True)
	flash(_('Your account was successfully created'))
	return redirect(url_for('selfservice.index'))

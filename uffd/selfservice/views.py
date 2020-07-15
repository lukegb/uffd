import datetime

import smtplib
from email.message import EmailMessage

from flask import Blueprint, render_template, request, url_for, redirect, flash, current_app

from uffd.navbar import register_navbar
from uffd.csrf import csrf_protect
from uffd.user.models import User, Group
from uffd.session import get_current_user, login_required, is_valid_session
from uffd.ldap import get_conn, escape_filter_chars, loginname_to_dn
from uffd.selfservice.models import PasswordToken
from uffd.database import db

bp = Blueprint("selfservice", __name__, template_folder='templates', url_prefix='/self/')

@bp.route("/")
@register_navbar('Selfservice', icon='portrait', blueprint=bp, visible=is_valid_session)
@login_required()
def self_index():
	return render_template('self.html', user=get_current_user())

@bp.route("/update", methods=(['POST']))
@csrf_protect(blueprint=bp)
@login_required()
def self_update():
	# TODO: actualy update the user...
	return 'OK', 200

@bp.route("/passwordreset", methods=(['GET', 'POST']))
@csrf_protect(blueprint=bp)
def self_forgot_password():
	if request.method == 'GET':
		return render_template('forgot_password.html')

	loginname = request.values['loginname']
	mail = request.values['mail']
	flash("We sent a mail to this users mail address if you entered the correct mail and login name combination")
	user = User.from_ldap_dn(loginname_to_dn(loginname))
	if user.mail == mail:
		send_passwordreset(loginname)
	return redirect(url_for('session.login'))

@bp.route("/token/password/<token>", methods=(['POST', 'GET']))
def self_token_password(token):
	session = db.session
	dbtoken = PasswordToken.query.get(token)
	if not dbtoken or dbtoken.created < (datetime.datetime.now() - datetime.timedelta(days=2)):
		flash('Token expired, please try again.')
		if dbtoken:
			session.delete(dbtoken)
			session.commit()
		return redirect(url_for('session.login'))
	if not 'loginname' in request.values:
		flash('Please set a new password.')
		return render_template('set_password.html', token=token)
	else:
		if not request.values['loginname'] == dbtoken.loginname:
			flash('That is not the correct login name for this token. Your token is now invalide. Please start the password reset process again')
			session.delete(dbtoken)
			session.commit()
			return redirect(url_for('session.login'))
		if not request.values['password1']:
			flash('Please specify a new password.')
			return render_template('set_password.html', token=token)
		user = User.from_ldap_dn(loginname_to_dn(dbtoken.loginname))
		user.set_password(request.values['password1'])
		user.to_ldap()
		flash('New password set')
		session.delete(dbtoken)
		session.commit()
		return redirect(url_for('session.login'))

def send_passwordreset(loginname):
	session = db.session
	expired_tokens = PasswordToken.query.filter(PasswordToken.created < (datetime.datetime.now() - datetime.timedelta(days=2))).all()
	for i in expired_tokens:
		session.delete(i)
	token = PasswordToken()
	token.loginname = loginname
	session.add(token)
	session.commit()

	user = User.from_ldap_dn(loginname_to_dn(loginname))

	msg = EmailMessage()
	msg.set_content(render_template('passwordreset.mail.txt', user=user, token=token.token))
	msg['Subject'] = 'Password reset'
	send_mail(user.mail, msg)

def send_mail(to, msg):
	server = smtplib.SMTP(host=current_app.config['MAIL_SERVER'], port=current_app.config['MAIL_PORT'])
	if current_app.config['MAIL_USE_STARTTLS']:
		server.starttls()
	server.login(current_app.config['MAIL_USERNAME'], current_app.config['MAIL_PASSWORD'])
	msg['From'] = current_app.config['MAIL_FROM_ADDRESS']
	msg['To'] = to
	server.send_message(msg)
	server.quit()

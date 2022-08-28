import csv
import io

from flask import Blueprint, render_template, request, url_for, redirect, flash, current_app, abort
from flask_babel import gettext as _, lazy_gettext
from sqlalchemy.exc import IntegrityError

from uffd.navbar import register_navbar
from uffd.csrf import csrf_protect
from uffd.remailer import remailer
from uffd.database import db
from uffd.models import User, UserEmail, Role
from .selfservice import send_passwordreset
from .session import login_required

bp = Blueprint("user", __name__, template_folder='templates', url_prefix='/user/')

bp.add_app_template_global(User, 'User')
bp.add_app_template_global(remailer, 'remailer')

def user_acl_check():
	return request.user and request.user.is_in_group(current_app.config['ACL_ADMIN_GROUP'])

@bp.before_request
@login_required(user_acl_check)
def user_acl():
	pass

@bp.route("/")
@register_navbar(lazy_gettext('Users'), icon='users', blueprint=bp, visible=user_acl_check)
def index():
	return render_template('user/list.html', users=User.query.all())

@bp.route("/<int:id>")
@bp.route("/new")
def show(id=None):
	user = User() if id is None else User.query.get_or_404(id)
	return render_template('user/show.html', user=user, roles=Role.query.all())

@bp.route("/<int:id>/update", methods=['POST'])
@bp.route("/new", methods=['POST'])
@csrf_protect(blueprint=bp)
def update(id=None):
	# pylint: disable=too-many-branches,too-many-statements
	if id is None:
		user = User()
		ignore_blocklist = request.form.get('ignore-loginname-blocklist', False)
		if request.form.get('serviceaccount'):
			user.is_service_user = True
		if not user.set_loginname(request.form['loginname'], ignore_blocklist=ignore_blocklist):
			flash(_('Login name does not meet requirements'))
			return redirect(url_for('user.show'))
		if not user.set_primary_email_address(request.form['email']):
			flash(_('E-Mail address is invalid'))
			return redirect(url_for('user.show'))
	else:
		user = User.query.get_or_404(id)

		for email in user.all_emails:
			if f'email-{email.id}-present' in request.form:
				email.verified = email.verified or (request.form.get(f'email-{email.id}-verified') == '1')

		for key, value in request.form.items():
			parts = key.split('-')
			if not parts[0] == 'newemail' or not parts[2] == 'address' or not value:
				continue
			tmp_id = parts[1]
			email = UserEmail(
				user=user,
				verified=(request.form.get(f'newemail-{tmp_id}-verified') == '1'),
			)
			if not email.set_address(value):
				flash(_('E-Mail address is invalid'))
				return redirect(url_for('user.show', id=id))
			db.session.add(email)

		verified_emails = UserEmail.query.filter_by(user=user, verified=True)
		email = verified_emails.filter_by(id=request.form['primary_email']).first()
		if not email:
			abort(400)
		user.primary_email = email
		if request.form['recovery_email'] == 'primary':
			user.recovery_email = None
		else:
			email = verified_emails.filter_by(id=request.form['recovery_email']).first()
			if not email:
				abort(400)
			user.recovery_email = email

		for email in user.all_emails:
			if request.form.get(f'email-{email.id}-delete') == '1':
				db.session.delete(email)

	new_displayname = request.form['displayname'] if request.form['displayname'] else request.form['loginname']
	if user.displayname != new_displayname and not user.set_displayname(new_displayname):
		flash(_('Display name does not meet requirements'))
		return redirect(url_for('user.show', id=id))

	new_password = request.form.get('password')
	if id is not None and new_password:
		if not user.set_password(new_password):
			flash(_('Password is invalid'))
			return redirect(url_for('user.show', id=id))

	db.session.add(user)

	user.roles.clear()
	for role in Role.query.all():
		if not user.is_service_user and role.is_default:
			continue
		if request.values.get('role-{}'.format(role.id), False):
			user.roles.append(role)
	user.update_groups()

	db.session.commit()
	if id is None:
		if user.is_service_user:
			flash(_('Service user created'))
		else:
			send_passwordreset(user, new=True)
			flash(_('User created. We sent the user a password reset link by e-mail'))
	else:
		flash(_('User updated'))
	return redirect(url_for('user.show', id=user.id))

@bp.route("/<int:id>/del")
@csrf_protect(blueprint=bp)
def delete(id):
	user = User.query.get_or_404(id)
	user.roles.clear()
	db.session.delete(user)
	db.session.commit()
	flash(_('Deleted user'))
	return redirect(url_for('user.index'))

@bp.route("/csv", methods=['POST'])
@csrf_protect(blueprint=bp)
def csvimport():
	csvdata = request.values.get('csv')
	if not csvdata:
		flash('No data for csv import!')
		return redirect(url_for('user.index'))

	ignore_blocklist = request.values.get('ignore-loginname-blocklist', False)

	roles = Role.query.filter_by(is_default=False).all()
	usersadded = 0
	with io.StringIO(initial_value=csvdata) as csvfile:
		csvreader = csv.reader(csvfile)
		for row in csvreader:
			if not len(row) == 3:
				flash("invalid line, ignored : {}".format(row))
				continue
			newuser = User()
			if not newuser.set_loginname(row[0], ignore_blocklist=ignore_blocklist) or not newuser.set_displayname(row[0]):
				flash("invalid login name, skipped : {}".format(row))
				continue
			if not newuser.set_primary_email_address(row[1]):
				flash("invalid e-mail address, skipped : {}".format(row))
				continue
			db.session.add(newuser)
			for role in roles:
				if str(role.id) in row[2].split(';'):
					role.members.append(newuser)
			newuser.update_groups()
			try:
				db.session.commit()
			except IntegrityError:
				flash('Error adding user {}'.format(row[0]))
				db.session.rollback()
				continue
			send_passwordreset(newuser, new=True)
			usersadded += 1
	flash('Added {} new users'.format(usersadded))
	return redirect(url_for('user.index'))

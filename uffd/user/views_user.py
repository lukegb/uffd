import csv
import io

from flask import Blueprint, render_template, request, url_for, redirect, flash, current_app
from flask_babel import gettext as _, lazy_gettext
from sqlalchemy.exc import IntegrityError

from uffd.navbar import register_navbar
from uffd.csrf import csrf_protect
from uffd.selfservice import send_passwordreset
from uffd.session import login_required
from uffd.role.models import Role
from uffd.database import db

from .models import User, remailer

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
	if id is None:
		user = User()
		ignore_blocklist = request.form.get('ignore-loginname-blocklist', False)
		if request.form.get('serviceaccount'):
			user.is_service_user = True
		if not user.set_loginname(request.form['loginname'], ignore_blocklist=ignore_blocklist):
			flash(_('Login name does not meet requirements'))
			return redirect(url_for('user.show'))
	else:
		user = User.query.get_or_404(id)
	if user.mail != request.form['mail'] and not user.set_mail(request.form['mail']):
		flash(_('Mail is invalid'))
		return redirect(url_for('user.show', id=id))
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
			flash(_('User created. We sent the user a password reset link by mail'))
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
			if not newuser.set_mail(row[1]):
				flash("invalid mail address, skipped : {}".format(row))
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

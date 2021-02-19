import csv
import io

from flask import Blueprint, render_template, request, url_for, redirect, flash, current_app

from uffd.navbar import register_navbar
from uffd.csrf import csrf_protect
from uffd.selfservice import send_passwordreset
from uffd.session import login_required, is_valid_session, get_current_user
from uffd.role.models import Role
from uffd.database import db
from uffd.ldap import ldap, LDAPCommitError

from .models import User

bp = Blueprint("user", __name__, template_folder='templates', url_prefix='/user/')
@bp.before_request
@login_required()
def user_acl(): #pylint: disable=inconsistent-return-statements
	if not user_acl_check():
		flash('Access denied')
		return redirect(url_for('index'))

def user_acl_check():
	return is_valid_session() and get_current_user().is_in_group(current_app.config['ACL_ADMIN_GROUP'])

@bp.route("/")
@register_navbar('Users', icon='users', blueprint=bp, visible=user_acl_check)
def index():
	return render_template('user_list.html', users=User.ldap_all())

@bp.route("/<int:uid>")
@bp.route("/new")
def show(uid=None):
	user = User() if uid is None else User.ldap_filter_by(uid=uid)[0]
	return render_template('user.html', user=user, roles=Role.query.all())

@bp.route("/<int:uid>/update", methods=['POST'])
@bp.route("/new", methods=['POST'])
@csrf_protect(blueprint=bp)
def update(uid=None):
	if uid is None:
		user = User()
		if not user.set_loginname(request.form['loginname']):
			flash('Login name does not meet requirements')
			return redirect(url_for('user.show'))
	else:
		user = User.ldap_filter_by(uid=uid)[0]
	if not user.set_mail(request.form['mail']):
		flash('Mail is invalid')
		return redirect(url_for('user.show', uid=uid))
	new_displayname = request.form['displayname'] if request.form['displayname'] else request.form['loginname']
	if not user.set_displayname(new_displayname):
		flash('Display name does not meet requirements')
		return redirect(url_for('user.show', uid=uid))
	new_password = request.form.get('password')
	if uid is not None and new_password:
		user.set_password(new_password)
	user.roles.clear()
	for role in Role.query.all():
		if request.values.get('role-{}'.format(role.id), False) or role.name in current_app.config["ROLES_BASEROLES"]:
			user.roles.add(role)
	user.update_groups()
	ldap.session.add(user)
	ldap.session.commit()
	db.session.commit()
	if uid is None:
		send_passwordreset(user, new=True)
		flash('User created. We sent the user a password reset link by mail')
	else:
		flash('User updated')
	return redirect(url_for('user.show', uid=user.uid))

@bp.route("/<int:uid>/del")
@csrf_protect(blueprint=bp)
def delete(uid):
	user = User.ldap_filter_by(uid=uid)[0]
	user.roles.clear()
	ldap.session.delete(user)
	ldap.session.commit()
	db.session.commit()
	flash('Deleted user')
	return redirect(url_for('user.index'))

@bp.route("/csv", methods=['POST'])
@csrf_protect(blueprint=bp)
def csvimport():
	csvdata = request.values.get('csv')
	if not csvdata:
		flash('No data for csv import!')
		return redirect(url_for('user.index'))

	roles = Role.query.all()
	usersadded = 0
	with io.StringIO(initial_value=csvdata) as csvfile:
		csvreader = csv.reader(csvfile)
		for row in csvreader:
			if not len(row) == 3:
				flash("invalid line, ignored : {}".format(row))
				continue
			newuser = User()
			if not newuser.set_loginname(row[0]) or not newuser.set_displayname(row[0]):
				flash("invalid login name, skipped : {}".format(row))
				continue
			if not newuser.set_mail(row[1]):
				flash("invalid mail address, skipped : {}".format(row))
				continue
			for role in roles:
				if (str(role.id) in row[2].split(';')) or role.name in current_app.config["ROLES_BASEROLES"]:
					role.members.add(newuser)
			newuser.update_groups()
			ldap.session.add(newuser)
			try:
				ldap.session.commit()
				db.session.commit()
			except LDAPCommitError:
				flash('Error adding user {}'.format(row[0]))
				ldap.session.rollback()
				db.session.rollback()
				continue
			send_passwordreset(newuser, new=True)
			usersadded += 1
	flash('Added {} new users'.format(usersadded))
	return redirect(url_for('user.index'))

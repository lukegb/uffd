import csv
import io

from flask import Blueprint, render_template, request, url_for, redirect, flash, current_app

from uffd.navbar import register_navbar
from uffd.csrf import csrf_protect
from uffd.selfservice import send_passwordreset
from uffd.ldap import get_conn, escape_filter_chars
from uffd.session import login_required, is_valid_session, get_current_user
from uffd.role.models import Role
from uffd.database import db

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
	conn = get_conn()
	conn.search(current_app.config["LDAP_BASE_USER"], '(objectclass=person)')
	users = []
	for i in conn.entries:
		users.append(User.from_ldap(i))
	return render_template('user_list.html', users=users)

@bp.route("/<int:uid>")
@bp.route("/new")
def show(uid=None):
	if not uid:
		user = User()
		ldif = '<none yet>'
	else:
		conn = get_conn()
		conn.search(current_app.config["LDAP_BASE_USER"], '(&(objectclass=person)(uidNumber={}))'.format((escape_filter_chars(uid))))
		assert len(conn.entries) == 1
		user = User.from_ldap(conn.entries[0])
		ldif = conn.entries[0].entry_to_ldif()
	return render_template('user.html', user=user, user_ldif=ldif, roles=Role.query.all())

@bp.route("/<int:uid>/update", methods=['POST'])
@bp.route("/new", methods=['POST'])
@csrf_protect(blueprint=bp)
def update(uid=False):
	conn = get_conn()
	is_newuser = bool(not uid)
	if is_newuser:
		user = User()
		if not user.set_loginname(request.form['loginname']):
			flash('Login name does not meet requirements')
			return redirect(url_for('user.show'))
	else:
		conn.search(current_app.config["LDAP_BASE_USER"], '(&(objectclass=person)(uidNumber={}))'.format((escape_filter_chars(uid))))
		assert len(conn.entries) == 1
		user = User.from_ldap(conn.entries[0])
	if not user.set_mail(request.form['mail']):
		flash('Mail is invalide.')
		return redirect(url_for('user.show', uid=uid))
	new_displayname = request.form['displayname'] if request.form['displayname'] else request.form['loginname']
	if not user.set_displayname(new_displayname):
		flash('Display name does not meet requirements')
		return redirect(url_for('user.show', uid=uid))
	new_password = request.form.get('password')
	if new_password and not is_newuser:
		user.set_password(new_password)

	session = db.session
	roles = Role.query.all()
	for role in roles:
		role_member_dns = role.member_dns()
		if request.values.get('role-{}'.format(role.id), False) or role.name in current_app.config["ROLES_BASEROLES"]:
			if user.dn in role_member_dns:
				continue
			role.add_member(user)
		elif user.dn in role_member_dns:
			role.del_member(user)

	if user.to_ldap(new=is_newuser):
		if is_newuser:
			send_passwordreset(user.loginname)
			flash('User created. We sent the user a password reset link by mail')
		else:
			flash('User updated')

		usergroups = set()
		for role in Role.get_for_user(user).all():
			usergroups.update(role.group_dns())
		user.replace_group_dns(usergroups)
		session.commit()
	else:
		flash('Error updating user: {}'.format(conn.result['message']))
		session.rollback()
	return redirect(url_for('user.show', uid=user.uid))

@bp.route("/<int:uid>/del")
@csrf_protect(blueprint=bp)
def delete(uid):
	conn = get_conn()
	conn.search(current_app.config["LDAP_BASE_USER"], '(&(objectclass=person)(uidNumber={}))'.format((escape_filter_chars(uid))))
	assert len(conn.entries) == 1
	user = User.from_ldap(conn.entries[0])

	session = db.session
	roles = Role.query.all()
	for role in roles:
		if user.dn in role.member_dns():
			role.del_member(user)

	if conn.delete(conn.entries[0].entry_dn):
		flash('Deleted user')
		session.commit()
	else:
		flash('Could not delete user: {}'.format(conn.result['message']))
		session.rollback()
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
			session = db.session

			for role in roles:
				role_member_dns = role.member_dns()
				if (str(role.id) in row[2].split(';')) or role.name in current_app.config["ROLES_BASEROLES"]:
					if newuser.dn in role_member_dns:
						continue
					role.add_member(newuser)

			result = newuser.to_ldap(new=True)
			print(result)
			if result:
				send_passwordreset(newuser.loginname)

				usergroups = set()
				for role in Role.get_for_user(newuser).all():
					usergroups.update(role.group_dns())
				newuser.replace_group_dns(usergroups)

				session.commit()
				usersadded += 1
			else:
				flash('Error adding user {}'.format(row[0]))
				session.rollback()
				continue

	flash('Added {} new users'.format(usersadded))
	return redirect(url_for('user.index'))

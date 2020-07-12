from flask import Blueprint, render_template, request, url_for, redirect, flash, current_app

from uffd.navbar import register_navbar
from uffd.csrf import csrf_protect
from uffd.ldap import get_conn, escape_filter_chars
from uffd.session import login_required

from .models import User

bp = Blueprint("user", __name__, template_folder='templates', url_prefix='/user/')

@bp.before_request
@login_required
def user_acl():
	pass

@bp.route("/")
@register_navbar('Users', icon='users', blueprint=bp)
def user_list():
	conn = get_conn()
	conn.search(current_app.config["LDAP_BASE_USER"], '(objectclass=person)')
	users = []
	for i in conn.entries:
		users.append(User.from_ldap(i))
	return render_template('user_list.html', users=users)

@bp.route("/<int:uid>")
@bp.route("/new")
def user_show(uid=None):
	if not uid:
		user = User()
		ldif = '<none yet>'
	else:
		conn = get_conn()
		conn.search(current_app.config["LDAP_BASE_USER"], '(&(objectclass=person)(uidNumber={}))'.format((escape_filter_chars(uid))))
		assert len(conn.entries) == 1
		user = User.from_ldap(conn.entries[0])
		ldif = conn.entries[0].entry_to_ldif()
	return render_template('user.html', user=user, user_ldif=ldif)

@bp.route("/<int:uid>/update", methods=['POST'])
@bp.route("/new", methods=['POST'])
def user_update(uid=False):
	conn = get_conn()
	if uid:
		conn.search(current_app.config["LDAP_BASE_USER"], '(&(objectclass=person)(uidNumber={}))'.format((escape_filter_chars(uid))))
		assert len(conn.entries) == 1
		user = User.from_ldap(conn.entries[0])
	else:
		# new user
		user = User()
		if not user.set_loginname(request.form['loginname']):
			flash('Login name does not meet requirements')
			return(url_for('.user_show'))
	user.mail = request.form['mail']
	if not user.set_displayname(request.form['displayname']):
		flash('Display name does not meet requirements')
		return(url_for('.user_show'))
	new_password = request.form.get('password')
	if new_password:
		user.set_password(new_password)
	if user.to_ldap(new=(not uid)):
		flash('User updated')
	else:
		flash('Error updating user: {}'.format(conn.result['message']))
	return redirect(url_for('.user_list'))

@bp.route("/<int:uid>/del")
@csrf_protect
def user_delete(uid):
	conn = get_conn()
	conn.search(current_app.config["LDAP_BASE_USER"], '(&(objectclass=person)(uidNumber={}))'.format((escape_filter_chars(uid))))
	assert len(conn.entries) == 1
	if conn.delete(conn.entries[0].entry_dn):
		flash('Deleted user')
	else:
		flash('Could not delete user: {}'.format(conn.result['message']))
	return redirect(url_for('.user_list'))

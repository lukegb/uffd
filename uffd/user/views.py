from flask import Blueprint, render_template, request, url_for, redirect, flash, current_app

from uffd.navbar import register_navbar
from uffd.csrf import csrf_protect
from uffd.ldap import get_conn, escape_filter_chars
from uffd.session import login_required, is_valid_session, get_current_user

from .models import User, Group

bp_user = Blueprint("user", __name__, template_folder='templates', url_prefix='/user/')
@bp_user.before_request
@login_required()
def user_acl():
	if not user_acl_check():
		flash('Access denied')
		return redirect(url_for('index'))

def user_acl_check():
	return is_valid_session() and get_current_user().is_in_group(current_app.config['ACL_ADMIN_GROUP'])

@bp_user.route("/")
@register_navbar('Users', icon='users', blueprint=bp_user, visible=user_acl_check)
def user_list():
	conn = get_conn()
	conn.search(current_app.config["LDAP_BASE_USER"], '(objectclass=person)')
	users = []
	for i in conn.entries:
		users.append(User.from_ldap(i))
	return render_template('user_list.html', users=users)

@bp_user.route("/<int:uid>")
@bp_user.route("/new")
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

@bp_user.route("/<int:uid>/update", methods=['POST'])
@bp_user.route("/new", methods=['POST'])
@csrf_protect(blueprint=bp_user)
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

@bp_user.route("/<int:uid>/del")
@csrf_protect(blueprint=bp_user)
def user_delete(uid):
	conn = get_conn()
	conn.search(current_app.config["LDAP_BASE_USER"], '(&(objectclass=person)(uidNumber={}))'.format((escape_filter_chars(uid))))
	assert len(conn.entries) == 1
	if conn.delete(conn.entries[0].entry_dn):
		flash('Deleted user')
	else:
		flash('Could not delete user: {}'.format(conn.result['message']))
	return redirect(url_for('.user_list'))

bp_group = Blueprint("group", __name__, template_folder='templates', url_prefix='/group/')
@bp_group.before_request
@login_required()
def group_acl():
	if not user_acl_check():
		flash('Access denied')
		return redirect(url_for('index'))

@bp_group.route("/")
@register_navbar('Groups', icon='layer-group', blueprint=bp_group, visible=user_acl_check)
def group_list():
	conn = get_conn()
	conn.search(current_app.config["LDAP_BASE_GROUPS"], '(objectclass=groupOfUniqueNames)')
	groups = []
	for i in conn.entries:
		groups.append(Group.from_ldap(i))
	return render_template('group_list.html', groups=groups)

@bp_group.route("/<int:gid>")
def group_show(gid):
	conn = get_conn()
	conn.search(current_app.config["LDAP_BASE_GROUPS"], '(&(objectclass=groupOfUniqueNames)(gidNumber={}))'.format((escape_filter_chars(gid))))
	assert len(conn.entries) == 1
	group = Group.from_ldap(conn.entries[0])
	return render_template('group.html', group=group)

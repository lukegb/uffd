from flask import Blueprint, render_template, request, url_for, redirect, flash, current_app

from uffd.navbar import register_navbar
from uffd.csrf import csrf_protect
from uffd.user.models import User, Group
from uffd.role.models import Role
from uffd.session import get_current_user, login_required, is_valid_session
from uffd.ldap import loginname_to_dn
from uffd.database import db

bp = Blueprint("role", __name__, template_folder='templates', url_prefix='/role/')
@bp.before_request
@login_required()
def role_acl(): #pylint: disable=inconsistent-return-statements
	if not role_acl_check():
		flash('Access denied')
		return redirect(url_for('index'))

def role_acl_check():
	return is_valid_session() and get_current_user().is_in_group(current_app.config['ACL_ADMIN_GROUP'])

@bp.route("/")
@register_navbar('Roles', icon='key', blueprint=bp, visible=role_acl_check)
def index():
	return render_template('role_list.html', roles=Role.query.all())

@bp.route("/<int:roleid>")
@bp.route("/new")
def show(roleid=False):
	if not roleid:
		role = Role()
	else:
		role = Role.query.get_or_404(roleid)
	return render_template('role.html', role=role)

@bp.route("/<int:roleid>/update", methods=['POST'])
@bp.route("/new", methods=['POST'])
@csrf_protect(blueprint=bp)
def update(roleid=False):
	is_newrole = bool(not roleid)
	session = db.session
	if is_newrole:
		role = Role()
		session.add(role)
	else:
		role = session.query(Role).get_or_404(roleid)
	role.name = request.values['name']
	role.description = request.values['description']
	print(role)
	session.commit()
	return redirect(url_for('role.index'))

@bp.route("/<int:roleid>/del")
@csrf_protect(blueprint=bp)
def delete(roleid):
	session = db.session
	role = session.query(Role).get_or_404(roleid)
	session.delete(role)
	session.commit()
	return redirect(url_for('role.index'))

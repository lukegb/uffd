from flask import Blueprint, render_template, request, url_for, redirect, flash

from uffd.navbar import register_navbar
from uffd.csrf import csrf_protect
from uffd.role.models import Role
from uffd.user.models import User
from uffd.session import get_current_user, login_required, is_valid_session
from uffd.database import db
from uffd.ldap import ldap

bp = Blueprint('rolemod', __name__, template_folder='templates', url_prefix='/rolemod/')

def user_is_rolemod():
	return is_valid_session() and Role.query.filter(Role.moderator_group_dn.in_(get_current_user().group_dns)).count()

@bp.before_request
@login_required()
def acl_check(): #pylint: disable=inconsistent-return-statements
	if not user_is_rolemod():
		flash('Access denied')
		return redirect(url_for('index'))

@bp.route("/")
@register_navbar('Moderation', icon='user-lock', blueprint=bp, visible=user_is_rolemod)
def index():
	roles = Role.query.filter(Role.moderator_group_dn.in_(get_current_user().group_dns)).all()
	return render_template('rolemod/list.html', roles=roles)

@bp.route("/<int:role_id>")
def show(role_id):
	# prefetch all users so the ldap orm can cache them and doesn't run one ldap query per user
	User.query.all()
	role = Role.query.get_or_404(role_id)
	if role.moderator_group not in get_current_user().groups:
		flash('Access denied')
		return redirect(url_for('index'))
	return render_template('rolemod/show.html', role=role)

@bp.route("/<int:role_id>", methods=['POST'])
@csrf_protect(blueprint=bp)
def update(role_id):
	role = Role.query.get_or_404(role_id)
	if role.moderator_group not in get_current_user().groups:
		flash('Access denied')
		return redirect(url_for('index'))
	if request.form['description'] != role.description:
		if len(request.form['description']) > 256:
			flash('Description too long')
			return redirect(url_for('.show', role_id=role.id))
		role.description = request.form['description']
	db.session.commit()
	return redirect(url_for('.show', role_id=role.id))

@bp.route("/<int:role_id>/delete_member/<member_dn>")
@csrf_protect(blueprint=bp)
def delete_member(role_id, member_dn):
	role = Role.query.get_or_404(role_id)
	if role.moderator_group not in get_current_user().groups:
		flash('Access denied')
		return redirect(url_for('index'))
	member = User.query.get_or_404(member_dn)
	role.members.discard(member)
	member.update_groups()
	ldap.session.commit()
	db.session.commit()
	flash('Member removed')
	return redirect(url_for('.show', role_id=role.id))

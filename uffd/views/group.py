from flask import Blueprint, render_template, current_app, request, flash, redirect, url_for
from flask_babel import lazy_gettext, gettext as _
import sqlalchemy

from uffd.navbar import register_navbar
from uffd.csrf import csrf_protect
from uffd.database import db
from uffd.models import Group
from .session import login_required

bp = Blueprint("group", __name__, template_folder='templates', url_prefix='/group/')

def group_acl_check():
	return request.user and request.user.is_in_group(current_app.config['ACL_ADMIN_GROUP'])

@bp.before_request
@login_required(group_acl_check)
def group_acl():
	pass

@bp.route("/")
@register_navbar(lazy_gettext('Groups'), icon='layer-group', blueprint=bp, visible=group_acl_check)
def index():
	return render_template('group/list.html', groups=Group.query.all())

@bp.route("/<int:id>")
@bp.route("/new")
def show(id=None):
	group = Group() if id is None else Group.query.get_or_404(id)
	return render_template('group/show.html', group=group)

@bp.route("/<int:id>/update", methods=['POST'])
@bp.route("/new", methods=['POST'])
@csrf_protect(blueprint=bp)
def update(id=None):
	if id is None:
		group = Group()
		if request.form['unix_gid']:
			try:
				group.unix_gid = int(request.form['unix_gid'])
			except ValueError:
				flash(_('GID is already in use or was used in the past'))
				return render_template('group/show.html', group=group), 400
		if not group.set_name(request.form['name']):
			flash(_('Invalid name'))
			return render_template('group/show.html', group=group), 400
	else:
		group = Group.query.get_or_404(id)
	group.description = request.form['description']
	db.session.add(group)
	if id is None:
		try:
			db.session.commit()
		except sqlalchemy.exc.IntegrityError:
			db.session.rollback()
			flash(_('Group with this name or id already exists'))
			return render_template('group/show.html', group=group), 400
	else:
		db.session.commit()
	if id is None:
		flash(_('Group created'))
	else:
		flash(_('Group updated'))
	return redirect(url_for('group.show', id=group.id))

@bp.route("/<int:id>/delete")
@csrf_protect(blueprint=bp)
def delete(id):
	group = Group.query.get_or_404(id)
	db.session.delete(group)
	db.session.commit()
	flash(_('Deleted group'))
	return redirect(url_for('group.index'))

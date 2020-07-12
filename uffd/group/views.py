from flask import Blueprint, current_app, render_template

from uffd.navbar import register_navbar
from uffd.ldap import get_conn, escape_filter_chars

from .models import Group

bp = Blueprint("group", __name__, template_folder='templates', url_prefix='/group/')

@bp.route("/")
@register_navbar('Groups', icon='layer-group', blueprint=bp)
def group_list():
	conn = get_conn()
	conn.search(current_app.config["LDAP_BASE_GROUPS"], '(objectclass=groupOfUniqueNames)')
	groups = []
	for i in conn.entries:
		groups.append(Group.from_ldap(i))
	return render_template('group_list.html', groups=groups)

@bp.route("/<int:gid>")
def group_show(gid):
	conn = get_conn()
	conn.search(current_app.config["LDAP_BASE_GROUPS"], '(&(objectclass=groupOfUniqueNames)(gidNumber={}))'.format((escape_filter_chars(gid))))
	assert len(conn.entries) == 1
	group = Group.from_ldap(conn.entries[0])
	return render_template('group.html', group=group)

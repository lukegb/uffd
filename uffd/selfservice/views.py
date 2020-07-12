from flask import Blueprint, render_template, request, url_for, redirect, flash, current_app

from uffd.navbar import register_navbar
from uffd.csrf import csrf_protect

from uffd.user.models import User
from uffd.group.models import Group
from uffd.session import get_current_user, login_required
from uffd.ldap import get_conn, escape_filter_chars

bp = Blueprint("selfservice", __name__, template_folder='templates', url_prefix='/self/')

@bp.before_request
@login_required
def self_acl():
	pass

@bp.route("/")
@register_navbar('Selfservice', icon='portrait', blueprint=bp)
def self_index():
	return render_template('self.html', user=get_current_user())

@bp.route("/update", methods=(['POST']))
@csrf_protect
def self_update():
	pass


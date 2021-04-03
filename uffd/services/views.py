from flask import Blueprint, render_template, current_app, abort

from uffd.navbar import register_navbar
from uffd.session import is_valid_session, get_current_user

bp = Blueprint("services", __name__, template_folder='templates', url_prefix='/services')

# pylint: disable=too-many-branches
def get_services(user=None):
	if not user and not current_app.config['SERVICES_PUBLIC']:
		return []
	services = []
	for service_data in current_app.config['SERVICES']:
		if not service_data.get('title'):
			continue
		service = {
			'title': service_data['title'],
			'subtitle': service_data.get('subtitle', ''),
			'description': service_data.get('description', ''),
			'url': service_data.get('url', ''),
			'logo_url': service_data.get('logo_url', ''),
			'has_access': True,
			'permission': '',
			'groups': [],
			'infos': [],
			'links': [],
		}
		if service_data.get('required_group'):
			if not user or not user.has_permission(service_data['required_group']):
				service['has_access'] = False
		for permission_data in service_data.get('permission_levels', []):
			if permission_data.get('required_group'):
				if not user or not user.has_permission(permission_data['required_group']):
					continue
			if not permission_data.get('name'):
				continue
			service['has_access'] = True
			service['permission'] = permission_data['name']
		if service_data.get('confidential', False) and not service['has_access']:
			continue
		for group_data in service_data.get('groups', []):
			if group_data.get('required_group'):
				if not user or not user.has_permission(group_data['required_group']):
					continue
			if not group_data.get('name'):
				continue
			service['groups'].append(group_data)
		for info_data in service_data.get('infos', []):
			if info_data.get('required_group'):
				if not user or not user.has_permission(info_data['required_group']):
					continue
			if not info_data.get('title') or not info_data.get('html'):
				continue
			info = {
				'title': info_data['title'],
				'button_text': info_data.get('button_text', info_data['title']),
				'html': info_data['html'],
				'id': '%d-%d'%(len(services), len(service['infos'])),
			}
			service['infos'].append(info)
		for link_data in service_data.get('links', []):
			if link_data.get('required_group'):
				if not user or not user.has_permission(link_data['required_group']):
					continue
			if not link_data.get('url') or not link_data.get('title'):
				continue
			service['links'].append(link_data)
		services.append(service)
	return services

def services_visible():
	user = None
	if is_valid_session():
		user = get_current_user()
	return len(get_services(user)) > 0

@bp.route("/")
@register_navbar('Services', icon='sitemap', blueprint=bp, visible=services_visible)
def index():
	user = None
	if is_valid_session():
		user = get_current_user()
	services = get_services(user)
	if not current_app.config['SERVICES']:
		abort(404)

	banner = current_app.config.get('SERVICES_BANNER')

	# Set the banner to None if it is not public and no user is logged in
	if not (current_app.config["SERVICES_BANNER_PUBLIC"] or user):
		banner = None

	return render_template('overview.html', user=user, services=services, banner=banner)

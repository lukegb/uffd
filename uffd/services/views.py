from flask import Blueprint, render_template, current_app, abort, request
from flask_babel import lazy_gettext, get_locale

from uffd.navbar import register_navbar

bp = Blueprint("services", __name__, template_folder='templates', url_prefix='/services')

# pylint: disable=too-many-branches
def get_services(user=None):
	if not user and not current_app.config['SERVICES_PUBLIC']:
		return []
	services = []
	for service_data in current_app.config['SERVICES']:
		service_title = get_language_specific(service_data, 'title')
		if not service_title:
			continue
		service_description = get_language_specific(service_data, 'description')
		service = {
			'title': service_title,
			'subtitle': service_data.get('subtitle', ''),
			'description': service_description,
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
			info_title = get_language_specific(info_data, 'title')
			info_html = get_language_specific(info_data, 'html')
			if not info_title or not info_html:
				continue
			info_button_text = get_language_specific(info_data, 'button_text', info_title)
			info = {
				'title': info_title,
				'button_text': info_button_text,
				'html': info_html,
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

def get_language_specific(data, field_name, default =''):
	return data.get(field_name + '_' + get_locale().language, data.get(field_name, default))

def services_visible():
	return len(get_services(request.user)) > 0

@bp.route("/")
@register_navbar(9, lazy_gettext('Services'), icon='sitemap', blueprint=bp, visible=services_visible)
def index():
	services = get_services(request.user)
	if not current_app.config['SERVICES']:
		abort(404)

	banner = current_app.config.get('SERVICES_BANNER')

	# Set the banner to None if it is not public and no user is logged in
	if not (current_app.config["SERVICES_BANNER_PUBLIC"] or request.user):
		banner = None

	return render_template('services/overview.html', user=request.user, services=services, banner=banner)

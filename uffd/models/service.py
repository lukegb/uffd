from flask import current_app
from flask_babel import get_locale
from sqlalchemy import Column, Integer, String, ForeignKey, Boolean
from sqlalchemy.orm import relationship

from uffd.database import db

class Service(db.Model):
	__tablename__ = 'service'
	id = Column(Integer, primary_key=True, autoincrement=True)
	name = Column(String(255), unique=True, nullable=False)

	# If limit_access is False, all users have access and access_group is
	# ignored. This attribute exists for legacy API and OAuth2 clients that
	# were migrated from config definitions where a missing "required_group"
	# parameter meant no access restrictions. Representing this state by
	# setting access_group_id to NULL would lead to a bad/unintuitive ondelete
	# behaviour.
	limit_access = Column(Boolean(), default=True, nullable=False)
	access_group_id = Column(Integer(), ForeignKey('group.id', onupdate='CASCADE', ondelete='SET NULL'), nullable=True)
	access_group = relationship('Group')

	oauth2_clients = relationship('OAuth2Client', back_populates='service', cascade='all, delete-orphan')
	api_clients = relationship('APIClient', back_populates='service', cascade='all, delete-orphan')

	use_remailer = Column(Boolean(), default=False, nullable=False)

	def has_access(self, user):
		return not self.limit_access or self.access_group in user.groups

# The user-visible services show on the service overview page are read from
# the SERVICES config key. It is planned to gradually extend the Service model
# in order to finally replace the config-defined services.

def get_language_specific(data, field_name, default =''):
	return data.get(field_name + '_' + get_locale().language, data.get(field_name, default))

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

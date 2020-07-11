# pylint: disable=invalid-name
navbarList = []
# pylint: enable=invalid-name

def setup_navbar(app):
	app.jinja_env.globals['navbar'] = navbarList

# iconlib can be 'bootstrap'
# ( see: http://getbootstrap.com/components/#glyphicons )
# or 'fa'
# ( see: http://fontawesome.io/icons/ )
def register_navbar(name, iconlib='fa', icon=None, group=None, endpoint=None, blueprint=None):
	def wrapper(func):
		urlendpoint = endpoint
		if not endpoint:
			# pylint: disable=protected-access
			if blueprint:
				urlendpoint = "{}.{}".format(blueprint.name, func.__name__)
			else:
				urlendpoint = func.__name_
			# pylint: enable=protected-access
		item = {}
		item['iconlib'] = iconlib
		item['icon'] = icon
		item['group'] = group
		item['endpoint'] = urlendpoint
		item['name'] = name
		item['blueprint'] = blueprint
		navbarList.append(item)
		return func
	return wrapper

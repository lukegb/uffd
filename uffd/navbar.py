# pylint: disable=invalid-name
navbarList = []
# pylint: enable=invalid-name

def setup_navbar(app):
	app.jinja_env.globals['getnavbar'] = lambda: [n for n in navbarList if n['visible']()]

# iconlib can be 'bootstrap'
# ( see: http://getbootstrap.com/components/#glyphicons )
# or 'fa'
# ( see: http://fontawesome.io/icons/ )
# visible is a function that returns "True" if this icon should be visible in the calling context
def register_navbar(name, iconlib='fa', icon=None, group=None, endpoint=None, blueprint=None, visible=None):
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
		item['visible'] = visible or (lambda: True)
		navbarList.append(item)
		return func
	return wrapper

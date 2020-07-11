#!/usr/bin/env python3
from uffd import *

if __name__ == '__main__':
	app = create_app()
	init_db(app)
	print(app.url_map)
	app.run(threaded=True, debug=True)

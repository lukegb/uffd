#!/usr/bin/python3
from werkzeug.contrib.profiler import ProfilerMiddleware
from uffd import create_app
app = create_app()
app.wsgi_app = ProfilerMiddleware(app.wsgi_app, restrictions=[30])
app.run(debug=True)

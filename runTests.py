#!/usr/bin/env python3
import unittest
import os
from src import server

def setUp():
	server.app.testing = True

def tearDown():
	os.unlink(server.app.config['SQLITE_DB'])

if __name__ == '__main__':
	setUp()
	try:
		suite = unittest.defaultTestLoader.discover('./tests/', pattern="*")
		unittest.TextTestRunner(verbosity=2, failfast=True).run(suite)
	finally:
		tearDown()


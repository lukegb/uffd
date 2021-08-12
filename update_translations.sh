#!/bin/sh
set -e

pybabel extract -F uffd/babel.cfg -k lazy_gettext -o messages.pot uffd

# If you want to initialize a new message, use:
#   pybabel init -i messages.pot -d uffd/translations -l fr
# Complete Documentation of Flask-Babel: https://flask-babel.tkte.ch

pybabel update -i messages.pot -d uffd/translations
pybabel compile -d uffd/translations

if [ -n "$1" ]; then
	NUM_EMPTY="$(tr '\n' '|' < uffd/translations/$1/LC_MESSAGES/messages.po | sed 's/msgstr ""|/empty/g' | tr '|' '\n' | grep '^empty$' | wc -l)"
	NUM_TOTAL="$(grep '^msgid' uffd/translations/$1/LC_MESSAGES/messages.po | wc -l)"
	# Emulate python-coverage output
	echo "TOTAL $NUM_TOTAL $(( $NUM_TOTAL - $NUM_EMPTY )) $(( 100 * ($NUM_TOTAL - $NUM_EMPTY) / $NUM_TOTAL ))%"
fi

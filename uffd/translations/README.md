# How to add new translations

Extract all translatable string from `.py` and `.html` files to a `.pot`.
```bash
pybabel extract -F babel.cfg -k lazy_gettext -o messages.pot .
```
Update the `messages.po` file to include the new / updated strings.
```bash
pybabel update -i messages.pot -d translations
```
Compile the `messages.po` file to a `messages.mo` file.
```bash
pybabel compile -d translations
```
Bonus:  
Initialize a new language.
```bash
pybabel init -i messages.pot -d translations -l de
```

Complete Documentation of Flask-Babel: https://flask-babel.tkte.ch
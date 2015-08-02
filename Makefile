VENV_DIR?=.venv
VENV_ACTIVATE?=$(VENV_DIR)/bin/activate
WITH_VENV=. $(VENV_ACTIVATE);

$(VENV_ACTIVATE): requirements*.txt
	test -f $@ || virtualenv --python=python2.7 $(VENV_DIR)
	$(WITH_VENV) pip install --upgrade -r requirements.txt
	$(WITH_VENV) pip install --upgrade -r requirements-dev.txt
	$(WITH_VENV) pip install --upgrade -r requirements-packaging.txt

.PHONY: venv
venv: $(VENV_ACTIVATE)

.PHONY: test
test: venv
	$(WITH_VENV) TOXENV=py27 tox

.PHONY: authors
authors:
	git shortlog --numbered --summary --email | cut -f 2 > AUTHORS

readme.html: readme.rst
	$(WITH_VENV) rst2html.py README.rst > readme.html

# Ensure the sdist builds correctly
.PHONY: sdist
sdist: authors venv readme.html
	$(WITH_VENV) python setup.py sdist bdist_wheel

.PHONY: clean
clean:
	python setup.py clean
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg*
	find . -type f -name '*.pyc' -delete

.PHONY: teardown
teardown:
	rm -rf .tox $(VENV_DIR)/

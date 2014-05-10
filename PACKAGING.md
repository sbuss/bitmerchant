First ensure that all tests pass:

```python
nosetests
```

Make sure to update the version following semantic versioning guidelines.

Then git tag it

```sh
git tag -a va.b.c -m "Version a.b.c"
```

Ensure the README is valid RST:

```sh
rst2html.py README.rst > readme.html
```

Make sure all authors are accounted for in the AUTHORS file.

```
git shortlog --numbered --summary --email | cut -f 2 > AUTHORS
```

Then prepare the project for distribution.

```python
python setup.py sdist bdist_wheel upload
```

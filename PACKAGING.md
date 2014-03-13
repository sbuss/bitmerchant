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

Then prepare the project for distribution.

```python
python setup.py sdist bdist_wheel upload
```

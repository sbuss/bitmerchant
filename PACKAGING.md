First ensure that all tests pass:

```python
nosetests
```

Make sure to update the version following semantic versioning guidelines.

Then prepare the project for distribution.

```python
python setup.py sdist bdist_wheel
twine upload dist/*
```

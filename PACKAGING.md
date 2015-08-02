Create a release branch, eg `release-0.1.6`.

Ensure that all tests pass via travis-ci.

Ensure the README is valid RST:

```sh
make readme.html
```

Make sure all authors are accounted for in the AUTHORS file.

```
make authors
```

Update `bitmerchant/_version.py` following semantic versioning guidelines.

Ensure the sdist builds correctly

```
make sdist
```

Open a PR against master from the release branch. Once it merges, tag the
merge into master and push to github. Travis-ci will then publish the package
to pypi.

```sh
git checkout master
git pull master
git tag -a a.b.c -m "Version a.b.c"
git push --tags
```

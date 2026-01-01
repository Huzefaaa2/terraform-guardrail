# Release Process

## Version bump

Update `version` in `pyproject.toml`.

## Tag and push

```bash
git tag -a v0.2.0 -m "v0.2.0"
git push origin v0.2.0
```

## GitHub release

Create a GitHub release from the tag and paste notes from the changelog.

## Package publish

```bash
python -m pip install build twine
python -m build
python -m twine upload dist/*
```

Requires a `PYPI_API_TOKEN` configured for the repo.

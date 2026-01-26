# Release Process

## Version bump

Update `version` in [pyproject.toml](https://github.com/Huzefaaa2/terraform-guardrail/blob/main/pyproject.toml).

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

## CI Release Workflow

The release workflow publishes to PyPI and creates a GitHub release on tag push.

Setup:

- Add repository secret `PYPI_API_TOKEN` with your PyPI API token.
- Push a tag like `v0.2.1` to trigger the workflow.

The workflow reads [RELEASE_NOTES.md](https://github.com/Huzefaaa2/terraform-guardrail/blob/main/RELEASE_NOTES.md)
for release body content.

## Container Image

On tag pushes, a separate workflow builds and publishes a container image to GHCR:

- https://github.com/Huzefaaa2/terraform-guardrail/pkgs/container/terraform-guardrail

## Registry Service Image

The registry API has its own container workflow and publishes:

- https://github.com/Huzefaaa2/terraform-guardrail/pkgs/container/terraform-guardrail-registry

## Homebrew Tap

The `Homebrew Tap Publish` workflow updates the formula repository when these secrets are set:

- `HOMEBREW_TAP_REPO` (for example `Huzefaaa2/homebrew-tap`)
- `HOMEBREW_TAP_TOKEN`

## Chocolatey Publish

The `Chocolatey Publish` workflow pushes a package when `CHOCO_API_KEY` is configured.

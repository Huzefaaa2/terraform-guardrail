.PHONY: changelog release release-dry

changelog:
	git cliff -o CHANGELOG.md

release:
	@if [ -z "$(VERSION)" ]; then echo "Usage: make release VERSION=x.y.z"; exit 1; fi
	sed -i '' 's/version = "[0-9.]*"/version = "$(VERSION)"/' pyproject.toml
	git cliff -o CHANGELOG.md
	echo "# v$(VERSION)" > RELEASE_NOTES.md
	git cliff --unreleased --tag v$(VERSION) >> RELEASE_NOTES.md
	git add pyproject.toml CHANGELOG.md RELEASE_NOTES.md
	git commit -m "Prepare v$(VERSION)"
	git tag -a v$(VERSION) -m "v$(VERSION)"
	git push origin main
	git push origin v$(VERSION)

release-dry:
	@if [ -z "$(VERSION)" ]; then echo "Usage: make release-dry VERSION=x.y.z"; exit 1; fi
	@echo "Would set version to $(VERSION) and generate release notes."

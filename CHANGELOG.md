# Changelog

All notable changes to this project will be documented in this file.

## [1.0.1] - 2026-01-25

### Changed
- Publishing workflows now skip cleanly when secrets are missing.

## [1.0.0] - 2026-01-25

### Added
- Registry API container image workflow and Dockerfile.
- Homebrew tap and Chocolatey publish workflows.
- OPA caching support for the GitHub Action.

### Changed
- TerraGuard branding across UI/API surfaces.
- Installer documentation updated for one-liner installs.

## [0.2.11] - 2026-01-24

### Added
- Packaging workflow + release artifacts for Homebrew/Chocolatey/Linux installs.
- Signed bundle example with public key metadata.
- Packaging documentation.

### Changed
- GitHub Action auto-installs OPA when policy bundles are enabled.
- README and Wiki updated with governance narrative and installer options.

## [0.2.10] - 2026-01-24

### Added
- OPA policy evaluation for scans with bundle support and signature verification hooks.
- Policy registry API with bundle versions and audit history.
- GitHub Action for pre-apply / PR checks.
- Roadmap entries for Homebrew/Chocolatey/Linux installers.

### Changed
- Registry index format now supports versions + entrypoints.

## [0.2.9] - 2026-01-24

### Added
- OPA bundle support for the policy registry with CLI + API access.
- Registry bundle artifacts for baseline guardrails.

### Changed
- Policy registry documentation now covers OPA bundles.

## [0.2.8] - 2026-01-24

### Added
- Docker Compose stack for API, Streamlit UI, and policy registry.
- Optional analytics profile with Prometheus + Grafana.
- `/metrics` endpoint for Prometheus scraping.

### Changed
- Documentation updated for the compose stack and new diagrams.

## [0.2.7] - 2026-01-24

### Added
- Manual workflow dispatch support for CI and container workflows.

### Changed
- GHCR image tags now use lowercase owner.

## [0.2.6] - 2026-01-01

### Added
- GHCR container image publishing on release tags.
- `RELEASE.md` with a release summary table.

### Changed
- README now includes container pull/run instructions.

## [0.2.5] - 2026-01-01

### Added
- Architecture diagram links for PyPI readers.

### Changed
- README long description aligned for PyPI display.

## [0.2.4] - 2026-01-01

### Added
- Multi-file upload (1–10 files) in Streamlit.
- CSV export with `file_name` and `scanned_at` fields.
- Supported provider list in UI and wiki.
- Streamlit sidebar install snippet and PyPI link.

### Changed
- Findings table shows file metadata by default.

## [0.2.2] - 2026-01-01

### Added
- Streamlit live app link in README and wiki.
- PyPI-friendly diagram links for non-rendered Mermaid.

## [0.2.0] - 2026-01-01

### Added
- Streamlit app for instant scanning and reporting.
- Schema-aware validation (TG005) with Terraform CLI integration.
- Expanded snippet generator templates.
- Wiki documentation and diagrams.

### Changed
- Updated dependencies and version bump to 0.2.0.

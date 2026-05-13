# Changelog

All notable changes to this project will be documented in this file.

## [4.0.0] - 2026-05-13

### Added
- Context-aware enterprise evaluation with risk profiles, environment-aware severity overrides, and decision metadata.
- Suggested remediation guidance attached to findings and exposed through CLI, REST API, Web UI, and Streamlit Enterprise.
- Explainability reports with human-readable decision reasons, finding explanations, next actions, and CI-ready Markdown comment output.
- Enterprise SARIF and JUnit report generation for code scanning and CI test result surfaces.
- Policy waiver lifecycle for temporary exceptions with approval/revocation, expiry handling, audit records, and evaluation suppression.
- Web UI and Streamlit Enterprise waiver visibility, applied waiver summaries, and policy intelligence panels.

### Changed
- Roadmap, README, wiki home page, release notes, and package/API versions updated for v4.0.0 Intelligent.
- Reference CI implementations now publish explainability comments plus SARIF and JUnit artifacts.

## [3.0.0] - 2026-05-11

### Added
- Built-in enterprise policy packs for PCI DSS, AWS Control Tower, Azure landing zone, and banking resiliency.
- Policy pack API endpoints and CLI install/list/show commands.
- Guardrails-as-a-Service endpoint `POST /service/evaluate` with request IDs, policy pack context, evidence links, and CI-friendly response contract.
- Cross-provider invariant rules TG021-TG023 for public exposure, storage encryption, and ownership metadata across AWS, Azure, and GCP.
- v3 reference implementations for GitHub Actions, GitLab CI, Azure DevOps, and AWS CodePipeline/CodeBuild.
- Contributor governance package with contribution guide, code of conduct, security policy, issue templates, PR template, and public roadmap metadata.

### Changed
- Roadmap, README, wiki home page, release notes, and package version updated for v3.0.0 Ecosystem.

## [2.0.0] - 2026-05-07

### Added
- Enterprise JSON store for policy lifecycle, baselines, group/repo bindings, evaluations, drift checks, evidence exports, and audit events.
- Enterprise REST API endpoints for policy authoring, approvals, baseline lifecycle, group enforcement resolution, evaluation results, drift gates, and export retrieval.
- Enterprise CLI commands for policy, baseline, binding, evaluation, drift, evidence export, and AWS CodePipeline/CodeBuild scaffolding.
- Web UI support for multi-file/folder uploads, policy authoring, default rule catalog details, policy preview, baseline management, group enforcement preview, and how-to guides.
- Rich finding metadata and remediation fields for enterprise reports.
- AWS CodePipeline example docs, buildspec scaffold, and evidence artifact examples.

### Changed
- Roadmap, README, wiki home page, release notes, and package version updated for v2.0.0 Enterprise.

## [1.0.5] - 2026-01-27

### Changed
- Version bump after local package verification.
- Documented local package verification steps.

## [1.0.4] - 2026-01-25

### Added
- Windows PyPI installation guidance.

### Changed
- Packaging metadata aligned with release guidance.

## [1.0.3] - 2026-01-25

### Added
- Windows installation dependency on Python 3.11+.

### Changed
- Windows installation guidance now ensures Python is available.

## [1.0.2] - 2026-01-25

### Added
- CLI `--version` flag.
- Web UI favicon.

### Changed
- Package data now includes PNG assets.

## [1.0.1] - 2026-01-25

### Changed
- Publishing workflows now skip cleanly when secrets are missing.

## [1.0.0] - 2026-01-25

### Added
- Registry API container image workflow and Dockerfile.
- Homebrew tap publishing workflow.
- OPA caching support for the GitHub Action.

### Changed
- TerraGuard branding across UI/API surfaces.
- Installer documentation updated for one-liner installs.

## [0.2.11] - 2026-01-24

### Added
- Packaging workflow + release artifacts for Homebrew, PyPI, and Linux installs.
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
- Roadmap entries for Homebrew, PyPI, and Linux installers.

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

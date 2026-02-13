# Deliverables Reference

This page explains each roadmap deliverable and points to the most relevant documentation.

<a name="dockerized-mcp-rest-api"></a>
## Dockerized Multi-Cloud Policy (MCP) + REST API

Container images for the Multi-Cloud Policy (MCP) server and REST API for consistent CI/CD usage.
See [Architecture](Architecture.md) and [Docker Compose](Docker-Compose.md).

<a name="cli-first-install"></a>
## CLI-first install

Package-first installs for local validation across platforms. See [Packaging](Packaging.md).

<a name="docker-compose-stack"></a>
## Docker Compose local stack (API + UI + registry)

Local stack for API, UI, and policy registry. See [Docker Compose](Docker-Compose.md).

<a name="github-action"></a>
## GitHub Action pre-apply / PR checks

Composite action for PR validation. See [GitHub Action](GitHub-Action.md).

<a name="gitlab-ci-templates"></a>
## GitLab CI templates

Shared template for GitLab pipelines. See [GitLab CI Templates](GitLab-CI.md).

<a name="azure-devops-extension"></a>
## Azure DevOps / Pipeline extension

Planned Azure DevOps extension for pre-apply checks in ADO pipelines.

## AWS CodePipeline + CodeBuild integration

Planned buildspec integration for policy gates in AWS CodePipeline. See
[AWS CodePipeline](AWS-CodePipeline.md).

<a name="policy-layering-model"></a>
## Policy layering model (base → env → app)

Layered policies for platform invariants (base), environment constraints, and app policies. See
[Policy Layering](Policy-Layering.md).

<a name="central-guardrail-registry"></a>
## Central guardrail registry

Registry service for policy bundles and audit history. See [Docker Compose](Docker-Compose.md).

<a name="policy-versioning-audit"></a>
## Policy versioning + audit trail

Versioned bundles with audit endpoints. See [Docker Compose](Docker-Compose.md).

<a name="registry-service-image"></a>
## Registry service image (GHCR)

Registry container published alongside core image. See [Packaging](Packaging.md).

<a name="homebrew-package"></a>
## Homebrew package (macOS)

Homebrew formula for macOS installs. See [Packaging](Packaging.md).

<a name="chocolatey-package"></a>
## Chocolatey package (Windows)

Chocolatey package for Windows installs. See [Packaging](Packaging.md).

<a name="linux-install-script"></a>
## Linux install script (curl | bash)

Linux one-liner install script. See [Packaging](Packaging.md).

<a name="policy-metadata-rich-messages"></a>
## Policy metadata + rich failure messages

Planned metadata (owner, risk, expiry) and actionable failure guidance.

<a name="drift-prevention"></a>
## Drift-prevention rules before apply

Planned rules to block drift before Terraform mutates state.

<a name="contributor-governance"></a>
## Contributor governance + public roadmap

Planned governance updates. See [Release Process](Release-Process.md).

<a name="reference-implementations"></a>
## Reference implementations across tools

Planned reference integrations across CI/CD tools and clouds.

<a name="cross-provider-invariants"></a>
## Cross-provider invariant enforcement

Planned cross-provider guardrails for consistent controls.

<a name="context-aware-evaluation"></a>
## Context-aware evaluation

Planned evaluation based on environment and risk context.

<a name="suggested-fixes"></a>
## Suggested fixes + recommendations

Planned guidance to suggest fixes instead of blocking only.

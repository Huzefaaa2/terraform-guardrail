# GitHub Action (Pre-apply / PR checks)

Terraform Guardrail Multi-Cloud Policy (MCP) (TerraGuard) ships with a composite GitHub Action that runs scans on pull requests.

## Workflow example

```yaml
name: Guardrail

on:
  pull_request:
    paths:
      - "**/*.tf"
      - "**/*.tfvars"
      - "**/*.hcl"
      - "**/*.tfstate"

jobs:
  guardrail:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Start local policy registry
        run: |
          python -m http.server 8081 --directory ops/policy-registry &
      - uses: ./.github/actions/guardrail
        with:
          path: .
          fail_on: medium
          install_source: repo
          policy_bundle: baseline-signed
          policy_registry: http://localhost:8081
```

### Local bundle example (no registry)

```yaml
      - uses: ./.github/actions/guardrail
        with:
          path: .
          install_source: repo
          policy_bundle_path: ./policies/my-bundle.tar.gz
```

## Inputs

- `path`: path to scan (default `.`)
- `state`: optional path to `.tfstate`
- `schema`: enable schema validation (`true`/`false`)
- `fail_on`: fail threshold (`low`, `medium`, `high`)
- `policy_bundle`: bundle ID to evaluate
- `policy_bundle_path`: local bundle path (`.tar.gz` or directory)
- `policy_registry`: registry URL
- `policy_query`: override OPA query
- `opa_version`: OPA version (`latest` or `v0.63.0`)
- `install_source`: `pypi` (default) or `repo`
- `python_version`: Python version for runner

Policy bundle evaluation requires the `opa` CLI in the runner.

When `policy_bundle` is set, the action installs OPA automatically and caches the binary per runner OS/version.

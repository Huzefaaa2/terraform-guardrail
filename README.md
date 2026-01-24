# Terraform Guardrail MCP

[![CI](https://github.com/Huzefaaa2/terraform-guardrail/actions/workflows/ci.yml/badge.svg)](https://github.com/Huzefaaa2/terraform-guardrail/actions/workflows/ci.yml)

Terraform Guardrail MCP is a Python-based MCP server + CLI + web UI that turns Terraform governance
into a fast, repeatable workflow. It gives AI assistants and platform teams real context from
provider metadata and adds compliance intelligence so every plan, module, and refactor is safer by
default. The result is fewer failures, cleaner state, and a shorter path from idea to production.

This project is built for teams shipping infrastructure at scale who need speed without sacrificing
security. It eliminates secret leakage, validates schema usage, and produces human-readable reports
that make decisions obvious and auditable.
Live app: https://terraform-guardrail.streamlit.app/

## What it does

- MCP server that exposes provider metadata and compliance checks
- CLI for scanning Terraform configs and state for sensitive leaks
- Minimal web UI for quick scans and reports
- Rules engine focused on ephemeral values, write-only arguments, and secret hygiene

## Architecture

```mermaid
flowchart LR
    subgraph Interfaces
        CLI[CLI]
        MCP[MCP Server]
        WEB[Web UI]
    end

    subgraph Core
        SCAN[Compliance Engine]
        GEN[Snippet Generator]
    end

    REG[Terraform Registry]
    TF[Terraform CLI]

    CLI --> SCAN
    WEB --> SCAN
    MCP --> SCAN
    MCP --> GEN
    SCAN --> TF
    GEN --> REG
    MCP --> REG
```

```mermaid
flowchart TB
    INPUTS[Inputs: .tf, .tfvars, .tfstate] --> PARSE[Parse & Normalize]
    PARSE --> RULES[Apply Rules TG001-TG005]
    RULES --> REPORT[Findings + Summary Report]
    REPORT --> OUTPUT[CLI JSON / UI Render / MCP Response]
```

## Scope

- Multi-file scanning with summaries and CSV export
- Secret hygiene checks across `.tf`, `.tfvars`, and `.tfstate`
- Schema-aware validation with Terraform CLI integration
- Provider metadata lookup via Terraform Registry
- MCP tools for scan, metadata, and snippet generation
- Streamlit and web UI for instant reporting

## Supported Providers

- AWS
- Azure
- GCP
- Kubernetes
- Helm
- OCI
- Vault
- Alicloud
- vSphere

## Feature Matrix

| Area | CLI | Web UI / Streamlit |
| --- | --- | --- |
| Config scan (`.tf`, `.tfvars`, `.hcl`) | Yes | Yes |
| State leak scan (`.tfstate`) | Yes | Yes |
| Schema-aware validation | Yes | Yes |
| CSV export | No | Yes |
| Provider metadata | Yes | Yes |
| Snippet generation | Yes | No |
| Multi-file scan | Yes (directory) | Yes (upload up to 10) |
| Human-readable report | Yes | Yes |

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e "[dev]"

# CLI scan
terraform-guardrail scan examples

# snippet generation
terraform-guardrail generate aws aws_s3_bucket --name demo

# MCP server (stdio)
terraform-guardrail mcp

# Web UI
terraform-guardrail web
```

## Install from PyPI

```bash
pip install terraform-guardrail
```

PyPI: https://pypi.org/project/terraform-guardrail/ (latest: 0.2.5)

## CLI examples

```bash
# scan a directory
terraform-guardrail scan ./examples --format json

# scan state files too
terraform-guardrail scan ./examples --state ./examples/sample.tfstate

# enable schema-aware validation (requires terraform CLI + initialized workspace)
terraform-guardrail scan ./examples --schema
```

## Web UI

Visit `http://127.0.0.1:8000` and upload a Terraform file to view a compliance report.

## Streamlit App

```bash
streamlit run streamlit_app.py
```

Live app: https://terraform-guardrail.streamlit.app/

### Streamlit Cloud deployment

1. Push this repo to GitHub.
2. Create a new Streamlit Cloud app.
3. Set the main file path to `streamlit_app.py`.
4. Deploy (Streamlit will install from `requirements.txt`).

## REST API (Docker)

Build and run the API server:

```bash
docker build -t terraform-guardrail .
docker run --rm -p 8080:8080 terraform-guardrail
```

API endpoints:

- `GET /health`
- `POST /scan`
- `POST /provider-metadata`
- `POST /generate-snippet`

Example request:

```bash
curl -X POST http://localhost:8080/scan \\
  -H "Content-Type: application/json" \\
  -d '{"path":"./examples","use_schema":false}'
```

## Release Links

- PyPI: https://pypi.org/project/terraform-guardrail/
- GitHub Releases: https://github.com/Huzefaaa2/terraform-guardrail/releases

## Deployment Guide

See `docs/streamlit_cloud.md` for a detailed Streamlit Cloud walkthrough.


## Release Checklist

- Update version in `pyproject.toml`.
- Update `RELEASE_NOTES.md` and `CHANGELOG.md`.
- Commit changes and push to `main`.
- Create and push a tag: `git tag -a vX.Y.Z -m "vX.Y.Z"` then `git push origin vX.Y.Z`.
- Confirm GitHub Actions release workflow completed successfully.

## Changelog Automation

This repo uses `git-cliff` to generate `CHANGELOG.md`.

```bash
git cliff -o CHANGELOG.md
```

Or run:

```bash
make changelog
```

### Release Helpers

```bash
make release-dry VERSION=0.2.1
make version-bump VERSION=0.2.1
```

## MCP tools (current)

- `scan_terraform`: Run compliance checks over a path and optional state file.
- `get_provider_metadata`: Fetch provider metadata from Terraform Registry (AWS + Azure).
- `generate_snippet`: Generate Terraform snippets for common AWS/Azure resources.

## Roadmap

- Schema-aware code generation using provider schemas
- `fix` command to apply safe rewrites for ephemeral values
- Multi-environment policies and OPA-compatible output
- Stack-aware orchestration and drift detection

## License

MIT

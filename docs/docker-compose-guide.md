# Docker Compose Guide

Terraform Guardrail MCP ships with a Docker Compose stack that gives developers a full local
environment: the REST API, the Streamlit UI, and a lightweight policy registry. An optional
analytics profile adds Prometheus + Grafana so teams can observe scans and API activity.

## Why use the Compose stack

- **Single command setup** for API + UI + policy registry.
- **Consistent local environment** that mirrors CI/CD workflows.
- **Optional analytics** for observability without extra wiring.
- **Composable architecture** you can extend with policy packs and future services.

## Prerequisites

- Docker Desktop (or Docker Engine)
- Docker Compose v2 (`docker compose` command)

## Quick start

```bash
docker compose up --build
```

This brings up:

- **REST API** at `http://localhost:8080`
- **Streamlit UI** at `http://localhost:8501`
- **Policy registry (static)** at `http://localhost:8081`
- **Policy registry API** at `http://localhost:8090`

## Enable analytics (optional)

```bash
docker compose --profile analytics up --build
```

Additional services:

- **Prometheus** at `http://localhost:9090`
- **Grafana** at `http://localhost:3000` (admin / guardrail)

The API exposes `/metrics` for Prometheus scraping.

## Service roles

### guardrail-api

The core REST API that powers CI/CD and programmatic usage.

Key endpoints:

- `GET /health`
- `GET /metrics`
- `POST /scan`
- `POST /provider-metadata`
- `POST /generate-snippet`

### guardrail-ui

The Streamlit app for interactive scans, CSV export, and reporting. It connects to the same
scanner logic as the CLI and API.

### policy-registry

A static policy registry stub (served by Nginx) that demonstrates how OPA bundles can be hosted
and versioned. It exposes:

- `/registry.json` – pack index
- `/bundles/baseline.tar.gz` – sample OPA bundle
- `/packs/baseline/README.md` – legacy doc pack

This is the foundation for the future policy registry service.

### policy-registry-api

Minimal FastAPI service that exposes bundle metadata, versions, and audit history:

- `GET /bundles`
- `GET /bundles/{bundle_id}`
- `GET /bundles/{bundle_id}/versions`
- `GET /audit`
- `GET /bundles/{bundle_id}/audit`

### prometheus + grafana (analytics profile)

Prometheus scrapes `/metrics` from the API and Grafana visualizes trends such as request volume
and latency.

## Typical developer workflows

### Validate a Terraform directory

1. Start the stack.
2. Use the Streamlit UI to upload `.tf`, `.tfvars`, or `.tfstate` files.
3. Export CSV for audit or review.

### Integrate with CI

1. Run the API container in CI (or in a job service).
2. Post a scan request to `/scan` with the file path or mounted workspace.
3. Use the JSON response in your pipeline checks.

### Pull policy bundles locally

```bash
terraform-guardrail policy list
terraform-guardrail policy fetch baseline --destination ./policies
terraform-guardrail policy fetch baseline-signed --destination ./policies
```

## Configuration notes

- Change ports in `docker-compose.yml` if you have conflicts.
- The policy registry volume can be replaced with your own policy packs.
- Bundles use the OPA bundle format (tar.gz with `.manifest` and `policies/`).
- Use the analytics profile only when you need observability.

## Bundle signature verification

If a bundle entry includes a `verification` block (public key + scope), Guardrail will call the
`opa` CLI to verify signatures before evaluation. Add verification settings in `registry.json`
and ensure the OPA binary is installed on the host or in the CI runner.

Signed bundle example:

- Bundle ID: `baseline-signed`
- Public key served at: `http://localhost:8081/keys/guardrail.pub`

## Troubleshooting

- **Port already in use**: update the port mapping in `docker-compose.yml`.
- **Docker daemon not running**: start Docker Desktop or your engine.
- **Metrics empty**: hit the API endpoints once to generate request data.

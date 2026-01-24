# Docker Compose Stack

Terraform Guardrail MCP ships with a local Docker Compose stack that brings up the REST API, the
Streamlit UI, and a lightweight policy registry. Optional analytics (Prometheus + Grafana) can be
enabled via Compose profiles.

For a deeper guide, see the repository document:
https://github.com/Huzefaaa2/terraform-guardrail/blob/main/docs/docker-compose-guide.md

## Start the stack

```bash
docker compose up --build
```

## Enable analytics

```bash
docker compose --profile analytics up --build
```

## Service URLs

- API: http://localhost:8080
- Streamlit UI: http://localhost:8501
- Policy registry: http://localhost:8081
- Prometheus: http://localhost:9090 (analytics profile)
- Grafana: http://localhost:3000 (analytics profile, admin / guardrail)

## Notes

- The policy registry is a static stub used to demonstrate policy pack hosting.
- The registry now publishes OPA bundles under `/bundles/*.tar.gz`.
- The API exposes `/metrics` for Prometheus scraping.

## Bundle CLI

```bash
terraform-guardrail policy list
terraform-guardrail policy fetch baseline --destination ./policies
```

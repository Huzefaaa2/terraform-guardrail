# Docker Compose Stack

Terraform Guardrail MCP ships with a local Docker Compose stack that brings up the REST API, the
Streamlit UI, and a lightweight policy registry. Optional analytics (Prometheus + Grafana) can be
enabled via Compose profiles.

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
- The API exposes `/metrics` for Prometheus scraping.

# Streamlit Deployment

## Local

Run the v1 Foundation demo:

```bash
pip install -e .
streamlit run streamlit_app.py
```

Run the v2 Enterprise + Intelligence demo:

```bash
pip install -e .
streamlit run streamlit_app_v2.py
```

Run the v3-v5 Governance demo:

```bash
pip install -e .
streamlit run streamlit_app_v3_v5.py
```

## Live Apps

| App | Purpose | URL |
| --- | --- | --- |
| v1 Foundation | Terraform scanning, state leak checks, schema-aware validation | https://terraform-guardrail.streamlit.app/ |
| v2 Enterprise + Intelligence | Policy authoring, org baselines, drift gates, evidence export, risk profiles, suggested fixes, waiver demos | https://terraform-guardrail-enterprise.streamlit.app/ |
| v3-v5 Governance | Policy packs, explainability, SARIF/JUnit, remediation plans, PR dry runs, scheduled scans, evidence schedules, health and trend dashboards | https://terraform-guardrail-governance.streamlit.app/ |

All apps link to each other and to the author profile:
https://www.linkedin.com/in/huzefaaa

## Streamlit Cloud

1. Push the repo to GitHub.
2. Create one Streamlit Cloud app for v1.
3. Main file: [streamlit_app.py](https://github.com/Huzefaaa2/terraform-guardrail/blob/main/streamlit_app.py).
4. Create a second Streamlit Cloud app for v2.
5. Main file: [streamlit_app_v2.py](https://github.com/Huzefaaa2/terraform-guardrail/blob/main/streamlit_app_v2.py).
6. Create a third Streamlit Cloud app for v3-v5.
7. Main file: [streamlit_app_v3_v5.py](https://github.com/Huzefaaa2/terraform-guardrail/blob/main/streamlit_app_v3_v5.py).
8. Deploy (Streamlit installs dependencies from
   [requirements.txt](https://github.com/Huzefaaa2/terraform-guardrail/blob/main/requirements.txt)).

Recommended settings:

- Branch: `main`
- Python version: read from
  [runtime.txt](https://github.com/Huzefaaa2/terraform-guardrail/blob/main/runtime.txt)
- Theme: read from
  [.streamlit/config.toml](https://github.com/Huzefaaa2/terraform-guardrail/blob/main/.streamlit/config.toml)
- Secrets: none required for the public v1, v2, or v3-v5 demos
- v2 app URL/name: `terraform-guardrail-enterprise`
- v3-v5 app URL/name: `terraform-guardrail-governance`

## Container Deployment

Run the v1 Foundation app:

```bash
docker build -f Dockerfile.streamlit -t terraform-guardrail-streamlit:v1 .
docker run --rm -p 8501:8501 terraform-guardrail-streamlit:v1
```

Run the v2 Enterprise + Intelligence app:

```bash
docker build -f Dockerfile.streamlit.v2 -t terraform-guardrail-streamlit:v2 .
docker run --rm -p 8502:8501 terraform-guardrail-streamlit:v2
```

Run the v3-v5 Governance app:

```bash
docker build -f Dockerfile.streamlit.v3_v5 -t terraform-guardrail-streamlit:v3-v5 .
docker run --rm -p 8503:8501 terraform-guardrail-streamlit:v3-v5
```

## Troubleshooting

- If a cloud app reports `ImportError` for `terraform_guardrail`, reboot the app so Streamlit
  Cloud reinstalls from `requirements.txt`. The apps also include a repo `src/` fallback for stale
  cloud builds.
- Use Python from `runtime.txt` and keep `requirements.txt` at the repo root.

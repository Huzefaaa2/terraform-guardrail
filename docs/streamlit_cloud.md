# Streamlit Cloud Deployment

## Prerequisites

- GitHub repo is public or connected to your Streamlit account.
- `streamlit_app.py` exists at repo root for the v1 Foundation demo.
- `streamlit_app_v2.py` exists at repo root for the v2 Enterprise demo.
- `streamlit_app_v3_v5.py` exists at repo root for the v3-v5 Governance demo.
- `streamlit_app_full.py` exists at repo root for the v1-v5 Full platform demo.
- `requirements.txt` contains `-e .` (already included).
- `runtime.txt` pins Python 3.11 for predictable Streamlit Cloud builds.
- `.streamlit/config.toml` defines the shared app theme and disables usage telemetry.

## v1 Foundation app

1. Go to https://streamlit.io/cloud and sign in.
2. Click **New app**.
3. Select your GitHub repo: `Huzefaaa2/terraform-guardrail`.
4. Set **Main file path** to `streamlit_app.py`.
5. Choose **Deploy**.
6. Use the app URL: https://terraform-guardrail.streamlit.app/

## v2 Enterprise app

1. Go to https://streamlit.io/cloud and sign in.
2. Click **New app**.
3. Select your GitHub repo: `Huzefaaa2/terraform-guardrail`.
4. Set **Main file path** to `streamlit_app_v2.py`.
5. Set the app URL/name to `terraform-guardrail-enterprise` when Streamlit asks for a URL.
6. Choose **Deploy**.
7. Use the app URL: https://terraform-guardrail-enterprise.streamlit.app/

## v3-v5 Governance app

This is the recommended additional app instead of one app per v3, v4, and v5. These releases are
most useful as a connected workflow: install a policy pack, run intelligent evaluation, generate
remediation, create a PR dry run, schedule scans, and export evidence.

1. Go to https://streamlit.io/cloud and sign in.
2. Click **New app**.
3. Select your GitHub repo: `Huzefaaa2/terraform-guardrail`.
4. Set **Main file path** to `streamlit_app_v3_v5.py`.
5. Set the app URL/name to `terraform-guardrail-governance` when Streamlit asks for a URL.
6. Choose **Deploy**.
7. Use the app URL: https://terraform-guardrail-governance.streamlit.app/

## v1-v5 Full platform app

Use this app when you want one professional enterprise GUI that demonstrates every release:
foundation scanning, enterprise policy catalog, policy packs, contextual intelligence,
drift/evidence, remediation, schedules, and governance health.

1. Go to https://streamlit.io/cloud and sign in.
2. Click **New app**.
3. Select your GitHub repo: `Huzefaaa2/terraform-guardrail`.
4. Set **Main file path** to `streamlit_app_full.py`.
5. Set the app URL/name to `terraform-guardrail-platform` when Streamlit asks for a URL.
6. Choose **Deploy**.
7. Use the app URL: https://terraform-guardrail-platform.streamlit.app/

Recommended advanced settings:

- Branch: `main`
- Python version: read from `runtime.txt`
- Secrets: none required for the public demo
- App visibility: public, if you want the link to be readable from the README and wiki

## Cross-links

All apps include links to each other:

- v1 Foundation app links to the v2 Enterprise demo.
- v2 Enterprise app links back to the v1 Foundation demo and forward to v3-v5 Governance.
- v3-v5 Governance links back to v1 and v2.
- v1-v5 Full platform links to every focused app and to the case-study wiki.
- All apps link to the GitHub repo, wiki, and author LinkedIn page.

## Container deployment

Run the v1 Foundation app:

```bash
docker build -f Dockerfile.streamlit -t terraform-guardrail-streamlit:v1 .
docker run --rm -p 8501:8501 terraform-guardrail-streamlit:v1
```

Run the v2 Enterprise app:

```bash
docker build -f Dockerfile.streamlit.v2 -t terraform-guardrail-streamlit:v2 .
docker run --rm -p 8502:8501 terraform-guardrail-streamlit:v2
```

Run the v3-v5 Governance app:

```bash
docker build -f Dockerfile.streamlit.v3_v5 -t terraform-guardrail-streamlit:v3-v5 .
docker run --rm -p 8503:8501 terraform-guardrail-streamlit:v3-v5
```

Run the v1-v5 Full platform app:

```bash
docker build -f Dockerfile.streamlit.full -t terraform-guardrail-streamlit:full .
docker run --rm -p 8504:8501 terraform-guardrail-streamlit:full
```

## Troubleshooting

- If imports fail, ensure the repo has `requirements.txt` at the root and reboot the app so
  Streamlit Cloud reinstalls `-e .`. The apps also include a repo `src/` fallback for stale cloud
  builds.
- If schema checks fail, disable schema mode or ensure Terraform CLI is available.

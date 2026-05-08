# Streamlit Cloud Deployment

## Prerequisites

- GitHub repo is public or connected to your Streamlit account.
- `streamlit_app.py` exists at repo root for the v1 Foundation demo.
- `streamlit_app_v2.py` exists at repo root for the v2 Enterprise demo.
- `requirements.txt` contains `-e .` (already included).

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

## Cross-links

Both apps include links to each other:

- v1 Foundation app links to the v2 Enterprise demo.
- v2 Enterprise app links back to the v1 Foundation demo.
- Both apps link to the GitHub repo, wiki, and author LinkedIn page.

## Troubleshooting

- If imports fail, ensure the repo has `requirements.txt` at the root.
- If schema checks fail, disable schema mode or ensure Terraform CLI is available.

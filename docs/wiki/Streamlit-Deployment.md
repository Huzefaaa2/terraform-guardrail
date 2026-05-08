# Streamlit Deployment

## Local

Run the v1 Foundation demo:

```bash
pip install -e .
streamlit run streamlit_app.py
```

Run the v2 Enterprise demo:

```bash
pip install -e .
streamlit run streamlit_app_v2.py
```

## Live Apps

| App | Purpose | URL |
| --- | --- | --- |
| v1 Foundation | Terraform scanning, state leak checks, schema-aware validation | https://terraform-guardrail.streamlit.app/ |
| v2 Enterprise | Policy authoring, org baselines, drift gates, evidence export | https://terraform-guardrail-enterprise.streamlit.app/ |

Both apps link to each other and to the author profile:
https://www.linkedin.com/in/huzefaaa

## Streamlit Cloud

1. Push the repo to GitHub.
2. Create one Streamlit Cloud app for v1.
3. Main file: [streamlit_app.py](https://github.com/Huzefaaa2/terraform-guardrail/blob/main/streamlit_app.py).
4. Create a second Streamlit Cloud app for v2.
5. Main file: [streamlit_app_v2.py](https://github.com/Huzefaaa2/terraform-guardrail/blob/main/streamlit_app_v2.py).
6. Deploy (Streamlit installs dependencies from
   [requirements.txt](https://github.com/Huzefaaa2/terraform-guardrail/blob/main/requirements.txt)).

## Container Deployment

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

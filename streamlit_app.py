from __future__ import annotations

import csv
import tempfile
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

import streamlit as st

from terraform_guardrail.scanner.scan import scan_path

REPO_URL = "https://github.com/Huzefaaa2/terraform-guardrail"
WIKI_URL = "https://github.com/Huzefaaa2/terraform-guardrail/wiki"
LINKEDIN_URL = "https://www.linkedin.com/in/huzefaaa"

st.set_page_config(page_title="Terraform Guardrail MCP", page_icon="🛡️", layout="wide")

st.title("Terraform Guardrail MCP")
st.caption("MCP-backed Terraform assistant with ephemeral-values compliance.")

st.markdown("### What it checks")
col_a, col_b, col_c = st.columns(3)
with col_a:
    st.markdown("#### 🔐 Secret Hygiene")
    st.caption("Detects hardcoded secrets in configs and tfvars.")
with col_b:
    st.markdown("#### 🧾 State Leaks")
    st.caption("Flags sensitive values written to Terraform state.")
with col_c:
    st.markdown("#### ✅ Schema Validity")
    st.caption("Validates attributes against provider schemas.")

with st.sidebar:
    st.header("Resources")
    st.markdown(f"- [GitHub Repo]({REPO_URL})")
    st.markdown(f"- [Wiki Docs]({WIKI_URL})")
    st.markdown(f"- [Follow on LinkedIn]({LINKEDIN_URL})")
    st.divider()
    st.subheader("Install")
    st.code("pip install terraform-guardrail")
    st.markdown("PyPI: https://pypi.org/project/terraform-guardrail/")
    st.divider()
    st.subheader("How to use")
    st.markdown(
        "\n".join(
            [
                "1. Upload a Terraform config file (`.tf`, `.tfvars`, `.hcl`).",
                "2. (Optional) Upload a `.tfstate` file for state leak checks.",
                "3. Toggle schema-aware validation if Terraform CLI is available.",
                "4. Click **Scan** to generate a compliance report.",
            ]
        )
    )

st.markdown("### Supported providers")
st.caption(
    "AWS, Azure, GCP, Kubernetes, Helm, OCI, Vault, Alicloud, and vSphere."
)

col1, col2 = st.columns(2)
with col1:
    tf_files = st.file_uploader(
        "Terraform config (.tf/.tfvars/.hcl)",
        type=["tf", "tfvars", "hcl"],
        accept_multiple_files=True,
    )
with col2:
    state_file = st.file_uploader("Optional state file (.tfstate)", type=["tfstate"])

use_schema = st.checkbox("Enable schema-aware validation (requires terraform CLI)")

if st.button("Scan"):
    if not tf_files:
        st.error("Please upload at least one Terraform file.")
    elif len(tf_files) > 10:
        st.error("Please upload no more than 10 Terraform files.")
    else:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_dir_path = Path(tmp_dir)
            state_path = None
            if state_file:
                state_path = tmp_dir_path / state_file.name
                state_path.write_bytes(state_file.getvalue())

            all_findings = []
            summary = {"Total findings": 0, "High": 0, "Medium": 0, "Low": 0}
            scanned_paths = []
            scanned_at = datetime.now(timezone.utc).isoformat()

            for tf_file in tf_files:
                tf_path = tmp_dir_path / tf_file.name
                tf_path.write_bytes(tf_file.getvalue())
                try:
                    report = scan_path(tf_path, state_path=state_path, use_schema=use_schema)
                except Exception as exc:  # noqa: BLE001
                    st.error(f"Scan failed for {tf_file.name}: {exc}")
                    st.stop()
                scanned_paths.append(report.scanned_path)
                summary["Total findings"] += report.summary.findings
                summary["High"] += report.summary.high
                summary["Medium"] += report.summary.medium
                summary["Low"] += report.summary.low
                for finding in report.findings:
                    payload = finding.model_dump()
                    payload["file_name"] = tf_file.name
                    payload["scanned_at"] = scanned_at
                    all_findings.append(payload)

        st.subheader("Summary")
        st.write(
            {
                "Scanned files": scanned_paths,
                "Total findings": summary["Total findings"],
                "High": summary["High"],
                "Medium": summary["Medium"],
                "Low": summary["Low"],
            }
        )

        st.subheader("Findings")
        if all_findings:
            columns = [
                "file_name",
                "scanned_at",
                "rule_id",
                "severity",
                "message",
                "path",
                "detail",
            ]
            table = [{key: finding.get(key) for key in columns} for finding in all_findings]
            st.dataframe(table, use_container_width=True)
        else:
            st.success("No findings detected.")

        output = StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "file_name",
                "scanned_at",
                "rule_id",
                "severity",
                "message",
                "path",
                "detail",
            ],
        )
        writer.writeheader()
        for finding in all_findings:
            writer.writerow(finding)
        st.download_button(
            "Download findings CSV",
            data=output.getvalue(),
            file_name="terraform_guardrail_findings.csv",
            mime="text/csv",
        )

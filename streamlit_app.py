from __future__ import annotations

import csv
import sys
import tempfile
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import streamlit as st  # noqa: E402

from terraform_guardrail.scanner.scan import scan_path  # noqa: E402

REPO_URL = "https://github.com/Huzefaaa2/terraform-guardrail"
WIKI_URL = "https://github.com/Huzefaaa2/terraform-guardrail/wiki"
LINKEDIN_URL = "https://www.linkedin.com/in/huzefaaa"
LIVE_V1_URL = "https://terraform-guardrail.streamlit.app/"
LIVE_V2_URL = "https://terraform-guardrail-enterprise.streamlit.app/"
LIVE_GOVERNANCE_URL = "https://terraform-guardrail-governance.streamlit.app/"

st.set_page_config(page_title="Terraform Guardrail MCP (TerraGuard)", page_icon="🛡️", layout="wide")

st.title("Terraform Guardrail MCP (TerraGuard)")
st.caption("MCP-backed Terraform assistant with ephemeral-values compliance.")
st.info(
    "You are viewing the v1 Foundation demo. "
    "Open the v2 Enterprise demo for policy authoring, baselines, drift gates, "
    f"and evidence: {LIVE_V2_URL}. "
    f"Open the v3-v5 Governance demo for policy packs and autonomous governance: "
    f"{LIVE_GOVERNANCE_URL}"
)

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
    st.markdown("### Live app versions")
    st.markdown(f"- [v1 Foundation demo]({LIVE_V1_URL})")
    st.markdown(f"- [v2 Enterprise demo]({LIVE_V2_URL})")
    st.markdown(f"- [v3-v5 Governance demo]({LIVE_GOVERNANCE_URL})")
    st.divider()
    st.markdown(f"- [GitHub Repo]({REPO_URL})")
    st.markdown(f"- [Wiki Docs]({WIKI_URL})")
    st.markdown(f"- [Author: Huzefa Husain]({LINKEDIN_URL})")
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
            st.dataframe(table, width="stretch")
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

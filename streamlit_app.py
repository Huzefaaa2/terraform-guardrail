from __future__ import annotations

import tempfile
from pathlib import Path

import streamlit as st

from terraform_guardrail.scanner.scan import scan_path

st.set_page_config(page_title="Terraform Guardrail MCP", page_icon="🛡️", layout="wide")

st.title("Terraform Guardrail MCP")
st.caption("MCP-backed Terraform assistant with ephemeral-values compliance.")

col1, col2 = st.columns(2)
with col1:
    tf_file = st.file_uploader("Terraform config (.tf/.tfvars/.hcl)", type=["tf", "tfvars", "hcl"])
with col2:
    state_file = st.file_uploader("Optional state file (.tfstate)", type=["tfstate"])

use_schema = st.checkbox("Enable schema-aware validation (requires terraform CLI)")

if st.button("Scan"):
    if not tf_file:
        st.error("Please upload a Terraform file first.")
    else:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_dir_path = Path(tmp_dir)
            tf_path = tmp_dir_path / tf_file.name
            tf_path.write_bytes(tf_file.getvalue())
            state_path = None
            if state_file:
                state_path = tmp_dir_path / state_file.name
                state_path.write_bytes(state_file.getvalue())

            try:
                report = scan_path(tf_path, state_path=state_path, use_schema=use_schema)
            except Exception as exc:  # noqa: BLE001
                st.error(f"Scan failed: {exc}")
                st.stop()

        st.subheader("Summary")
        st.write(
            {
                "Scanned": report.scanned_path,
                "Total findings": report.summary.findings,
                "High": report.summary.high,
                "Medium": report.summary.medium,
                "Low": report.summary.low,
            }
        )

        st.subheader("Findings")
        if report.findings:
            table = [finding.model_dump() for finding in report.findings]
            st.dataframe(table, use_container_width=True)
        else:
            st.success("No findings detected.")

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import streamlit as st

from terraform_guardrail.enterprise import (
    Baseline,
    EnterprisePolicy,
    EnterpriseStore,
    PolicyMetadata,
    PolicyWaiver,
    check_drift,
    evaluate_enterprise,
    export_evidence,
)
from terraform_guardrail.scanner.rules import RULES

REPO_URL = "https://github.com/Huzefaaa2/terraform-guardrail"
WIKI_URL = "https://github.com/Huzefaaa2/terraform-guardrail/wiki"
RELEASE_URL = "https://github.com/Huzefaaa2/terraform-guardrail/releases/tag/v2.0.0"
LINKEDIN_URL = "https://www.linkedin.com/in/huzefaaa"
LIVE_V1_URL = "https://terraform-guardrail.streamlit.app/"
LIVE_V2_URL = "https://terraform-guardrail-enterprise.streamlit.app/"

SAMPLE_TERRAFORM = """resource "aws_s3_bucket" "logs" {
  bucket = "prod-logs"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  name = "web"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""

DRIFT_BASELINE = """resource "aws_s3_bucket" "logs" {
  bucket = "prod-logs"
}
"""

DRIFT_CHANGED = """resource "aws_s3_bucket" "logs" {
  bucket = "prod-logs"
  acl    = "public-read"
}
"""

st.set_page_config(
    page_title="TerraGuard Enterprise + Intelligence",
    page_icon="TG",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
      .stApp {
        background:
          linear-gradient(
            135deg,
            rgba(8, 16, 30, 0.98),
            rgba(19, 36, 45, 0.96) 48%,
            rgba(15, 47, 46, 0.98)
          );
        color: #f7fafc;
      }
      [data-testid="stSidebar"] {
        background: #0d1624;
      }
      .hero {
        border: 1px solid rgba(255,255,255,0.16);
        background: linear-gradient(135deg, rgba(255,255,255,0.10), rgba(255,255,255,0.04));
        border-radius: 8px;
        padding: 28px;
        margin-bottom: 20px;
      }
      .hero h1 {
        font-size: 44px;
        line-height: 1.05;
        margin: 0 0 12px 0;
        color: #ffffff;
      }
      .hero p {
        color: #d9e6ef;
        font-size: 17px;
        max-width: 960px;
      }
      .pill-row {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin-top: 18px;
      }
      .pill {
        border: 1px solid rgba(255,255,255,0.18);
        background: rgba(255,255,255,0.08);
        border-radius: 999px;
        padding: 7px 11px;
        color: #eaf6ff;
        font-size: 13px;
      }
      .metric-card {
        border: 1px solid rgba(255,255,255,0.15);
        border-radius: 8px;
        background: rgba(255,255,255,0.08);
        padding: 18px;
      }
      .metric-card span {
        color: #a9c2d1;
        font-size: 13px;
      }
      .metric-card strong {
        display: block;
        color: #ffffff;
        font-size: 30px;
        margin-top: 6px;
      }
      a {
        color: #76e4f7 !important;
      }
    </style>
    """,
    unsafe_allow_html=True,
)


def build_demo_store(root: Path) -> EnterpriseStore:
    store = EnterpriseStore(root)
    policies = [
        EnterprisePolicy(
            name="Public S3 access is blocked",
            rule_id="TG006",
            severity="block",
            metadata=PolicyMetadata(
                owner="platform-security",
                standard="SOC2",
                control_id="CC6.6",
                risk="high",
                remediation="Remove public ACLs and use private bucket policies.",
            ),
        ),
        EnterprisePolicy(
            name="S3 default encryption is required",
            rule_id="TG011",
            severity="block",
            metadata=PolicyMetadata(
                owner="cloud-platform",
                standard="ISO 27001",
                control_id="A.8.24",
                risk="medium",
                remediation="Enable S3 server-side encryption with KMS or AES256.",
            ),
        ),
        EnterprisePolicy(
            name="Mandatory platform tags",
            rule_id="TG016",
            severity="warn",
            metadata=PolicyMetadata(
                owner="finops",
                standard="Internal Cloud Standard",
                control_id="TAG-001",
                risk="low",
                remediation="Add owner, environment, and cost_center tags.",
            ),
        ),
    ]
    saved_ids = []
    for policy in policies:
        saved = store.save_policy(policy, actor="demo")
        store.approve_policy(saved.id, actor="platform-security")
        saved_ids.append(saved.id)
    store.save_baseline(
        Baseline(name="org-baseline", policy_ids=saved_ids, approved=True),
        actor="demo",
    )
    return store


def write_workspace(root: Path, content: str, uploaded_files: list[Any]) -> Path:
    workspace = root / "infra"
    workspace.mkdir(parents=True, exist_ok=True)
    if uploaded_files:
        for uploaded in uploaded_files:
            target = workspace / Path(uploaded.name).name
            target.write_bytes(uploaded.getvalue())
    else:
        (workspace / "main.tf").write_text(content, encoding="utf-8")
    return workspace


def decision_color(decision: str) -> str:
    return {"pass": "#30d158", "warn": "#ffd166", "block": "#ff6b6b"}.get(decision, "#ffffff")


def finding_rows(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    columns = [
        "rule_id",
        "severity",
        "message",
        "owner",
        "standard",
        "control_id",
        "risk",
        "remediation",
        "suggested_fix",
        "waiver_id",
        "waiver_expires_at",
    ]
    return [{key: finding.get(key) for key in columns} for finding in findings]


with st.sidebar:
    st.markdown("## TerraGuard Enterprise + Intelligence")
    st.markdown(
        "Enterprise governance demo for policy lifecycle, baselines, drift, evidence, "
        "risk profiles, and suggested fixes."
    )
    st.divider()
    st.markdown("### Live app versions")
    st.markdown(f"- [v1 Foundation demo]({LIVE_V1_URL})")
    st.markdown(f"- [v2 Enterprise demo]({LIVE_V2_URL})")
    st.divider()
    st.markdown("### Resources")
    st.markdown(f"- [GitHub Repository]({REPO_URL})")
    st.markdown(f"- [v2.0.0 Release]({RELEASE_URL})")
    st.markdown(f"- [Enterprise Wiki]({WIKI_URL}/Release-v2.0.0)")
    st.markdown(f"- [Author: Huzefa Husain]({LINKEDIN_URL})")
    st.divider()
    st.code("pip install terraform-guardrail")
    st.code("terraform-guardrail enterprise drift-gate ./infra --baseline org-baseline")

st.markdown(
    """
    <section class="hero">
      <h1>Terraform Guardrail v2 Enterprise</h1>
      <p>
        A live control-plane demo for authoring policies, enforcing org baselines,
        catching drift before apply, and exporting audit evidence from Terraform changes.
      </p>
      <div class="pill-row">
        <span class="pill">Policy authoring</span>
        <span class="pill">Org baselines</span>
        <span class="pill">Group enforcement</span>
        <span class="pill">Drift gate</span>
        <span class="pill">Evidence export</span>
        <span class="pill">AWS CodePipeline ready</span>
      </div>
    </section>
    """,
    unsafe_allow_html=True,
)

top_a, top_b, top_c, top_d = st.columns(4)
with top_a:
    st.markdown(
        '<div class="metric-card"><span>Release</span><strong>v2.0.0</strong></div>',
        unsafe_allow_html=True,
    )
with top_b:
    st.markdown(
        '<div class="metric-card"><span>Built-in rules</span>'
        '<strong>TG001-TG020</strong></div>',
        unsafe_allow_html=True,
    )
with top_c:
    st.markdown(
        '<div class="metric-card"><span>Evidence formats</span>'
        '<strong>JSON CSV PDF</strong></div>',
        unsafe_allow_html=True,
    )
with top_d:
    st.markdown(
        '<div class="metric-card"><span>Decision model</span>'
        '<strong>Pass Warn Block</strong></div>',
        unsafe_allow_html=True,
    )

tab_evaluate, tab_authoring, tab_drift, tab_pipeline = st.tabs(
    ["Enterprise Evaluation", "Policy Catalog", "Drift Gate", "CI Evidence"]
)

with tab_evaluate:
    st.subheader("Evaluate a Terraform workspace with enterprise intelligence")
    left, right = st.columns([1.1, 0.9])
    with left:
        terraform_text = st.text_area(
            "Terraform sample",
            value=SAMPLE_TERRAFORM,
            height=280,
            help="Use the sample or upload one or more Terraform files.",
        )
        uploaded_files = st.file_uploader(
            "Optional Terraform files",
            type=["tf", "tfvars", "hcl"],
            accept_multiple_files=True,
        )
    with right:
        st.markdown("#### Evaluation context")
        provider = st.selectbox("Provider", ["aws", "azure", "gcp", "kubernetes", "helm"])
        environment = st.selectbox("Environment", ["prod", "dev", "sandbox", "production"])
        risk_tier = st.selectbox("Risk tier", ["high", "medium", "low", "critical"])
        baseline = st.text_input("Baseline", value="org-baseline")
        group = st.text_input("Group", value="platform")
        repo = st.text_input("Repository", value="payments-infra")
        fail_on = st.selectbox("Fail on severity", ["high", "medium", "low"])
        waiver_rule = st.selectbox("Demo waiver", ["None", "TG006", "TG011", "TG016"])
        waiver_reason = st.text_input("Waiver reason", value="Approved migration window")

    if st.button("Run Enterprise Evaluation", type="primary"):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = build_demo_store(root / "enterprise-store")
            if waiver_rule != "None":
                waiver = store.save_waiver(
                    PolicyWaiver(
                        rule_id=waiver_rule,
                        reason=waiver_reason,
                        owner="platform-security",
                        expires_at="2099-01-01T00:00:00Z",
                        requested_by="streamlit-demo",
                    ),
                    actor="streamlit-demo",
                )
                store.approve_waiver(waiver.id, actor="streamlit-demo")
            workspace = write_workspace(root, terraform_text, uploaded_files or [])
            result = evaluate_enterprise(
                workspace,
                provider=provider,
                baseline=baseline,
                context={
                    "group": group,
                    "repo": repo,
                    "environment": environment,
                    "risk_tier": risk_tier,
                },
                fail_on=fail_on,
                store=store,
                actor="streamlit-demo",
            )
            findings = result.report.get("findings", [])
            decision = result.decision
            intelligence = result.service_metadata.get("intelligence", {})
            profile = intelligence.get("profile") or {}
            adjustments = intelligence.get("adjustments") or []
            recommendations = intelligence.get("recommendations") or []
            waivers = result.service_metadata.get("waivers", {}).get("applied", [])

            st.markdown(
                "### Decision: "
                f"<span style='color:{decision_color(decision)}'>{decision.upper()}</span>",
                unsafe_allow_html=True,
            )
            profile_cols = st.columns(4)
            profile_cols[0].metric("Risk profile", profile.get("name", "No match"))
            profile_cols[1].metric("Environment", environment)
            profile_cols[2].metric("Risk tier", risk_tier)
            profile_cols[3].metric("Severity adjustments", len(adjustments))
            if waivers:
                st.info(f"{len(waivers)} approved waiver(s) applied to this evaluation.")
            st.write(
                {
                    "evaluation_id": result.id,
                    "resolved_policy_ids": result.resolved_policy_ids,
                    "summary": result.report.get("summary", {}),
                }
            )
            if adjustments:
                st.markdown("#### Context adjustments")
                st.dataframe(adjustments, use_container_width=True, hide_index=True)
            if recommendations:
                st.markdown("#### Suggested fixes")
                st.dataframe(recommendations, use_container_width=True, hide_index=True)
            if waivers:
                st.markdown("#### Applied waivers")
                st.dataframe(waivers, use_container_width=True, hide_index=True)
            if findings:
                st.dataframe(finding_rows(findings), use_container_width=True)
            else:
                st.success("No enterprise findings were detected.")

            export_json = export_evidence(result.id, format="json", store=store)
            export_csv = export_evidence(result.id, format="csv", store=store)
            export_pdf = export_evidence(result.id, format="pdf", store=store)
            st.download_button(
                "Download JSON Evidence",
                data=Path(export_json.path).read_text(encoding="utf-8"),
                file_name="guardrail-evidence.json",
                mime="application/json",
            )
            st.download_button(
                "Download CSV Evidence",
                data=Path(export_csv.path).read_text(encoding="utf-8"),
                file_name="guardrail-evidence.csv",
                mime="text/csv",
            )
            st.download_button(
                "Download PDF Evidence",
                data=Path(export_pdf.path).read_bytes(),
                file_name="guardrail-evidence.pdf",
                mime="application/pdf",
            )

with tab_authoring:
    st.subheader("Policy catalog and enterprise metadata")
    st.caption(
        "v2 enriches native rule findings with owner, standard, control ID, risk, "
        "and remediation."
    )
    default_rules = [
        {"rule_id": rule_id, "name": name}
        for rule_id, name in sorted(RULES.items(), key=lambda item: item[0])
    ]
    st.markdown("#### Built-in default rules")
    st.dataframe(default_rules, use_container_width=True, hide_index=True)

    st.markdown("#### Enterprise policy example")
    st.json(
        {
            "name": "S3 default encryption is required",
            "rule_id": "TG011",
            "severity": "block",
            "status": "approved",
            "metadata": {
                "owner": "cloud-platform",
                "standard": "ISO 27001",
                "control_id": "A.8.24",
                "risk": "medium",
                "remediation": "Enable S3 server-side encryption with KMS or AES256.",
            },
        }
    )
    st.code(
        "\n".join(
            [
                'terraform-guardrail enterprise policy create \\',
                '  --name "S3 default encryption is required" \\',
                "  --rule-id TG011",
                "terraform-guardrail enterprise policy approve <policy-id> \\",
                "  --actor platform-security",
                "terraform-guardrail enterprise baseline create \\",
                "  --name org-baseline \\",
                "  --policy-id <policy-id> \\",
                "  --approved",
                "terraform-guardrail enterprise waiver create \\",
                "  --rule-id TG011 \\",
                '  --reason "Approved migration window" \\',
                "  --owner platform-security \\",
                "  --expires-at 2026-12-31T00:00:00Z",
            ]
        ),
        language="bash",
    )

with tab_drift:
    st.subheader("Drift gate before apply")
    st.caption(
        "The first run creates a snapshot. Later runs compare current findings to that snapshot."
    )
    col_base, col_changed = st.columns(2)
    with col_base:
        baseline_text = st.text_area(
            "Approved snapshot Terraform",
            value=DRIFT_BASELINE,
            height=220,
        )
    with col_changed:
        changed_text = st.text_area("Current Terraform change", value=DRIFT_CHANGED, height=220)

    if st.button("Simulate Drift Gate"):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = build_demo_store(root / "enterprise-store")
            infra = root / "main.tf"
            infra.write_text(baseline_text, encoding="utf-8")
            created = check_drift(infra, snapshot_id="prod", store=store)
            matched = check_drift(infra, snapshot_id="prod", store=store)
            infra.write_text(changed_text, encoding="utf-8")
            changed = check_drift(infra, snapshot_id="prod", store=store)
            st.write(
                {
                    "first_run": created.model_dump(mode="json"),
                    "second_run": matched.model_dump(mode="json"),
                    "current_change": changed.model_dump(mode="json"),
                }
            )
            if changed.drifted:
                st.error("Drift detected. CI should block before terraform apply.")
            else:
                st.success("No drift detected.")

with tab_pipeline:
    st.subheader("CI evidence and AWS CodePipeline")
    st.markdown(
        "Use the v2 drift gate as a CodeBuild stage before Terraform apply. "
        "The gate can emit JSON, CSV, or PDF evidence for audit workflows."
    )
    st.code(
        "\n".join(
            [
                "terraform-guardrail enterprise drift-gate . \\",
                "  --provider aws \\",
                "  --baseline org-baseline \\",
                "  --snapshot-id prod \\",
                "  --evidence-format json \\",
                "  --format json",
            ]
        ),
        language="bash",
    )
    st.markdown(
        f"Read the full guide: [{WIKI_URL}/AWS-CodePipeline]({WIKI_URL}/AWS-CodePipeline)"
    )
    st.markdown(
        f"Author: [Huzefa Husain]({LINKEDIN_URL})"
    )

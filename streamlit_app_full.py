from __future__ import annotations

# ruff: noqa: E402,I001

import csv
import json
import sys
import tempfile
from io import StringIO
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import streamlit as st  # noqa: E402

from terraform_guardrail.enterprise import (  # noqa: E402
    Baseline,
    EnterprisePolicy,
    EnterpriseStore,
    EvidenceSchedule,
    PolicyMetadata,
    PolicyWaiver,
    ScheduledScanTarget,
    check_drift,
    create_github_pull_request,
    create_remediation_patch_bundle,
    create_remediation_plan,
    evaluate_enterprise,
    explain_evaluation,
    export_evidence,
    get_rule_recommendation,
    governance_health_report,
    governance_trend_report,
    install_policy_pack,
    list_builtin_policy_packs,
    render_evaluation_junit,
    render_evaluation_sarif,
    render_explanation_markdown,
    render_remediation_markdown,
    run_automation_cycle,
    run_evidence_schedule,
    run_scheduled_scan,
)
from terraform_guardrail.scanner.rules import RULES, RULE_METADATA  # noqa: E402
from terraform_guardrail.scanner.scan import scan_path  # noqa: E402

REPO_URL = "https://github.com/Huzefaaa2/terraform-guardrail"
WIKI_URL = "https://github.com/Huzefaaa2/terraform-guardrail/wiki"
LINKEDIN_URL = "https://www.linkedin.com/in/huzefaaa"
LIVE_V1_URL = "https://terraform-guardrail.streamlit.app/"
LIVE_V2_URL = "https://terraform-guardrail-enterprise.streamlit.app/"
LIVE_GOVERNANCE_URL = "https://terraform-guardrail-governance.streamlit.app/"
LIVE_FULL_URL = "https://terraform-guardrail-platform.streamlit.app/"
HOW_TO_GUIDES_URL = f"{WIKI_URL}/How-To-Guides"
HOW_TO_APP_URL = f"{WIKI_URL}/How-To-Use-v1-v5-Enterprise-Streamlit-App"
CASE_STUDIES_URL = f"{WIKI_URL}/Enterprise-Case-Studies"

SAMPLE_TERRAFORM = """variable "db_password" {
  type      = string
  sensitive = true
}

resource "aws_s3_bucket" "logs" {
  bucket = "prod-logs"
  acl    = "public-read"
}

resource "aws_security_group" "admin" {
  name = "admin"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "orders" {
  identifier          = "orders-prod"
  publicly_accessible = true
}
"""

DRIFT_APPROVED = """resource "aws_s3_bucket" "logs" {
  bucket = "prod-logs"
}
"""

DRIFT_CURRENT = """resource "aws_s3_bucket" "logs" {
  bucket = "prod-logs"
  acl    = "public-read"
}
"""

st.set_page_config(
    page_title="TerraGuard Enterprise Platform",
    page_icon="TG",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
      .stApp {
        background: #eef3f8;
        color: #142033;
      }
      [data-testid="stSidebar"] {
        background: #0a1424;
        border-right: 1px solid #1e3554;
      }
      [data-testid="stSidebar"] * {
        color: #e8f0f8;
      }
      [data-testid="stSidebar"] a {
        color: #8fd7ff !important;
      }
      [data-testid="stHeader"] {
        background: rgba(238, 243, 248, 0.86);
      }
      h2, h3, h4, p, label, span {
        color: #142033;
      }
      div[data-baseweb="select"] > div,
      textarea,
      input {
        border-color: #9fb1c6 !important;
        background: #ffffff !important;
        color: #142033 !important;
      }
      div[data-testid="stTabs"] [data-baseweb="tab-list"] {
        background: #d9e4ef;
        border: 1px solid #b8c8da;
        border-radius: 8px;
        gap: 8px;
        padding: 8px;
        overflow-x: auto;
      }
      button[data-baseweb="tab"] {
        background: #ffffff;
        border: 1px solid #9fb1c6;
        border-radius: 8px;
        color: #1e3350;
        font-weight: 800;
        min-height: 48px;
        padding: 10px 16px;
        white-space: nowrap;
      }
      button[data-baseweb="tab"] p {
        color: inherit;
        font-size: 15px;
        font-weight: 800;
      }
      button[data-baseweb="tab"]:hover {
        background: #edf7ff;
        border-color: #2563eb;
        color: #12315a;
      }
      button[data-baseweb="tab"][aria-selected="true"] {
        background: #12315a;
        border-color: #12315a;
        box-shadow: 0 8px 18px rgba(18, 49, 90, 0.26);
        color: #ffffff;
      }
      button[data-baseweb="tab"][aria-selected="true"] p {
        color: #ffffff;
      }
      .stButton > button {
        background: #174a7c;
        border: 1px solid #0f355c;
        border-radius: 8px;
        color: #ffffff;
        font-weight: 750;
        min-height: 42px;
      }
      .stButton > button:hover {
        background: #0f6b6e;
        border-color: #0b5558;
        color: #ffffff;
      }
      .stButton > button[kind="primary"] {
        background: #0f766e;
        border-color: #0a5c56;
        color: #ffffff;
        box-shadow: 0 8px 18px rgba(15, 118, 110, 0.22);
      }
      .stButton > button[kind="primary"]:hover {
        background: #0b5f59;
        border-color: #084b46;
      }
      [data-testid="stDownloadButton"] button {
        background: #5b3a94;
        border: 1px solid #442776;
        border-radius: 8px;
        color: #ffffff;
        font-weight: 750;
        min-height: 42px;
      }
      [data-testid="stDownloadButton"] button:hover {
        background: #7c3aed;
        border-color: #5b21b6;
        color: #ffffff;
      }
      .platform-hero {
        background: linear-gradient(135deg, #ffffff 0%, #f7fbff 58%, #edf6f5 100%);
        border: 1px solid #b8c8da;
        border-radius: 8px;
        padding: 30px;
        margin-bottom: 18px;
        box-shadow: 0 14px 34px rgba(22, 33, 62, 0.12);
      }
      .platform-hero h1 {
        color: #111827;
        font-size: 42px;
        line-height: 1.08;
        margin: 0 0 12px 0;
      }
      .platform-hero p {
        color: #31445d;
        font-size: 17px;
        max-width: 980px;
      }
      .stage-row {
        display: grid;
        grid-template-columns: repeat(5, minmax(120px, 1fr));
        gap: 10px;
        margin-top: 18px;
      }
      .stage {
        background: #ffffff;
        border: 1px solid #aebfd2;
        border-radius: 8px;
        padding: 12px;
        box-shadow: 0 6px 16px rgba(22, 33, 62, 0.08);
      }
      .stage strong {
        display: block;
        color: #12315a;
      }
      .stage span {
        color: #334d66;
        font-size: 13px;
      }
      .metric-card {
        border: 1px solid #b8c8da;
        border-radius: 8px;
        background: #ffffff;
        padding: 17px;
        min-height: 112px;
        box-shadow: 0 8px 22px rgba(22, 33, 62, 0.08);
      }
      .metric-card span {
        color: #445a72;
        font-size: 13px;
      }
      .metric-card strong {
        display: block;
        color: #111827;
        font-size: 28px;
        margin-top: 7px;
      }
      .case-card {
        border: 1px solid #b8c8da;
        border-left: 5px solid #0f766e;
        background: #ffffff;
        border-radius: 8px;
        padding: 15px 18px;
        margin: 10px 0;
        box-shadow: 0 6px 16px rgba(22, 33, 62, 0.07);
      }
      a {
        color: #0f5f8f !important;
      }
    </style>
    """,
    unsafe_allow_html=True,
)


def pack_options() -> dict[str, str]:
    return {
        f"{pack.name} ({pack.id})": pack.id
        for pack in list_builtin_policy_packs()
    }


def write_workspace(root: Path, content: str, uploaded_files: list[Any]) -> Path:
    workspace = root / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    if uploaded_files:
        for uploaded in uploaded_files:
            (workspace / Path(uploaded.name).name).write_bytes(uploaded.getvalue())
    else:
        (workspace / "main.tf").write_text(content, encoding="utf-8")
    return workspace


def bootstrap_enterprise_store(root: Path) -> EnterpriseStore:
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
            name="Database public access is blocked",
            rule_id="TG015",
            severity="block",
            metadata=PolicyMetadata(
                owner="data-security",
                standard="PCI DSS",
                control_id="1.2.1",
                risk="high",
                remediation="Disable public database access and route through private subnets.",
            ),
        ),
        EnterprisePolicy(
            name="Mandatory tags are present",
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
    policy_ids = []
    for policy in policies:
        saved = store.save_policy(policy, actor="streamlit-full")
        store.approve_policy(saved.id, actor="platform-security")
        policy_ids.append(saved.id)
    store.save_baseline(
        Baseline(name="enterprise-baseline", policy_ids=policy_ids, approved=True),
        actor="streamlit-full",
    )
    return store


def rule_detail(rule_id: str) -> dict[str, Any]:
    metadata = RULE_METADATA.get(rule_id, {})
    try:
        recommendation = get_rule_recommendation(rule_id).model_dump(mode="json")
    except KeyError:
        recommendation = {}
    snippet = {
        "rule_id": rule_id,
        "name": RULES.get(rule_id, "Unknown rule"),
        "risk": metadata.get("risk", "unknown"),
        "severity": "block",
        "owner": "platform-security",
        "standard": "SOC2 / ISO / PCI",
        "remediation": metadata.get("remediation", "Review the finding."),
    }
    return {
        **snippet,
        "suggested_fix": recommendation.get("suggested_fix", snippet["remediation"]),
        "snippet": json.dumps(snippet, indent=2),
    }


def finding_rows(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    keys = [
        "rule_id",
        "severity",
        "message",
        "risk",
        "standard",
        "control_id",
        "remediation",
        "suggested_fix",
    ]
    return [{key: finding.get(key) for key in keys} for finding in findings]


def run_platform_demo(
    *,
    pack_id: str,
    provider: str,
    environment: str,
    risk_tier: str,
    fail_on: str,
    terraform_text: str,
    uploaded_files: list[Any],
    apply_waiver: bool,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        store = bootstrap_enterprise_store(root / "enterprise-store")
        install = install_policy_pack(pack_id, store=store, actor="streamlit-full")
        baseline_name = "enterprise-baseline"
        if apply_waiver:
            waiver = store.save_waiver(
                PolicyWaiver(
                    rule_id="TG006",
                    reason="Approved short migration window",
                    owner="platform-security",
                    expires_at="2099-01-01T00:00:00Z",
                    requested_by="streamlit-full",
                ),
                actor="streamlit-full",
            )
            store.approve_waiver(waiver.id, actor="platform-security")
        workspace = write_workspace(root, terraform_text, uploaded_files)

        result = evaluate_enterprise(
            workspace,
            provider=provider,
            baseline=baseline_name,
            context={
                "org": "acme",
                "group": "platform",
                "repo": "payments-infra",
                "app": "payments",
                "environment": environment,
                "risk_tier": risk_tier,
            },
            fail_on=fail_on,
            store=store,
            actor="streamlit-full",
        )
        explanation = explain_evaluation(result.id, store=store)
        plan = create_remediation_plan(result.id, store=store, actor="streamlit-full")
        bundle = create_remediation_patch_bundle(
            plan.id,
            store=store,
            actor="streamlit-full",
        )
        pull_request = create_github_pull_request(
            bundle.id,
            repository="Huzefaaa2/terraform-guardrail",
            store=store,
            actor="streamlit-full",
            dry_run=True,
        )
        target = store.save_scheduled_scan_target(
            ScheduledScanTarget(
                name="Payments production daily scan",
                path=str(workspace),
                cadence="daily",
                provider=provider,
                baseline=baseline_name,
                fail_on=fail_on,
                context={"environment": environment, "risk_tier": risk_tier},
            ),
            actor="streamlit-full",
        )
        schedule = store.save_evidence_schedule(
            EvidenceSchedule(
                name="Payments monthly evidence",
                cadence="monthly",
                format="json",
                result_id=result.id,
                app="payments",
                group="platform",
                repo="payments-infra",
            ),
            actor="streamlit-full",
        )
        scheduled_scan = run_scheduled_scan(target.id, store=store, actor="streamlit-full")
        scheduled_evidence = run_evidence_schedule(schedule.id, store=store, actor="streamlit-full")
        automation = run_automation_cycle(store=store, actor="streamlit-full", limit=3)
        json_export = export_evidence(result.id, format="json", store=store)
        csv_export = export_evidence(result.id, format="csv", store=store)
        return {
            "install": install.model_dump(mode="json"),
            "result": result.model_dump(mode="json"),
            "findings": result.report.get("findings", []),
            "explanation": explanation.model_dump(mode="json"),
            "explanation_markdown": render_explanation_markdown(explanation),
            "plan": plan.model_dump(mode="json"),
            "plan_markdown": render_remediation_markdown(plan),
            "bundle": bundle.model_dump(mode="json"),
            "pull_request": pull_request.model_dump(mode="json"),
            "scheduled_scan": scheduled_scan.model_dump(mode="json"),
            "scheduled_evidence": scheduled_evidence.model_dump(mode="json"),
            "automation": automation.model_dump(mode="json"),
            "health": governance_health_report(store=store).model_dump(mode="json"),
            "trend": governance_trend_report(store=store, days=14).model_dump(mode="json"),
            "sarif": json.dumps(render_evaluation_sarif(result), indent=2),
            "junit": render_evaluation_junit(result),
            "json_evidence": Path(json_export.path).read_text(encoding="utf-8"),
            "csv_evidence": Path(csv_export.path).read_text(encoding="utf-8"),
            "audit_events": [
                event.model_dump(mode="json") for event in store.audit_events()
            ],
        }


def run_foundation_scan(
    terraform_text: str,
    uploaded_files: list[Any],
    state_file: Any | None,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        workspace = write_workspace(root, terraform_text, uploaded_files)
        state_path = None
        if state_file:
            state_path = root / Path(state_file.name).name
            state_path.write_bytes(state_file.getvalue())
        report = scan_path(workspace, state_path=state_path)
        return report.model_dump(mode="json")


with st.sidebar:
    st.markdown("## TerraGuard Platform")
    st.caption("Single app for v1 Foundation through v5 Autonomous Governance.")
    st.divider()
    st.markdown("### Live app versions")
    st.markdown(f"- [v1 Foundation demo]({LIVE_V1_URL})")
    st.markdown(f"- [v2 Enterprise demo]({LIVE_V2_URL})")
    st.markdown(f"- [v3-v5 Governance demo]({LIVE_GOVERNANCE_URL})")
    st.markdown(f"- [v1-v5 Full platform demo]({LIVE_FULL_URL})")
    st.divider()
    st.markdown("### Guides")
    st.markdown(f"- [How-to guides]({HOW_TO_GUIDES_URL})")
    st.markdown(f"- [How to use this app]({HOW_TO_APP_URL})")
    st.markdown(f"- [Enterprise case studies]({CASE_STUDIES_URL})")
    st.divider()
    st.markdown(f"- [GitHub Repository]({REPO_URL})")
    st.markdown(f"- [Author: Huzefa Husain]({LINKEDIN_URL})")

st.markdown(
    """
    <section class="platform-hero">
      <h1>Terraform Guardrail Enterprise Platform</h1>
      <p>
        One professional workspace for scanning Terraform, authoring controls, installing policy
        packs, explaining decisions, creating remediation, planning pull requests, scheduling
        governance, and exporting audit evidence.
      </p>
      <div class="stage-row">
        <div class="stage"><strong>v1</strong><span>Scan and state checks</span></div>
        <div class="stage"><strong>v2</strong><span>Policies and evidence</span></div>
        <div class="stage"><strong>v3</strong><span>Policy packs and APIs</span></div>
        <div class="stage"><strong>v4</strong><span>Explainability and fixes</span></div>
        <div class="stage"><strong>v5</strong><span>Autonomous governance</span></div>
      </div>
    </section>
    """,
    unsafe_allow_html=True,
)

metric_a, metric_b, metric_c, metric_d = st.columns(4)
with metric_a:
    st.markdown(
        '<div class="metric-card"><span>Rules</span><strong>TG001-TG023</strong></div>',
        unsafe_allow_html=True,
    )
with metric_b:
    st.markdown(
        '<div class="metric-card"><span>Policy packs</span><strong>4</strong></div>',
        unsafe_allow_html=True,
    )
with metric_c:
    st.markdown(
        '<div class="metric-card"><span>Reports</span><strong>JSON CSV SARIF JUnit</strong></div>',
        unsafe_allow_html=True,
    )
with metric_d:
    st.markdown(
        '<div class="metric-card"><span>Loop</span><strong>Evaluate Fix Schedule</strong></div>',
        unsafe_allow_html=True,
    )

tab_scan, tab_catalog, tab_enterprise, tab_governance, tab_evidence, tab_stories = st.tabs(
    [
        "v1 Scan",
        "v2 Catalog",
        "v2-v3 Enterprise",
        "v4-v5 Governance",
        "Evidence + Health",
        "Stories",
    ]
)

with tab_scan:
    st.subheader("v1 Foundation scan")
    scan_text = st.text_area("Terraform input", value=SAMPLE_TERRAFORM, height=260)
    scan_files = st.file_uploader(
        "Optional Terraform files",
        type=["tf", "tfvars", "hcl"],
        accept_multiple_files=True,
        key="full-scan-files",
    )
    state_file = st.file_uploader(
        "Optional state file",
        type=["tfstate"],
        key="full-state",
    )
    if st.button("Run Foundation Scan", type="primary"):
        st.session_state["full_scan"] = run_foundation_scan(
            scan_text,
            scan_files or [],
            state_file,
        )
    if "full_scan" in st.session_state:
        scan = st.session_state["full_scan"]
        st.write(scan.get("summary", {}))
        findings = scan.get("findings", [])
        if findings:
            st.dataframe(finding_rows(findings), width="stretch", hide_index=True)
            output = StringIO()
            writer = csv.DictWriter(output, fieldnames=list(findings[0].keys()))
            writer.writeheader()
            writer.writerows(findings)
            st.download_button(
                "Download scan CSV",
                data=output.getvalue(),
                file_name="terraguard-scan.csv",
                mime="text/csv",
            )
        else:
            st.success("No findings detected.")

with tab_catalog:
    st.subheader("v2 clickable policy catalog")
    if "full_selected_rule" not in st.session_state:
        st.session_state["full_selected_rule"] = "TG001"
    list_col, detail_col = st.columns([0.9, 1.2])
    with list_col:
        for rule_id, name in sorted(RULES.items()):
            if st.button(f"{rule_id} - {name}", key=f"full-rule-{rule_id}", width="stretch"):
                st.session_state["full_selected_rule"] = rule_id
    with detail_col:
        selected = st.session_state["full_selected_rule"]
        detail = rule_detail(selected)
        st.markdown(f"#### {detail['rule_id']} - {detail['name']}")
        st.write(
            {
                "risk": detail["risk"],
                "remediation": detail["remediation"],
                "suggested_fix": detail["suggested_fix"],
            }
        )
        st.code(detail["snippet"], language="json")
        st.download_button(
            "Download policy snippet",
            data=detail["snippet"],
            file_name=f"{selected.lower()}-enterprise-policy.json",
            mime="application/json",
        )

with tab_enterprise:
    st.subheader("v2-v3 enterprise evaluation")
    packs = pack_options()
    col_a, col_b = st.columns([1.05, 0.95])
    with col_a:
        enterprise_text = st.text_area(
            "Enterprise Terraform sample",
            value=SAMPLE_TERRAFORM,
            height=250,
            key="enterprise-text",
        )
        enterprise_files = st.file_uploader(
            "Optional enterprise Terraform files",
            type=["tf", "tfvars", "hcl"],
            accept_multiple_files=True,
            key="enterprise-files",
        )
    with col_b:
        selected_pack = st.selectbox("Policy pack", list(packs), key="full-pack")
        provider = st.selectbox("Provider", ["aws", "azure", "gcp", "kubernetes"])
        environment = st.selectbox("Environment", ["production", "prod", "dev", "sandbox"])
        risk_tier = st.selectbox("Risk tier", ["critical", "high", "medium", "low"], index=1)
        fail_on = st.selectbox("Fail on", ["high", "medium", "low"])
        waiver = st.checkbox("Apply demo waiver for TG006")
    if st.button("Run Full Platform Evaluation", type="primary"):
        st.session_state["full_platform"] = run_platform_demo(
            pack_id=packs[selected_pack],
            provider=provider,
            environment=environment,
            risk_tier=risk_tier,
            fail_on=fail_on,
            terraform_text=enterprise_text,
            uploaded_files=enterprise_files or [],
            apply_waiver=waiver,
        )
    if "full_platform" in st.session_state:
        payload = st.session_state["full_platform"]
        result = payload["result"]
        summary = result["report"].get("summary", {})
        cols = st.columns(4)
        cols[0].metric("Decision", result["decision"].upper())
        cols[1].metric("High", summary.get("high", 0))
        cols[2].metric("Medium", summary.get("medium", 0))
        cols[3].metric("Low", summary.get("low", 0))
        st.write({"installed_pack": payload["install"], "resolved": result["resolved_policy_ids"]})
        if payload["findings"]:
            st.dataframe(finding_rows(payload["findings"]), width="stretch", hide_index=True)

with tab_governance:
    st.subheader("v4-v5 explainability, remediation, and automation")
    payload = st.session_state.get("full_platform")
    if not payload:
        st.info("Run the full platform evaluation first.")
    else:
        cols = st.columns(4)
        cols[0].metric("Remediation actions", len(payload["plan"]["actions"]))
        cols[1].metric("Patch files", len(payload["bundle"]["files"]))
        cols[2].metric("PR status", payload["pull_request"]["status"])
        cols[3].metric("Runner status", payload["automation"]["status"])
        st.markdown("#### Explainability")
        st.markdown(payload["explanation_markdown"])
        st.markdown("#### Remediation")
        st.markdown(payload["plan_markdown"])
        if payload["bundle"]["files"]:
            st.markdown("#### First patch preview")
            st.code(payload["bundle"]["files"][0]["content"], language="hcl")
        st.markdown("#### GitHub PR dry run")
        st.code(" ".join(payload["pull_request"]["command"]), language="bash")
        st.markdown("#### Schedules")
        st.json(
            {
                "scheduled_scan": payload["scheduled_scan"],
                "scheduled_evidence": payload["scheduled_evidence"],
                "automation": payload["automation"],
            }
        )

with tab_evidence:
    st.subheader("Evidence, reports, drift, and health")
    payload = st.session_state.get("full_platform")
    drift_left, drift_right = st.columns(2)
    with drift_left:
        approved = st.text_area("Approved drift snapshot", DRIFT_APPROVED, height=180)
    with drift_right:
        current = st.text_area("Current drift candidate", DRIFT_CURRENT, height=180)
    if st.button("Run Drift Check"):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = EnterpriseStore(root / "drift-store")
            infra = root / "main.tf"
            infra.write_text(approved, encoding="utf-8")
            check_drift(infra, snapshot_id="full-demo", store=store)
            infra.write_text(current, encoding="utf-8")
            st.session_state["full_drift"] = check_drift(
                infra,
                snapshot_id="full-demo",
                store=store,
            ).model_dump(mode="json")
    if "full_drift" in st.session_state:
        st.json(st.session_state["full_drift"])
    if not payload:
        st.info("Run the full platform evaluation to generate evidence and health reports.")
    else:
        health = payload["health"]
        trend = payload["trend"]
        cols = st.columns(4)
        cols[0].metric("Evaluations", health["totals"].get("evaluations", 0))
        cols[1].metric("Exports", health["evidence_summary"].get("exports", 0))
        cols[2].metric("Coverage", f"{trend['summary'].get('coverage_percent', 0)}%")
        cols[3].metric("Audit events", len(payload["audit_events"]))
        if health["top_rules"]:
            st.dataframe(health["top_rules"], width="stretch", hide_index=True)
        st.dataframe(payload["audit_events"][-12:], width="stretch", hide_index=True)
        col_json, col_csv, col_sarif, col_junit = st.columns(4)
        with col_json:
            st.download_button(
                "JSON evidence",
                payload["json_evidence"],
                "terraguard-evidence.json",
                "application/json",
            )
        with col_csv:
            st.download_button(
                "CSV evidence",
                payload["csv_evidence"],
                "terraguard-evidence.csv",
                "text/csv",
            )
        with col_sarif:
            st.download_button(
                "SARIF",
                payload["sarif"],
                "terraguard.sarif",
                "application/sarif+json",
            )
        with col_junit:
            st.download_button(
                "JUnit",
                payload["junit"],
                "terraguard-junit.xml",
                "application/xml",
            )

with tab_stories:
    st.subheader("Enterprise case-study playbooks")
    st.markdown(
        f"Read the full story-driven guide in the wiki: "
        f"[Enterprise Case Studies]({CASE_STUDIES_URL})."
    )
    stories = [
        (
            "Audit evidence without spreadsheet work",
            "Generate SOC2, ISO, and PCI evidence from CI.",
        ),
        (
            "Prevent public exposure before apply",
            "Block public buckets, databases, and ingress early.",
        ),
        ("Consistent controls across business units", "Use baselines and group bindings."),
        ("Developer-friendly remediation", "Turn findings into suggested fixes and patch bundles."),
        ("Governance that runs itself", "Schedule scans, evidence, and health reporting."),
        ("Multi-cloud platform standards", "Use cross-provider invariant rules."),
        (
            "Board-ready governance telemetry",
            "Convert engineering controls into leadership signals.",
        ),
    ]
    for title, body in stories:
        st.markdown(
            f'<div class="case-card"><strong>{title}</strong><br>{body}</div>',
            unsafe_allow_html=True,
        )

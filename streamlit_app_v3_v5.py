from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import streamlit as st  # noqa: E402

from terraform_guardrail.enterprise import (  # noqa: E402
    EnterpriseStore,
    EvidenceSchedule,
    ScheduledScanTarget,
    create_github_pull_request,
    create_remediation_patch_bundle,
    create_remediation_plan,
    evaluate_enterprise,
    explain_evaluation,
    export_evidence,
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

REPO_URL = "https://github.com/Huzefaaa2/terraform-guardrail"
WIKI_URL = "https://github.com/Huzefaaa2/terraform-guardrail/wiki"
LINKEDIN_URL = "https://www.linkedin.com/in/huzefaaa"
LIVE_V1_URL = "https://terraform-guardrail.streamlit.app/"
LIVE_V2_URL = "https://terraform-guardrail-enterprise.streamlit.app/"
LIVE_GOVERNANCE_URL = "https://terraform-guardrail-governance.streamlit.app/"

SAMPLE_TERRAFORM = """resource "aws_s3_bucket" "logs" {
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
  identifier = "orders-prod"
}
"""


st.set_page_config(
    page_title="TerraGuard Governance v3-v5",
    page_icon="TG",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
      .stApp {
        background: #f7f9fb;
        color: #18212f;
      }
      [data-testid="stSidebar"] {
        background: #111827;
      }
      .hero {
        border: 1px solid #d9e2ea;
        background: #ffffff;
        border-radius: 8px;
        padding: 28px;
        margin-bottom: 18px;
        box-shadow: 0 10px 28px rgba(31, 41, 55, 0.08);
      }
      .hero h1 {
        color: #111827;
        font-size: 42px;
        line-height: 1.08;
        margin: 0 0 12px 0;
      }
      .hero p {
        color: #42526b;
        font-size: 17px;
        max-width: 940px;
      }
      .pill-row {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin-top: 18px;
      }
      .pill {
        border: 1px solid #c8d4df;
        border-radius: 999px;
        padding: 7px 11px;
        color: #1f3a5f;
        background: #eef6fb;
        font-size: 13px;
      }
      .metric-card {
        border: 1px solid #d9e2ea;
        border-radius: 8px;
        background: #ffffff;
        padding: 18px;
        min-height: 116px;
      }
      .metric-card span {
        color: #637083;
        font-size: 13px;
      }
      .metric-card strong {
        display: block;
        color: #111827;
        font-size: 29px;
        margin-top: 7px;
      }
      .signal {
        border-left: 4px solid #1b7f79;
        background: #ffffff;
        border-radius: 8px;
        padding: 14px 16px;
        margin: 8px 0;
      }
      a {
        color: #0f766e !important;
      }
    </style>
    """,
    unsafe_allow_html=True,
)


def policy_pack_rows() -> list[dict[str, Any]]:
    return [
        {
            "pack_id": pack.id,
            "name": pack.name,
            "category": pack.category,
            "providers": ", ".join(pack.providers),
            "standards": ", ".join(pack.standards),
            "policies": len(pack.policies),
            "baseline": pack.baseline_name,
        }
        for pack in list_builtin_policy_packs()
    ]


def write_demo_workspace(root: Path, content: str, uploaded_files: list[Any]) -> Path:
    workspace = root / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    if uploaded_files:
        for uploaded in uploaded_files:
            target = workspace / Path(uploaded.name).name
            target.write_bytes(uploaded.getvalue())
    else:
        (workspace / "main.tf").write_text(content, encoding="utf-8")
    return workspace


def finding_rows(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    keys = [
        "rule_id",
        "severity",
        "message",
        "standard",
        "control_id",
        "risk",
        "remediation",
        "suggested_fix",
    ]
    return [{key: finding.get(key) for key in keys} for finding in findings]


def run_demo(
    *,
    pack_id: str,
    provider: str,
    environment: str,
    risk_tier: str,
    app: str,
    group: str,
    repo: str,
    fail_on: str,
    terraform_text: str,
    uploaded_files: list[Any],
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        store = EnterpriseStore(root / "enterprise-store")
        install = install_policy_pack(pack_id, store=store, actor="streamlit-demo")
        baseline_name = None
        if install.baseline_id:
            baseline_name = store.get_baseline(install.baseline_id).name
        workspace = write_demo_workspace(root, terraform_text, uploaded_files)

        result = evaluate_enterprise(
            workspace,
            provider=provider,
            baseline=baseline_name,
            context={
                "environment": environment,
                "risk_tier": risk_tier,
                "app": app,
                "group": group,
                "repo": repo,
            },
            fail_on=fail_on,
            store=store,
            actor="streamlit-demo",
        )
        explanation = explain_evaluation(result.id, store=store)
        explanation_markdown = render_explanation_markdown(explanation)
        sarif = json.dumps(render_evaluation_sarif(result), indent=2)
        junit = render_evaluation_junit(result)

        plan = create_remediation_plan(result.id, store=store, actor="streamlit-demo")
        remediation_markdown = render_remediation_markdown(plan)
        bundle = create_remediation_patch_bundle(
            plan.id,
            store=store,
            actor="streamlit-demo",
        )
        pull_request = create_github_pull_request(
            bundle.id,
            repository="Huzefaaa2/terraform-guardrail",
            store=store,
            actor="streamlit-demo",
            dry_run=True,
        )

        target = store.save_scheduled_scan_target(
            ScheduledScanTarget(
                name=f"{app} daily governance scan",
                path=str(workspace),
                cadence="daily",
                provider=provider,
                baseline=baseline_name,
                fail_on=fail_on,
                context={
                    "environment": environment,
                    "risk_tier": risk_tier,
                    "app": app,
                    "group": group,
                    "repo": repo,
                },
            ),
            actor="streamlit-demo",
        )
        evidence_schedule = store.save_evidence_schedule(
            EvidenceSchedule(
                name=f"{app} monthly evidence",
                cadence="monthly",
                format="json",
                result_id=result.id,
                app=app,
                group=group,
                repo=repo,
                limit=5,
            ),
            actor="streamlit-demo",
        )
        scheduled_scan = run_scheduled_scan(target.id, store=store, actor="streamlit-demo")
        scheduled_evidence = run_evidence_schedule(
            evidence_schedule.id,
            store=store,
            actor="streamlit-demo",
        )
        automation = run_automation_cycle(store=store, actor="streamlit-demo", limit=3)
        json_export = export_evidence(result.id, format="json", store=store)
        csv_export = export_evidence(result.id, format="csv", store=store)
        health = governance_health_report(store=store)
        trend = governance_trend_report(store=store, days=14)

        return {
            "install": install.model_dump(mode="json"),
            "baseline_name": baseline_name,
            "result": result.model_dump(mode="json"),
            "findings": result.report.get("findings", []),
            "explanation": explanation.model_dump(mode="json"),
            "explanation_markdown": explanation_markdown,
            "sarif": sarif,
            "junit": junit,
            "plan": plan.model_dump(mode="json"),
            "remediation_markdown": remediation_markdown,
            "bundle": bundle.model_dump(mode="json"),
            "pull_request": pull_request.model_dump(mode="json"),
            "scheduled_scan": scheduled_scan.model_dump(mode="json"),
            "scheduled_evidence": scheduled_evidence.model_dump(mode="json"),
            "automation": automation.model_dump(mode="json"),
            "health": health.model_dump(mode="json"),
            "trend": trend.model_dump(mode="json"),
            "json_evidence": Path(json_export.path).read_text(encoding="utf-8"),
            "csv_evidence": Path(csv_export.path).read_text(encoding="utf-8"),
            "audit_events": [
                event.model_dump(mode="json") for event in store.audit_events()
            ],
        }


with st.sidebar:
    st.markdown("## TerraGuard v3-v5")
    st.caption("Ecosystem packs, intelligent evaluation, and autonomous governance.")
    st.divider()
    st.markdown("### Live app versions")
    st.markdown(f"- [v1 Foundation demo]({LIVE_V1_URL})")
    st.markdown(f"- [v2 Enterprise demo]({LIVE_V2_URL})")
    st.markdown(f"- [v3-v5 Governance demo]({LIVE_GOVERNANCE_URL})")
    st.divider()
    st.markdown("### Resources")
    st.markdown(f"- [GitHub Repository]({REPO_URL})")
    st.markdown(f"- [Wiki Docs]({WIKI_URL})")
    st.markdown(f"- [Author: Huzefa Husain]({LINKEDIN_URL})")
    st.divider()

    packs = policy_pack_rows()
    pack_names = {f"{row['name']} ({row['pack_id']})": row["pack_id"] for row in packs}
    selected_pack = st.selectbox("Policy pack", list(pack_names), index=0)
    provider = st.selectbox("Provider", ["aws", "azure", "gcp", "kubernetes"], index=0)
    environment = st.selectbox("Environment", ["production", "prod", "dev", "sandbox"], index=0)
    risk_tier = st.selectbox("Risk tier", ["critical", "high", "medium", "low"], index=1)
    app = st.text_input("Application", value="payments-platform")
    group = st.text_input("Platform group", value="platform-engineering")
    repo = st.text_input("Repository", value="payments-infra")
    fail_on = st.selectbox("Fail on", ["high", "medium", "low"], index=0)
    run_clicked = st.button("Run Governance Loop", type="primary")

st.markdown(
    """
    <section class="hero">
      <h1>Terraform Guardrail v3-v5 Governance Demo</h1>
      <p>
        One live workspace for policy packs, context-aware decisions, explainability,
        remediation plans, PR-ready patch bundles, scheduled scans, evidence schedules,
        and governance health reporting.
      </p>
      <div class="pill-row">
        <span class="pill">v3 Policy Packs</span>
        <span class="pill">v3 Service API</span>
        <span class="pill">v4 Intelligence</span>
        <span class="pill">v4 SARIF/JUnit</span>
        <span class="pill">v5 Remediation</span>
        <span class="pill">v5 Automation</span>
      </div>
    </section>
    """,
    unsafe_allow_html=True,
)

metric_a, metric_b, metric_c, metric_d = st.columns(4)
with metric_a:
    st.markdown(
        '<div class="metric-card"><span>Policy packs</span><strong>4</strong></div>',
        unsafe_allow_html=True,
    )
with metric_b:
    st.markdown(
        '<div class="metric-card"><span>Evaluation model</span>'
        "<strong>Pass Warn Block</strong></div>",
        unsafe_allow_html=True,
    )
with metric_c:
    st.markdown(
        '<div class="metric-card"><span>Reports</span><strong>SARIF JUnit Evidence</strong></div>',
        unsafe_allow_html=True,
    )
with metric_d:
    st.markdown(
        '<div class="metric-card"><span>Governance loop</span><strong>Plan Patch PR</strong></div>',
        unsafe_allow_html=True,
    )

terraform_text = st.text_area(
    "Terraform workspace sample",
    value=SAMPLE_TERRAFORM,
    height=260,
    help="Use the sample or upload one or more Terraform files.",
)
uploaded_files = st.file_uploader(
    "Optional Terraform files",
    type=["tf", "tfvars", "hcl"],
    accept_multiple_files=True,
)

if run_clicked:
    st.session_state["governance_demo"] = run_demo(
        pack_id=pack_names[selected_pack],
        provider=provider,
        environment=environment,
        risk_tier=risk_tier,
        app=app,
        group=group,
        repo=repo,
        fail_on=fail_on,
        terraform_text=terraform_text,
        uploaded_files=uploaded_files or [],
    )

demo = st.session_state.get("governance_demo")

tab_v3, tab_v4, tab_v5, tab_reports = st.tabs(
    ["v3 Ecosystem", "v4 Intelligence", "v5 Autonomous", "Evidence + Health"]
)

with tab_v3:
    st.subheader("Ecosystem policy packs")
    st.caption(
        "v3 adds installable policy packs and reference baselines so platform teams "
        "can distribute controls without rebuilding every repo."
    )
    st.dataframe(packs, width="stretch", hide_index=True)
    if demo:
        st.markdown("#### Installed pack")
        st.json(demo["install"])
        st.markdown(
            '<div class="signal">Resolved baseline: '
            f'<strong>{demo["baseline_name"]}</strong></div>',
            unsafe_allow_html=True,
        )

with tab_v4:
    st.subheader("Intelligent evaluation and explainability")
    if not demo:
        st.info("Run the governance loop from the sidebar to generate a live evaluation.")
    else:
        result = demo["result"]
        summary = result["report"].get("summary", {})
        cols = st.columns(4)
        cols[0].metric("Decision", result["decision"].upper())
        cols[1].metric("High", summary.get("high", 0))
        cols[2].metric("Medium", summary.get("medium", 0))
        cols[3].metric("Low", summary.get("low", 0))
        intelligence = result["service_metadata"].get("intelligence", {})
        profile = intelligence.get("profile") or {}
        st.write(
            {
                "risk_profile": profile.get("name", "No risk profile matched"),
                "resolved_policy_ids": result["resolved_policy_ids"],
                "binding_targets": demo["explanation"].get("binding_targets", []),
            }
        )
        adjustments = intelligence.get("adjustments") or []
        recommendations = intelligence.get("recommendations") or []
        if adjustments:
            st.markdown("#### Context severity adjustments")
            st.dataframe(adjustments, width="stretch", hide_index=True)
        if recommendations:
            st.markdown("#### Suggested fixes")
            st.dataframe(recommendations, width="stretch", hide_index=True)
        if demo["findings"]:
            st.markdown("#### Findings")
            st.dataframe(finding_rows(demo["findings"]), width="stretch", hide_index=True)
        st.markdown("#### Explainability report")
        st.markdown(demo["explanation_markdown"])

with tab_v5:
    st.subheader("Autonomous governance loop")
    if not demo:
        st.info(
            "Run the governance loop from the sidebar to create remediation "
            "and automation outputs."
        )
    else:
        plan = demo["plan"]
        bundle = demo["bundle"]
        pull_request = demo["pull_request"]
        automation = demo["automation"]
        cols = st.columns(4)
        cols[0].metric("Remediation actions", len(plan["actions"]))
        cols[1].metric("Patch files", len(bundle["files"]))
        cols[2].metric("PR status", pull_request["status"])
        cols[3].metric("Runner status", automation["status"])
        st.markdown("#### Remediation plan")
        st.markdown(demo["remediation_markdown"])
        st.markdown("#### Patch bundle")
        st.write(
            {
                "branch": bundle["branch_name"],
                "commit_message": bundle["commit_message"],
                "title": bundle["title"],
                "files": [file["path"] for file in bundle["files"]],
            }
        )
        if bundle["files"]:
            st.code(bundle["files"][0]["content"], language="hcl")
        st.markdown("#### GitHub PR dry run")
        st.code(" ".join(pull_request["command"]), language="bash")
        st.markdown("#### Scheduled governance")
        st.json(
            {
                "scheduled_scan": demo["scheduled_scan"],
                "scheduled_evidence": demo["scheduled_evidence"],
                "automation_runner": demo["automation"],
            }
        )

with tab_reports:
    st.subheader("Evidence, reports, and governance health")
    if not demo:
        st.info("Run the governance loop from the sidebar to generate evidence and health signals.")
    else:
        health = demo["health"]
        trend = demo["trend"]
        cols = st.columns(4)
        cols[0].metric("Evaluations", health["totals"].get("evaluations", 0))
        cols[1].metric("Evidence exports", health["evidence_summary"].get("exports", 0))
        cols[2].metric("Active waivers", health["waiver_summary"].get("active", 0))
        cols[3].metric("Coverage", f"{trend['summary'].get('coverage_percent', 0)}%")
        if health["risk_signals"]:
            st.markdown("#### Governance signals")
            for signal in health["risk_signals"]:
                st.markdown(f'<div class="signal">{signal}</div>', unsafe_allow_html=True)
        if health["top_rules"]:
            st.markdown("#### Top rules")
            st.dataframe(health["top_rules"], width="stretch", hide_index=True)
        if trend["activity_timeline"]:
            st.markdown("#### Activity timeline")
            st.dataframe(trend["activity_timeline"], width="stretch", hide_index=True)
        st.markdown("#### Audit events")
        st.dataframe(demo["audit_events"][-12:], width="stretch", hide_index=True)
        col_json, col_csv, col_sarif, col_junit = st.columns(4)
        with col_json:
            st.download_button(
                "JSON evidence",
                data=demo["json_evidence"],
                file_name="terraguard-evidence.json",
                mime="application/json",
            )
        with col_csv:
            st.download_button(
                "CSV evidence",
                data=demo["csv_evidence"],
                file_name="terraguard-evidence.csv",
                mime="text/csv",
            )
        with col_sarif:
            st.download_button(
                "SARIF report",
                data=demo["sarif"],
                file_name="terraguard.sarif",
                mime="application/sarif+json",
            )
        with col_junit:
            st.download_button(
                "JUnit report",
                data=demo["junit"],
                file_name="terraguard-junit.xml",
                mime="application/xml",
            )

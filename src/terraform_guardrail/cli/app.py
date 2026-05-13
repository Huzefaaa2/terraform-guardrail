from __future__ import annotations

import importlib.metadata
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.json import JSON

from terraform_guardrail.api.app import create_app as create_api_app
from terraform_guardrail.aws_codepipeline import (
    AwsCodePipelineScaffoldError,
    scaffold_aws_codepipeline,
)
from terraform_guardrail.enterprise import (
    Baseline,
    EnterprisePolicy,
    EnterpriseStore,
    EvaluationContext,
    GroupPolicyBinding,
    PolicyMetadata,
    PolicyWaiver,
    RiskProfile,
    ScheduledScanTarget,
    check_drift,
    create_remediation_patch_bundle,
    create_remediation_plan,
    evaluate_enterprise,
    explain_evaluation,
    export_evidence,
    get_builtin_policy_pack,
    get_rule_recommendation,
    governance_health_report,
    install_policy_pack,
    list_builtin_policy_packs,
    list_rule_recommendations,
    render_evaluation_report,
    render_explanation_markdown,
    render_remediation_markdown,
    resolve_policy_set,
    run_drift_gate,
    run_scheduled_scan,
)
from terraform_guardrail.generator import generate_snippet
from terraform_guardrail.mcp.server import run_stdio
from terraform_guardrail.policy_registry import (
    PolicyRegistryError,
    download_bundle,
    get_policy_bundle,
    list_policy_bundles,
)
from terraform_guardrail.registry_api import create_registry_app
from terraform_guardrail.scanner.rules import RULES
from terraform_guardrail.scanner.scan import scan_path
from terraform_guardrail.web.app import create_app

app = typer.Typer(add_completion=False)
policy_app = typer.Typer(help="Policy registry commands.")
rules_app = typer.Typer(help="Rule catalog commands.")
enterprise_app = typer.Typer(help="Enterprise policy lifecycle commands.")
enterprise_policy_app = typer.Typer(help="Enterprise policy commands.")
enterprise_baseline_app = typer.Typer(help="Enterprise baseline commands.")
enterprise_binding_app = typer.Typer(help="Enterprise group/repo binding commands.")
enterprise_pack_app = typer.Typer(help="Enterprise policy pack commands.")
enterprise_risk_app = typer.Typer(help="Enterprise context risk profile commands.")
enterprise_waiver_app = typer.Typer(help="Enterprise policy waiver commands.")
enterprise_remediation_app = typer.Typer(help="Enterprise remediation plan commands.")
enterprise_schedule_app = typer.Typer(help="Enterprise scheduled governance scan commands.")
enterprise_aws_app = typer.Typer(help="AWS enterprise integration commands.")
enterprise_aws_codepipeline_app = typer.Typer(help="AWS CodePipeline scaffold commands.")
evidence_app = typer.Typer(help="Evidence export commands.")
app.add_typer(policy_app, name="policy")
app.add_typer(rules_app, name="rules")
app.add_typer(enterprise_app, name="enterprise")
app.add_typer(evidence_app, name="evidence")
enterprise_app.add_typer(enterprise_policy_app, name="policy")
enterprise_app.add_typer(enterprise_baseline_app, name="baseline")
enterprise_app.add_typer(enterprise_binding_app, name="binding")
enterprise_app.add_typer(enterprise_pack_app, name="pack")
enterprise_app.add_typer(enterprise_risk_app, name="risk-profile")
enterprise_app.add_typer(enterprise_waiver_app, name="waiver")
enterprise_app.add_typer(enterprise_remediation_app, name="remediation")
enterprise_app.add_typer(enterprise_schedule_app, name="schedule")
enterprise_app.add_typer(enterprise_aws_app, name="aws")
enterprise_aws_app.add_typer(enterprise_aws_codepipeline_app, name="codepipeline")
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(importlib.metadata.version("terraform-guardrail"))
        raise typer.Exit()


@app.callback()
def _root(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show version and exit.",
        ),
    ] = False,
) -> None:
    """Terraform Guardrail MCP CLI."""


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Path to a Terraform file or directory.")],
    state: Annotated[Path | None, typer.Option(help="Optional path to a .tfstate file.")] = None,
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
    schema: Annotated[bool, typer.Option(help="Enable schema-aware validation")] = False,
    policy_bundle: Annotated[str | None, typer.Option(help="Policy bundle ID to evaluate")] = None,
    policy_bundle_path: Annotated[
        Path | None,
        typer.Option(help="Local policy bundle path (.tar.gz or directory)"),
    ] = None,
    policy_layers: Annotated[
        list[str] | None,
        typer.Option(help="Ordered policy bundles for layering (repeatable)"),
    ] = None,
    policy_base: Annotated[str | None, typer.Option(help="Base policy bundle ID")] = None,
    policy_env: Annotated[str | None, typer.Option(help="Environment policy bundle ID")] = None,
    policy_app: Annotated[str | None, typer.Option(help="Application policy bundle ID")] = None,
    policy_registry: Annotated[str | None, typer.Option(help="Policy registry URL")] = None,
    policy_query: Annotated[str | None, typer.Option(help="OPA query override")] = None,
    fail_on: Annotated[
        str | None,
        typer.Option(help="Fail if findings at/above severity: low, medium, high"),
    ] = None,
) -> None:
    try:
        report = scan_path(
            path=path,
            state_path=state,
            use_schema=schema,
            policy_bundle=policy_bundle,
            policy_bundle_path=policy_bundle_path,
            policy_layers=policy_layers,
            policy_base=policy_base,
            policy_env=policy_env,
            policy_app=policy_app,
            policy_registry=policy_registry,
            policy_query=policy_query,
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"Scan failed: {exc}")
        raise typer.Exit(code=1) from exc
    if format == "json":
        console.print(JSON(json.dumps(report.model_dump(), indent=2)))
    else:
        console.print(f"Scanned: {report.scanned_path}")
        console.print(f"Findings: {report.summary.findings}")
        console.print(
            "High: "
            f"{report.summary.high} Medium: {report.summary.medium} Low: {report.summary.low}"
        )
        for finding in report.findings:
            console.print(
                f"- [{finding.severity}] {finding.rule_id} {finding.message} ({finding.path})"
            )

    if fail_on:
        _maybe_fail(report.summary, fail_on.lower())


@app.command()
def evaluate(
    path: Annotated[Path, typer.Argument(help="Path to a Terraform file or directory.")],
    state: Annotated[Path | None, typer.Option(help="Optional path to a .tfstate file.")] = None,
    provider: Annotated[str | None, typer.Option(help="Provider context, e.g. aws")] = None,
    policy_set: Annotated[str | None, typer.Option(help="Named enterprise policy set")] = None,
    baseline: Annotated[str | None, typer.Option(help="Baseline ID or name to resolve")] = None,
    context: Annotated[
        list[str] | None,
        typer.Option(help="Evaluation context as key=value, repeatable"),
    ] = None,
    fail_on: Annotated[
        str | None,
        typer.Option(help="Block if findings at/above severity: low, medium, high"),
    ] = None,
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    try:
        result = evaluate_enterprise(
            path=path,
            state_path=state,
            provider=provider,
            policy_set=policy_set,
            baseline=baseline,
            context=_parse_key_values(context),
            fail_on=fail_on.lower() if fail_on else None,
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"Evaluation failed: {exc}")
        raise typer.Exit(code=1) from exc

    if format == "json":
        console.print(JSON(json.dumps(result.model_dump(mode="json"), indent=2)))
    else:
        summary = result.report["summary"]
        console.print(f"Evaluation: {result.id}")
        console.print(f"Decision: {result.decision}")
        console.print(
            "Findings: "
            f"{summary['findings']} High: {summary['high']} "
            f"Medium: {summary['medium']} Low: {summary['low']}"
        )
        if result.resolved_policy_ids:
            console.print(f"Policies: {', '.join(result.resolved_policy_ids)}")
    if result.decision == "block":
        raise typer.Exit(code=1)


@app.command()
def generate(
    provider: Annotated[str, typer.Argument(help="Provider: aws or azure")],
    resource: Annotated[str, typer.Argument(help="Resource type, e.g. aws_s3_bucket")],
    name: Annotated[str, typer.Option(help="Resource name")] = "example",
) -> None:
    try:
        snippet = generate_snippet(provider, resource, name)
    except Exception as exc:  # noqa: BLE001
        console.print(f"Generation failed: {exc}")
        raise typer.Exit(code=1) from exc
    console.print(snippet.content.strip())


@app.command()
def mcp() -> None:
    console.print("Starting MCP server on stdio...")
    run_stdio()


@app.command()
def web(
    host: Annotated[str, typer.Option(help="Bind host")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Bind port")] = 8000,
) -> None:
    import uvicorn

    uvicorn.run(create_app(), host=host, port=port)


@app.command()
def api(
    host: Annotated[str, typer.Option(help="Bind host")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Bind port")] = 8080,
) -> None:
    import uvicorn

    uvicorn.run(create_api_app(), host=host, port=port)


@app.command("registry-api")
def registry_api(
    host: Annotated[str, typer.Option(help="Bind host")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Bind port")] = 8090,
) -> None:
    import uvicorn

    uvicorn.run(create_registry_app(), host=host, port=port)


@policy_app.command("list")
def list_policies(
    registry: Annotated[str | None, typer.Option(help="Policy registry URL")] = None,
) -> None:
    try:
        bundles = list_policy_bundles(registry)
    except PolicyRegistryError as exc:
        console.print(f"Policy registry error: {exc}")
        raise typer.Exit(code=1) from exc
    for bundle in bundles:
        console.print(f"- {bundle.bundle_id} ({bundle.version or 'unknown'}) {bundle.title}")


@policy_app.command("fetch")
def fetch_policy(
    bundle_id: Annotated[str, typer.Argument(help="Bundle ID to download")],
    destination: Annotated[
        Path, typer.Option(help="Destination directory for the bundle")
    ] = Path("./policies"),
    registry: Annotated[str | None, typer.Option(help="Policy registry URL")] = None,
) -> None:
    try:
        bundle = get_policy_bundle(bundle_id, registry)
        bundle_path = download_bundle(bundle, destination)
    except PolicyRegistryError as exc:
        console.print(f"Policy registry error: {exc}")
        raise typer.Exit(code=1) from exc
    console.print(f"Bundle downloaded to {bundle_path}")


@policy_app.command("init")
def init_policy_bundle(
    destination: Annotated[
        Path, typer.Option(help="Destination directory for the new bundle")
    ] = Path("./policy-bundle"),
    bundle_name: Annotated[str, typer.Option(help="Policy package name")] = "guardrail",
) -> None:
    bundle_dir = destination
    policies_dir = bundle_dir / "policies"
    policies_dir.mkdir(parents=True, exist_ok=True)
    (bundle_dir / ".manifest").write_text(
        '{\n  "revision": "0.1.0",\n  "roots": ["guardrail"]\n}\n',
        encoding="utf-8",
    )
    (bundle_dir / "data.json").write_text(
        "\n".join(
            [
                "{",
                '  "guardrail": {',
                '    "allowed_regions": [],',
                '    "allowed_instance_types": []',
                "  }",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (policies_dir / "guardrail.rego").write_text(
        "\n".join(
            [
                f"package {bundle_name}",
                "",
                "import rego.v1",
                "",
                "default allow = true",
                "",
                "deny contains output if {",
                "  false",
                "",
                "  output := {",
                "    \"message\": \"Example policy violation\",",
                "    \"severity\": \"medium\",",
                "    \"rule_id\": \"CUSTOM001\",",
                "    \"path\": \"policy\",",
                "  }",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    console.print(f"Policy bundle scaffold created at {bundle_dir}")


@policy_app.command("validate")
def validate_policy_bundle(
    bundle_path: Annotated[Path, typer.Argument(help="Bundle path (.tar.gz or directory)")],
) -> None:
    if not bundle_path.exists():
        console.print(f"Bundle not found: {bundle_path}")
        raise typer.Exit(code=1)
    opa_path = shutil.which("opa")
    if not opa_path:
        console.print("OPA CLI not found. Install OPA to validate bundles.")
        raise typer.Exit(code=1)
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir) / "validated.tar.gz"
        cmd = [
            opa_path,
            "build",
            "--bundle",
            str(bundle_path),
            "--output",
            str(tmp_path),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            console.print(f"Bundle validation failed: {result.stderr.strip()}")
            raise typer.Exit(code=1)
    console.print("Bundle validation succeeded.")


@rules_app.command("list")
def list_rules() -> None:
    for rule_id, message in sorted(RULES.items()):
        console.print(f"- {rule_id}: {message}")


@enterprise_policy_app.command("create")
def enterprise_policy_create(
    name: Annotated[str, typer.Option(help="Policy name")],
    description: Annotated[str, typer.Option(help="Policy description")] = "",
    rule_id: Annotated[
        str | None,
        typer.Option(help="Built-in rule ID this metadata enriches"),
    ] = None,
    category: Annotated[
        str,
        typer.Option(help="security, cost, resiliency, compliance"),
    ] = "security",
    severity: Annotated[str, typer.Option(help="info, warn, block")] = "warn",
    scope: Annotated[str, typer.Option(help="org, group, repo")] = "org",
    provider: Annotated[
        list[str] | None,
        typer.Option(help="Provider this policy applies to, repeatable"),
    ] = None,
    rule_type: Annotated[str, typer.Option(help="rego, native, invariant")] = "native",
    rule_body: Annotated[str, typer.Option(help="Policy rule body")] = "",
    owner: Annotated[str | None, typer.Option(help="Policy owner")] = None,
    standard: Annotated[str | None, typer.Option(help="Compliance standard")] = None,
    control_id: Annotated[str | None, typer.Option(help="Control ID")] = None,
    risk: Annotated[str | None, typer.Option(help="Risk tier")] = None,
    expiry: Annotated[str | None, typer.Option(help="Policy expiry date")] = None,
    remediation: Annotated[str | None, typer.Option(help="Remediation guidance")] = None,
    baseline_policy: Annotated[bool, typer.Option(help="Mark as baseline policy")] = False,
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    try:
        policy = EnterprisePolicy(
            name=name,
            description=description,
            category=category,  # type: ignore[arg-type]
            severity=severity,  # type: ignore[arg-type]
            scope=scope,  # type: ignore[arg-type]
            providers=provider or [],
            rule_type=rule_type,  # type: ignore[arg-type]
            rule_body=rule_body,
            rule_id=rule_id,
            metadata=PolicyMetadata(
                owner=owner,
                standard=standard,
                control_id=control_id,
                risk=risk,
                expiry=expiry,
                remediation=remediation,
            ),
            baseline_policy=baseline_policy,
        )
        saved = EnterpriseStore().save_policy(policy)
    except Exception as exc:  # noqa: BLE001
        console.print(f"Policy create failed: {exc}")
        raise typer.Exit(code=1) from exc
    _print_model(saved, format)


@enterprise_policy_app.command("list")
def enterprise_policy_list(
    scope: Annotated[str | None, typer.Option(help="Filter by scope")] = None,
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    policies = EnterpriseStore().list_policies()
    if scope:
        policies = [policy for policy in policies if policy.scope == scope]
    if format == "json":
        console.print(JSON(json.dumps([policy.model_dump(mode="json") for policy in policies])))
        return
    for policy in policies:
        console.print(f"- {policy.id} {policy.name} [{policy.status}] {policy.severity}")


@enterprise_policy_app.command("show")
def enterprise_policy_show(
    policy_id: Annotated[str, typer.Argument(help="Policy ID")],
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    try:
        policy = EnterpriseStore().get_policy(policy_id)
    except KeyError as exc:
        console.print(str(exc))
        raise typer.Exit(code=1) from exc
    _print_model(policy, format)


@enterprise_policy_app.command("approve")
def enterprise_policy_approve(
    policy_id: Annotated[str, typer.Argument(help="Policy ID")],
    actor: Annotated[str, typer.Option(help="Approver identity")] = "system",
    comment: Annotated[str | None, typer.Option(help="Approval comment")] = None,
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    try:
        approval = EnterpriseStore().approve_policy(policy_id, actor=actor, comment=comment)
    except KeyError as exc:
        console.print(str(exc))
        raise typer.Exit(code=1) from exc
    _print_model(approval, format)


@enterprise_baseline_app.command("create")
def enterprise_baseline_create(
    name: Annotated[str, typer.Option(help="Baseline name")],
    policy_id: Annotated[
        list[str] | None,
        typer.Option(help="Policy ID to include, repeatable"),
    ] = None,
    scope: Annotated[str, typer.Option(help="org, group, repo")] = "org",
    version: Annotated[str, typer.Option(help="Baseline version")] = "0.1.0",
    approved: Annotated[bool, typer.Option(help="Mark baseline approved")] = False,
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    try:
        baseline = Baseline(
            name=name,
            policy_ids=policy_id or [],
            scope=scope,  # type: ignore[arg-type]
            version=version,
            approved=approved,
        )
        saved = EnterpriseStore().save_baseline(baseline)
    except Exception as exc:  # noqa: BLE001
        console.print(f"Baseline create failed: {exc}")
        raise typer.Exit(code=1) from exc
    _print_model(saved, format)


@enterprise_baseline_app.command("list")
def enterprise_baseline_list(
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    baselines = EnterpriseStore().list_baselines()
    if format == "json":
        console.print(
            JSON(json.dumps([baseline.model_dump(mode="json") for baseline in baselines]))
        )
        return
    for baseline in baselines:
        console.print(
            f"- {baseline.id} {baseline.name} [{baseline.version}] "
            f"approved={baseline.approved} policies={len(baseline.policy_ids)}"
        )


@enterprise_baseline_app.command("show")
def enterprise_baseline_show(
    baseline_id: Annotated[str, typer.Argument(help="Baseline ID or name")],
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    try:
        baseline = EnterpriseStore().get_baseline(baseline_id)
    except KeyError as exc:
        console.print(str(exc))
        raise typer.Exit(code=1) from exc
    _print_model(baseline, format)


@enterprise_baseline_app.command("version")
def enterprise_baseline_version(
    baseline_id: Annotated[str, typer.Argument(help="Baseline ID or name")],
    version: Annotated[str, typer.Option(help="New baseline version")],
    policy_id: Annotated[
        list[str] | None,
        typer.Option(help="Policy ID to include in this version, repeatable"),
    ] = None,
    actor: Annotated[str, typer.Option(help="Actor identity")] = "system",
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    try:
        created = EnterpriseStore().add_baseline_version(
            baseline_id=baseline_id,
            version=version,
            policy_ids=policy_id,
            actor=actor,
        )
    except KeyError as exc:
        console.print(str(exc))
        raise typer.Exit(code=1) from exc
    _print_model(created, format)


@enterprise_baseline_app.command("approve")
def enterprise_baseline_approve(
    baseline_id: Annotated[str, typer.Argument(help="Baseline ID or name")],
    actor: Annotated[str, typer.Option(help="Approver identity")] = "system",
    comment: Annotated[str | None, typer.Option(help="Approval comment")] = None,
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    try:
        approval = EnterpriseStore().approve_baseline(
            baseline_id=baseline_id,
            actor=actor,
            comment=comment,
        )
    except KeyError as exc:
        console.print(str(exc))
        raise typer.Exit(code=1) from exc
    _print_model(approval, format)


@enterprise_baseline_app.command("history")
def enterprise_baseline_history(
    baseline_id: Annotated[str, typer.Argument(help="Baseline ID or name")],
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    store = EnterpriseStore()
    try:
        versions = store.list_baseline_versions(baseline_id)
        approvals = store.list_baseline_approvals(baseline_id)
    except KeyError as exc:
        console.print(str(exc))
        raise typer.Exit(code=1) from exc
    payload = {
        "versions": [version.model_dump(mode="json") for version in versions],
        "approvals": [approval.model_dump(mode="json") for approval in approvals],
    }
    if format == "json":
        console.print(JSON(json.dumps(payload, indent=2)))
        return
    for version in versions:
        console.print(f"- version {version.version} policies={len(version.policy_ids)}")
    for approval in approvals:
        console.print(f"- approval {approval.status} {approval.version} by {approval.actor}")


@enterprise_binding_app.command("create")
def enterprise_binding_create(
    target_type: Annotated[str, typer.Option(help="org, group, or repo")],
    target: Annotated[str, typer.Option(help="Target org, group, or repo identifier")],
    policy_id: Annotated[
        list[str] | None,
        typer.Option(help="Policy ID to bind, repeatable"),
    ] = None,
    baseline_id: Annotated[
        list[str] | None,
        typer.Option(help="Baseline ID/name to bind, repeatable"),
    ] = None,
    parent: Annotated[str | None, typer.Option(help="Parent target for inheritance")] = None,
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    try:
        binding = GroupPolicyBinding(
            target_type=target_type,  # type: ignore[arg-type]
            target=target,
            policy_ids=policy_id or [],
            baseline_ids=baseline_id or [],
            parent=parent,
        )
        saved = EnterpriseStore().save_binding(binding)
    except Exception as exc:  # noqa: BLE001
        console.print(f"Binding create failed: {exc}")
        raise typer.Exit(code=1) from exc
    _print_model(saved, format)


@enterprise_binding_app.command("list")
def enterprise_binding_list(
    target_type: Annotated[str | None, typer.Option(help="Filter by org, group, or repo")] = None,
    target: Annotated[str | None, typer.Option(help="Filter by target identifier")] = None,
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    bindings = EnterpriseStore().list_bindings()
    if target_type:
        bindings = [binding for binding in bindings if binding.target_type == target_type]
    if target:
        bindings = [binding for binding in bindings if binding.target == target]
    if format == "json":
        console.print(JSON(json.dumps([binding.model_dump(mode="json") for binding in bindings])))
        return
    for binding in bindings:
        console.print(
            f"- {binding.id} {binding.target_type}:{binding.target} "
            f"policies={len(binding.policy_ids)} baselines={len(binding.baseline_ids)}"
        )


@enterprise_binding_app.command("resolve")
def enterprise_binding_resolve(
    org: Annotated[str | None, typer.Option(help="Org target")] = None,
    group: Annotated[str | None, typer.Option(help="Group target")] = None,
    repo: Annotated[str | None, typer.Option(help="Repo target")] = None,
    baseline: Annotated[str | None, typer.Option(help="Explicit baseline ID or name")] = None,
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    result = resolve_policy_set(
        EnterpriseStore(),
        EvaluationContext(org=org, group=group, repo=repo, baseline=baseline),
    )
    if format == "json":
        console.print(JSON(json.dumps(result.model_dump(mode="json"), indent=2)))
        return
    console.print(f"Target: {result.target_type}:{result.target}")
    console.print(f"Bindings: {', '.join(result.binding_targets) or 'none'}")
    console.print(f"Baselines: {', '.join(result.baseline_ids) or 'none'}")
    console.print(f"Policies: {', '.join(result.policy_ids) or 'none'}")
    for policy in result.policies:
        console.print(f"- {policy.get('rule_id') or 'none'} {policy.get('name')}")


@enterprise_pack_app.command("list")
def enterprise_pack_list(
    provider: Annotated[str | None, typer.Option(help="Filter by provider")] = None,
    standard: Annotated[str | None, typer.Option(help="Filter by standard")] = None,
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    packs = list_builtin_policy_packs()
    if provider:
        packs = [pack for pack in packs if provider in pack.providers]
    if standard:
        packs = [pack for pack in packs if standard in pack.standards]
    if format == "json":
        console.print(
            JSON(
                json.dumps(
                    [pack.model_dump(mode="json", exclude={"policies"}) for pack in packs],
                    indent=2,
                )
            )
        )
        return
    for pack in packs:
        console.print(
            f"- {pack.id} {pack.name} [{pack.version}] "
            f"providers={','.join(pack.providers)} policies={len(pack.policies)}"
        )


@enterprise_pack_app.command("show")
def enterprise_pack_show(
    pack_id: Annotated[str, typer.Argument(help="Built-in pack ID")],
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    try:
        pack = get_builtin_policy_pack(pack_id)
    except KeyError as exc:
        console.print(str(exc))
        raise typer.Exit(code=1) from exc
    if format == "json":
        console.print(JSON(json.dumps(pack.model_dump(mode="json"), indent=2)))
        return
    console.print(f"{pack.id}: {pack.name}")
    console.print(f"Version: {pack.version}")
    console.print(f"Category: {pack.category}")
    console.print(f"Providers: {', '.join(pack.providers)}")
    console.print(f"Standards: {', '.join(pack.standards)}")
    console.print(f"Baseline: {pack.baseline_name or pack.id + '-baseline'}")
    console.print(pack.description)
    for policy in pack.policies:
        console.print(f"- {policy.rule_id} {policy.name} [{policy.severity}]")


@enterprise_pack_app.command("install")
def enterprise_pack_install(
    pack_id: Annotated[str, typer.Argument(help="Built-in pack ID")],
    actor: Annotated[str, typer.Option(help="Installer identity")] = "system",
    no_approve: Annotated[
        bool,
        typer.Option(help="Install policies as draft instead of approved"),
    ] = False,
    no_baseline: Annotated[
        bool,
        typer.Option(help="Do not create an approved baseline for the pack"),
    ] = False,
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    try:
        result = install_policy_pack(
            pack_id,
            actor=actor,
            approve=not no_approve,
            create_baseline=not no_baseline,
        )
    except KeyError as exc:
        console.print(str(exc))
        raise typer.Exit(code=1) from exc
    except Exception as exc:  # noqa: BLE001
        console.print(f"Pack install failed: {exc}")
        raise typer.Exit(code=1) from exc
    _print_model(result, format)


@enterprise_risk_app.command("list")
def enterprise_risk_profile_list(
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    profiles = EnterpriseStore().list_risk_profiles()
    if format == "json":
        console.print(
            JSON(json.dumps([profile.model_dump(mode="json") for profile in profiles], indent=2))
        )
        return
    for profile in profiles:
        console.print(
            f"- {profile.id} {profile.name} "
            f"env={','.join(profile.environments) or 'any'} "
            f"risk={','.join(profile.risk_tiers) or 'any'}"
        )


@enterprise_risk_app.command("show")
def enterprise_risk_profile_show(
    profile_id: Annotated[str, typer.Argument(help="Risk profile ID or name")],
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    try:
        profile = EnterpriseStore().get_risk_profile(profile_id)
    except KeyError as exc:
        console.print(str(exc))
        raise typer.Exit(code=1) from exc
    _print_model(profile, format)


@enterprise_risk_app.command("create")
def enterprise_risk_profile_create(
    name: Annotated[str, typer.Option(help="Risk profile name")],
    environment: Annotated[
        list[str] | None,
        typer.Option(help="Matching environment, repeatable"),
    ] = None,
    risk_tier: Annotated[
        list[str] | None,
        typer.Option(help="Matching risk tier, repeatable"),
    ] = None,
    severity_override: Annotated[
        list[str] | None,
        typer.Option(help="Rule severity override as TG011=high, repeatable"),
    ] = None,
    default_fail_on: Annotated[
        str | None,
        typer.Option(help="Default fail threshold: low, medium, or high"),
    ] = None,
    description: Annotated[str, typer.Option(help="Risk profile description")] = "",
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    try:
        overrides = _parse_severity_overrides(severity_override)
        if default_fail_on and default_fail_on not in {"low", "medium", "high"}:
            raise ValueError("default-fail-on must be low, medium, or high")
        profile = RiskProfile(
            name=name,
            description=description,
            environments=environment or [],
            risk_tiers=risk_tier or [],
            rule_severity_overrides=overrides,
            default_fail_on=default_fail_on,  # type: ignore[arg-type]
        )
        saved = EnterpriseStore().save_risk_profile(profile)
    except Exception as exc:  # noqa: BLE001
        console.print(f"Risk profile create failed: {exc}")
        raise typer.Exit(code=1) from exc
    _print_model(saved, format)


@enterprise_app.command("recommendations")
def enterprise_recommendations(
    rule_id: Annotated[str | None, typer.Option(help="Filter to a single rule ID")] = None,
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    try:
        recommendations = (
            [get_rule_recommendation(rule_id)] if rule_id else list_rule_recommendations()
        )
    except KeyError as exc:
        console.print(str(exc))
        raise typer.Exit(code=1) from exc
    if format == "json":
        console.print(
            JSON(
                json.dumps(
                    [item.model_dump(mode="json") for item in recommendations],
                    indent=2,
                )
            )
        )
        return
    for item in recommendations:
        console.print(f"- {item.rule_id}: {item.suggested_fix}")


@enterprise_app.command("explain")
def enterprise_explain(
    result_id: Annotated[str, typer.Argument(help="Stored evaluation result ID")],
    format: Annotated[str, typer.Option(help="pretty, json, or markdown")] = "pretty",
    output: Annotated[
        Path | None,
        typer.Option(help="Write markdown output to a file"),
    ] = None,
) -> None:
    try:
        report = explain_evaluation(result_id)
    except KeyError as exc:
        console.print(str(exc))
        raise typer.Exit(code=1) from exc
    if format == "markdown":
        content = render_explanation_markdown(report)
        if output:
            output.write_text(content, encoding="utf-8")
            console.print(str(output))
            return
        console.print(content.rstrip())
        return
    if format == "json":
        console.print(JSON(json.dumps(report.model_dump(mode="json"), indent=2)))
        return
    console.print(f"Result: {report.result_id}")
    console.print(f"Decision: {report.decision}")
    console.print(f"Reasons: {'; '.join(report.reasons) or 'none'}")
    if report.risk_profile:
        console.print(f"Risk profile: {report.risk_profile.get('name')}")
    if report.baseline_ids:
        console.print(f"Baselines: {', '.join(report.baseline_ids)}")
    if report.applied_policy_ids:
        console.print(f"Policies: {', '.join(report.applied_policy_ids)}")
    if report.finding_explanations:
        console.print("Findings:")
        for finding in report.finding_explanations:
            console.print(f"- {finding.rule_id} [{finding.severity}] {finding.reason}")
    if report.next_actions:
        console.print("Next actions:")
        for action in report.next_actions:
            console.print(f"- {action}")


@enterprise_app.command("report")
def enterprise_report(
    result_id: Annotated[str, typer.Argument(help="Stored evaluation result ID")],
    format: Annotated[str, typer.Option(help="sarif or junit")] = "sarif",
    output: Annotated[
        Path | None,
        typer.Option(help="Write report output to a file"),
    ] = None,
) -> None:
    if format not in {"sarif", "junit"}:
        console.print("Report format must be sarif or junit.")
        raise typer.Exit(code=2)
    try:
        content = render_evaluation_report(result_id, format=format)  # type: ignore[arg-type]
    except KeyError as exc:
        console.print(str(exc))
        raise typer.Exit(code=1) from exc
    if output:
        output.write_text(content, encoding="utf-8")
        console.print(str(output))
        return
    if format == "sarif":
        console.print(JSON(content))
    else:
        console.print(content)


@enterprise_remediation_app.command("create")
def enterprise_remediation_create(
    result_id: Annotated[str, typer.Argument(help="Stored evaluation result ID")],
    actor: Annotated[str, typer.Option(help="Actor creating the plan")] = "system",
    format: Annotated[str, typer.Option(help="pretty, json, or markdown")] = "pretty",
    output: Annotated[
        Path | None,
        typer.Option(help="Write markdown output to a file"),
    ] = None,
) -> None:
    try:
        plan = create_remediation_plan(result_id, actor=actor)
    except KeyError as exc:
        console.print(str(exc))
        raise typer.Exit(code=1) from exc
    if format == "json":
        console.print(JSON(json.dumps(plan.model_dump(mode="json"), indent=2)))
        return
    if format == "markdown":
        content = render_remediation_markdown(plan)
        if output:
            output.write_text(content, encoding="utf-8")
            console.print(str(output))
            return
        console.print(content.rstrip())
        return
    console.print(f"Remediation plan: {plan.id}")
    console.print(f"Result: {plan.result_id}")
    console.print(f"Actions: {len(plan.actions)} Skipped: {len(plan.skipped)}")
    for action in plan.actions:
        console.print(f"- {action.rule_id} [{action.severity}] {action.suggested_fix}")


@enterprise_remediation_app.command("list")
def enterprise_remediation_list(
    result_id: Annotated[str | None, typer.Option(help="Filter by evaluation result ID")] = None,
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    plans = EnterpriseStore().list_remediation_plans(result_id=result_id)
    if format == "json":
        console.print(JSON(json.dumps([plan.model_dump(mode="json") for plan in plans], indent=2)))
        return
    for plan in plans:
        console.print(
            f"- {plan.id} result={plan.result_id} actions={len(plan.actions)} "
            f"skipped={len(plan.skipped)}"
        )


@enterprise_remediation_app.command("show")
def enterprise_remediation_show(
    plan_id: Annotated[str, typer.Argument(help="Remediation plan ID")],
    format: Annotated[str, typer.Option(help="pretty, json, or markdown")] = "pretty",
    output: Annotated[
        Path | None,
        typer.Option(help="Write markdown output to a file"),
    ] = None,
) -> None:
    try:
        plan = EnterpriseStore().get_remediation_plan(plan_id)
    except KeyError as exc:
        console.print(str(exc))
        raise typer.Exit(code=1) from exc
    if format == "json":
        console.print(JSON(json.dumps(plan.model_dump(mode="json"), indent=2)))
        return
    if format == "markdown":
        content = render_remediation_markdown(plan)
        if output:
            output.write_text(content, encoding="utf-8")
            console.print(str(output))
            return
        console.print(content.rstrip())
        return
    console.print(f"Remediation plan: {plan.id}")
    for action in plan.actions:
        console.print(f"- {action.rule_id} {action.path or 'n/a'}: {action.suggested_fix}")


@enterprise_remediation_app.command("patch-bundle")
def enterprise_remediation_patch_bundle(
    plan_id: Annotated[str, typer.Argument(help="Remediation plan ID")],
    branch_prefix: Annotated[
        str,
        typer.Option(help="Branch prefix for provider-neutral PR metadata"),
    ] = "guardrail/remediate",
    actor: Annotated[str, typer.Option(help="Actor creating the bundle")] = "system",
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    try:
        bundle = create_remediation_patch_bundle(
            plan_id,
            actor=actor,
            branch_prefix=branch_prefix,
        )
    except KeyError as exc:
        console.print(str(exc))
        raise typer.Exit(code=1) from exc
    if format == "json":
        console.print(JSON(json.dumps(bundle.model_dump(mode="json"), indent=2)))
        return
    console.print(f"Patch bundle: {bundle.id}")
    console.print(f"Branch: {bundle.branch_name}")
    console.print(f"Commit: {bundle.commit_message}")
    console.print(f"Artifact directory: {bundle.artifact_dir}")
    for file in bundle.files:
        console.print(f"- {file.path}")


@enterprise_remediation_app.command("patch-bundles")
def enterprise_remediation_patch_bundles(
    plan_id: Annotated[str | None, typer.Option(help="Filter by remediation plan ID")] = None,
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    bundles = EnterpriseStore().list_patch_bundles(plan_id=plan_id)
    if format == "json":
        console.print(
            JSON(json.dumps([bundle.model_dump(mode="json") for bundle in bundles], indent=2))
        )
        return
    for bundle in bundles:
        console.print(
            f"- {bundle.id} plan={bundle.plan_id} branch={bundle.branch_name} "
            f"files={len(bundle.files)}"
        )


@enterprise_app.command("health")
def enterprise_health(
    window: Annotated[str, typer.Option(help="Reporting window label")] = "all",
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    report = governance_health_report(window=window)
    if format == "json":
        console.print(JSON(json.dumps(report.model_dump(mode="json"), indent=2)))
        return
    console.print(f"Governance health: {report.id}")
    console.print(
        f"Evaluations: {report.totals.get('evaluations', 0)} "
        f"Findings: {report.totals.get('findings', 0)} "
        f"Policies: {report.totals.get('policies', 0)}"
    )
    console.print(
        "Decisions: "
        f"pass={report.decisions.get('pass', 0)} "
        f"warn={report.decisions.get('warn', 0)} "
        f"block={report.decisions.get('block', 0)}"
    )
    if report.top_rules:
        console.print("Top rules:")
        for item in report.top_rules:
            console.print(f"- {item['rule_id']}: {item['count']}")
    for signal in report.risk_signals:
        console.print(f"- {signal}")


@enterprise_schedule_app.command("create")
def enterprise_schedule_create(
    name: Annotated[str, typer.Option(help="Scheduled scan name")],
    path: Annotated[Path, typer.Option(help="Terraform path to scan")],
    cadence: Annotated[
        str,
        typer.Option(help="Cadence: hourly, daily, weekly, or monthly"),
    ] = "daily",
    provider: Annotated[str | None, typer.Option(help="Provider context")] = None,
    baseline: Annotated[str | None, typer.Option(help="Baseline ID or name")] = None,
    policy_set: Annotated[str | None, typer.Option(help="Policy set name")] = None,
    fail_on: Annotated[
        str | None,
        typer.Option(help="Block if findings at/above severity: low, medium, high"),
    ] = None,
    context: Annotated[
        list[str] | None,
        typer.Option(help="Evaluation context as key=value, repeatable"),
    ] = None,
    disabled: Annotated[bool, typer.Option(help="Create target disabled")] = False,
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    if cadence not in {"hourly", "daily", "weekly", "monthly"}:
        console.print("Cadence must be hourly, daily, weekly, or monthly.")
        raise typer.Exit(code=2)
    if fail_on and fail_on not in {"low", "medium", "high"}:
        console.print("fail-on must be low, medium, or high.")
        raise typer.Exit(code=2)
    target = ScheduledScanTarget(
        name=name,
        path=str(path),
        cadence=cadence,  # type: ignore[arg-type]
        enabled=not disabled,
        provider=provider,
        baseline=baseline,
        policy_set=policy_set,
        fail_on=fail_on,  # type: ignore[arg-type]
        context=_parse_key_values(context),
    )
    saved = EnterpriseStore().save_scheduled_scan_target(target)
    _print_model(saved, format)


@enterprise_schedule_app.command("list")
def enterprise_schedule_list(
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    targets = EnterpriseStore().list_scheduled_scan_targets()
    if format == "json":
        console.print(
            JSON(json.dumps([target.model_dump(mode="json") for target in targets], indent=2))
        )
        return
    for target in targets:
        console.print(
            f"- {target.id} {target.name} cadence={target.cadence} "
            f"enabled={target.enabled} path={target.path}"
        )


@enterprise_schedule_app.command("run")
def enterprise_schedule_run(
    target_id: Annotated[str, typer.Argument(help="Scheduled scan target ID")],
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    try:
        run = run_scheduled_scan(target_id)
    except KeyError as exc:
        console.print(str(exc))
        raise typer.Exit(code=1) from exc
    _print_model(run, format)
    if run.status == "failed":
        raise typer.Exit(code=1)


@enterprise_schedule_app.command("runs")
def enterprise_schedule_runs(
    target_id: Annotated[str | None, typer.Option(help="Filter by target ID")] = None,
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    runs = EnterpriseStore().list_scheduled_scan_runs(target_id=target_id)
    if format == "json":
        console.print(JSON(json.dumps([run.model_dump(mode="json") for run in runs], indent=2)))
        return
    for run in runs:
        console.print(
            f"- {run.id} target={run.target_id} status={run.status} "
            f"decision={run.decision or 'none'}"
        )


@enterprise_waiver_app.command("create")
def enterprise_waiver_create(
    rule_id: Annotated[str, typer.Option(help="Rule ID to waive, e.g. TG011")],
    reason: Annotated[str, typer.Option(help="Business reason for the exception")],
    owner: Annotated[str, typer.Option(help="Owner accountable for the waiver")],
    expires_at: Annotated[str, typer.Option(help="Expiry timestamp, e.g. 2026-12-31T00:00:00Z")],
    path: Annotated[str | None, typer.Option(help="Optional exact finding path")] = None,
    policy_id: Annotated[str | None, typer.Option(help="Optional enterprise policy ID")] = None,
    target_type: Annotated[
        str | None,
        typer.Option(help="Optional target type: org, group, repo, or app"),
    ] = None,
    target: Annotated[str | None, typer.Option(help="Optional target identifier")] = None,
    requested_by: Annotated[str, typer.Option(help="Requester identity")] = "system",
    approve: Annotated[bool, typer.Option(help="Approve immediately")] = False,
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    try:
        waiver = PolicyWaiver(
            rule_id=rule_id,
            reason=reason,
            owner=owner,
            expires_at=expires_at,
            path=path,
            policy_id=policy_id,
            target_type=target_type,  # type: ignore[arg-type]
            target=target,
            requested_by=requested_by,
        )
        store = EnterpriseStore()
        saved = store.save_waiver(waiver, actor=requested_by)
        if approve:
            saved = store.approve_waiver(saved.id, actor=requested_by)
    except Exception as exc:  # noqa: BLE001
        console.print(f"Waiver create failed: {exc}")
        raise typer.Exit(code=1) from exc
    _print_model(saved, format)


@enterprise_waiver_app.command("list")
def enterprise_waiver_list(
    status: Annotated[str | None, typer.Option(help="Filter by status")] = None,
    rule_id: Annotated[str | None, typer.Option(help="Filter by rule ID")] = None,
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    waivers = EnterpriseStore().list_waivers()
    if status:
        waivers = [waiver for waiver in waivers if waiver.status == status]
    if rule_id:
        waivers = [waiver for waiver in waivers if waiver.rule_id == rule_id]
    if format == "json":
        console.print(
            JSON(json.dumps([waiver.model_dump(mode="json") for waiver in waivers], indent=2))
        )
        return
    for waiver in waivers:
        console.print(
            f"- {waiver.id} {waiver.rule_id} status={waiver.status} "
            f"owner={waiver.owner} expires={waiver.expires_at}"
        )


@enterprise_waiver_app.command("approve")
def enterprise_waiver_approve(
    waiver_id: Annotated[str, typer.Argument(help="Waiver ID")],
    actor: Annotated[str, typer.Option(help="Approver identity")] = "system",
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    try:
        waiver = EnterpriseStore().approve_waiver(waiver_id, actor=actor)
    except KeyError as exc:
        console.print(str(exc))
        raise typer.Exit(code=1) from exc
    _print_model(waiver, format)


@enterprise_waiver_app.command("revoke")
def enterprise_waiver_revoke(
    waiver_id: Annotated[str, typer.Argument(help="Waiver ID")],
    actor: Annotated[str, typer.Option(help="Revoker identity")] = "system",
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    try:
        waiver = EnterpriseStore().revoke_waiver(waiver_id, actor=actor)
    except KeyError as exc:
        console.print(str(exc))
        raise typer.Exit(code=1) from exc
    _print_model(waiver, format)


@enterprise_aws_codepipeline_app.command("init")
def enterprise_aws_codepipeline_init(
    destination: Annotated[
        Path,
        typer.Option(help="Destination directory for generated CodeBuild files"),
    ] = Path("aws-codepipeline-guardrail"),
    terraform_dir: Annotated[
        str,
        typer.Option(help="Terraform directory inside the CodeBuild workspace"),
    ] = ".",
    provider: Annotated[str, typer.Option(help="Provider context for evaluation")] = "aws",
    baseline: Annotated[str, typer.Option(help="Enterprise baseline ID or name")] = "org-baseline",
    evidence_format: Annotated[
        str,
        typer.Option(help="Evidence format: json, csv, or pdf"),
    ] = "json",
    include_apply: Annotated[
        bool,
        typer.Option(help="Include terraform apply in the generated buildspec"),
    ] = False,
    force: Annotated[bool, typer.Option(help="Overwrite generated files if they exist")] = False,
) -> None:
    try:
        scaffold = scaffold_aws_codepipeline(
            destination=destination,
            terraform_dir=terraform_dir,
            provider=provider,
            baseline=baseline,
            evidence_format=evidence_format,  # type: ignore[arg-type]
            include_apply=include_apply,
            force=force,
        )
    except AwsCodePipelineScaffoldError as exc:
        console.print(f"AWS CodePipeline scaffold failed: {exc}")
        raise typer.Exit(code=1) from exc
    console.print(f"Generated: {scaffold.buildspec_path}")
    console.print(f"Generated: {scaffold.readme_path}")


@evidence_app.command("export")
def evidence_export(
    result_id: Annotated[str, typer.Argument(help="Evaluation result ID")],
    format: Annotated[str, typer.Option(help="json, csv, or pdf")] = "json",
) -> None:
    if format not in {"json", "csv", "pdf"}:
        console.print("Evidence format must be json, csv, or pdf.")
        raise typer.Exit(code=2)
    try:
        export = export_evidence(result_id=result_id, format=format)  # type: ignore[arg-type]
    except Exception as exc:  # noqa: BLE001
        console.print(f"Evidence export failed: {exc}")
        raise typer.Exit(code=1) from exc
    console.print(f"Evidence exported: {export.path}")


@enterprise_app.command("drift-check")
def enterprise_drift_check(
    path: Annotated[Path, typer.Argument(help="Path to a Terraform file or directory.")],
    state: Annotated[Path | None, typer.Option(help="Optional path to a .tfstate file.")] = None,
    snapshot_id: Annotated[str, typer.Option(help="Drift snapshot ID")] = "default",
    update_snapshot: Annotated[bool, typer.Option(help="Replace snapshot after check")] = False,
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    try:
        result = check_drift(
            path=path,
            state_path=state,
            snapshot_id=snapshot_id,
            update_snapshot=update_snapshot,
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"Drift check failed: {exc}")
        raise typer.Exit(code=1) from exc
    _print_model(result, format)
    if result.drifted:
        raise typer.Exit(code=1)


@enterprise_app.command("drift-gate")
def enterprise_drift_gate(
    path: Annotated[Path, typer.Argument(help="Path to a Terraform file or directory.")],
    state: Annotated[Path | None, typer.Option(help="Optional path to a .tfstate file.")] = None,
    snapshot_id: Annotated[str, typer.Option(help="Drift snapshot ID")] = "default",
    provider: Annotated[str | None, typer.Option(help="Provider context, e.g. aws")] = None,
    policy_set: Annotated[str | None, typer.Option(help="Named enterprise policy set")] = None,
    baseline: Annotated[str | None, typer.Option(help="Baseline ID or name to resolve")] = None,
    context: Annotated[
        list[str] | None,
        typer.Option(help="Evaluation context as key=value, repeatable"),
    ] = None,
    fail_on: Annotated[
        str | None,
        typer.Option(help="Block if findings at/above severity: low, medium, high"),
    ] = None,
    update_snapshot: Annotated[bool, typer.Option(help="Replace snapshot after gate")] = False,
    no_create_snapshot: Annotated[
        bool,
        typer.Option(help="Block if the drift snapshot does not exist"),
    ] = False,
    evidence_format: Annotated[
        str | None,
        typer.Option(help="Optional evidence export format: json, csv, or pdf"),
    ] = None,
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
) -> None:
    if evidence_format and evidence_format not in {"json", "csv", "pdf"}:
        console.print("Evidence format must be json, csv, or pdf.")
        raise typer.Exit(code=2)
    try:
        result = run_drift_gate(
            path=path,
            state_path=state,
            snapshot_id=snapshot_id,
            provider=provider,
            policy_set=policy_set,
            baseline=baseline,
            context=_parse_key_values(context),
            fail_on=fail_on.lower() if fail_on else None,
            update_snapshot=update_snapshot,
            create_snapshot=not no_create_snapshot,
            export_format=evidence_format,  # type: ignore[arg-type]
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"Drift gate failed: {exc}")
        raise typer.Exit(code=1) from exc
    if format == "json":
        console.print(JSON(json.dumps(result.model_dump(mode="json"), indent=2)))
    else:
        console.print(f"Drift gate: {result.id}")
        console.print(f"Decision: {result.decision}")
        console.print(f"Evaluation: {result.evaluation.id} ({result.evaluation.decision})")
        console.print(f"Drift: {result.drift.status} drifted={result.drift.drifted}")
        if result.evidence:
            console.print(f"Evidence: {result.evidence.path}")
        if result.reasons:
            console.print(f"Reasons: {', '.join(result.reasons)}")
    if result.decision == "block":
        raise typer.Exit(code=1)


def main() -> None:
    app()


def _maybe_fail(summary, level: str) -> None:
    if level not in {"low", "medium", "high"}:
        console.print("Invalid fail-on severity. Use low, medium, or high.")
        raise typer.Exit(code=2)
    if level == "high" and summary.high > 0:
        raise typer.Exit(code=1)
    if level == "medium" and (summary.high + summary.medium) > 0:
        raise typer.Exit(code=1)
    if level == "low" and summary.findings > 0:
        raise typer.Exit(code=1)


def _parse_key_values(values: list[str] | None) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for item in values or []:
        if "=" not in item:
            raise ValueError(f"Context values must use key=value: {item}")
        key, value = item.split("=", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def _parse_severity_overrides(values: list[str] | None) -> dict[str, str]:
    overrides: dict[str, str] = {}
    for item in values or []:
        if "=" not in item:
            raise ValueError(f"Severity overrides must use RULE_ID=severity: {item}")
        rule_id, severity = item.split("=", 1)
        severity = severity.strip().lower()
        if severity not in {"low", "medium", "high"}:
            raise ValueError(f"Invalid severity override for {rule_id}: {severity}")
        overrides[rule_id.strip()] = severity
    return overrides


def _print_model(model, format: str) -> None:
    payload = model.model_dump(mode="json")
    if format == "json":
        console.print(JSON(json.dumps(payload, indent=2)))
        return
    for key, value in payload.items():
        console.print(f"{key}: {value}")


if __name__ == "__main__":
    main()

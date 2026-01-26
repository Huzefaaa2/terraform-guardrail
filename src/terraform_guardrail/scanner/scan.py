from __future__ import annotations

import json
import os
from collections.abc import Iterable
from pathlib import Path

import hcl2

from terraform_guardrail.scanner.models import Finding, ScanReport, ScanSummary
from terraform_guardrail.scanner.policy_eval import (
    PolicyEvalError,
    PolicyInputFile,
    evaluate_policy_layers,
)
from terraform_guardrail.scanner.rules import RULES, SENSITIVE_ASSIGN_RE, SENSITIVE_NAME_RE
from terraform_guardrail.schema import (
    SchemaError,
    allowed_keys,
    iter_resource_blocks,
    load_provider_schema,
)

TERRAFORM_EXTS = {".tf", ".tfvars", ".hcl"}


def scan_path(
    path: Path | str,
    state_path: Path | str | None = None,
    use_schema: bool = False,
    policy_bundle: str | None = None,
    policy_layers: list[str] | None = None,
    policy_base: str | None = None,
    policy_env: str | None = None,
    policy_app: str | None = None,
    policy_registry: str | None = None,
    policy_query: str | None = None,
) -> ScanReport:
    path = Path(path)
    state_path = Path(state_path) if state_path else None
    if not path.exists():
        raise FileNotFoundError(f"Path not found: {path}")
    schema = None
    if use_schema:
        workdir = path if path.is_dir() else path.parent
        try:
            schema = load_provider_schema(workdir)
        except SchemaError as exc:
            raise RuntimeError(f"Schema load failed: {exc}") from exc
    report = ScanReport.empty(path)
    findings: list[Finding] = []
    scanned_files = 0
    policy_inputs: list[PolicyInputFile] = []
    policy_state: dict | None = None

    paths = _expand_paths(path)
    for file_path in paths:
        if file_path.suffix not in TERRAFORM_EXTS:
            continue
        scanned_files += 1
        file_findings, hcl_data = _scan_hcl_file(file_path, schema)
        findings.extend(file_findings)
        if hcl_data is not None:
            policy_inputs.append(PolicyInputFile(path=str(file_path), hcl=hcl_data))

    if state_path:
        if not state_path.exists():
            raise FileNotFoundError(f"State file not found: {state_path}")
        state_findings, state_data = _scan_state_file(state_path)
        findings.extend(state_findings)
        policy_state = state_data

    bundle_ids, layer_names = _resolve_policy_layers(
        policy_bundle=policy_bundle,
        policy_layers=policy_layers,
        policy_base=policy_base,
        policy_env=policy_env,
        policy_app=policy_app,
    )
    if bundle_ids:
        try:
            findings.extend(
                evaluate_policy_layers(
                    bundle_ids=bundle_ids,
                    layer_names=layer_names,
                    registry_url=policy_registry,
                    files=policy_inputs,
                    state=policy_state,
                    policy_query=policy_query,
                )
            )
        except PolicyEvalError as exc:
            findings.append(
                Finding(
                    rule_id="OPA_EVAL",
                    severity="low",
                    message=f"Policy evaluation failed: {exc}",
                    path=str(path),
                )
            )

    report.findings = findings
    report.summary = _build_summary(scanned_files, findings)
    return report


def _expand_paths(path: Path) -> Iterable[Path]:
    if path.is_dir():
        return path.rglob("*")
    return [path]


def _resolve_policy_layers(
    policy_bundle: str | None,
    policy_layers: list[str] | None,
    policy_base: str | None,
    policy_env: str | None,
    policy_app: str | None,
) -> tuple[list[str], list[str]]:
    layers: list[str] = []
    layer_names: list[str] = []

    if policy_base or policy_env or policy_app:
        if policy_base:
            layers.append(policy_base)
            layer_names.append("base")
        if policy_env:
            layers.append(policy_env)
            layer_names.append("env")
        if policy_app:
            layers.append(policy_app)
            layer_names.append("app")
        return layers, layer_names

    if policy_layers:
        for idx, bundle in enumerate(policy_layers):
            if bundle:
                layers.append(bundle)
                layer_names.append(f"layer{idx + 1}")
        if layers:
            return layers, layer_names

    env_base = os.getenv("GUARDRAIL_POLICY_BASE")
    env_env = os.getenv("GUARDRAIL_POLICY_ENV")
    env_app = os.getenv("GUARDRAIL_POLICY_APP")
    if env_base or env_env or env_app:
        if env_base:
            layers.append(env_base)
            layer_names.append("base")
        if env_env:
            layers.append(env_env)
            layer_names.append("env")
        if env_app:
            layers.append(env_app)
            layer_names.append("app")
        return layers, layer_names

    env_layers = os.getenv("GUARDRAIL_POLICY_LAYERS")
    if env_layers:
        for idx, bundle in enumerate(_split_policy_bundles(env_layers)):
            layers.append(bundle)
            layer_names.append(f"layer{idx + 1}")
        return layers, layer_names

    bundle_id = policy_bundle or os.getenv("GUARDRAIL_POLICY_BUNDLE_ID")
    if bundle_id:
        layers = _split_policy_bundles(bundle_id)
        layer_names = [f"layer{idx + 1}" for idx in range(len(layers))]
        return layers, layer_names

    return [], []


def _split_policy_bundles(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _scan_hcl_file(path: Path, schema: dict | None) -> tuple[list[Finding], dict | None]:
    findings: list[Finding] = []
    content = path.read_text(encoding="utf-8")

    for match in SENSITIVE_ASSIGN_RE.finditer(content):
        findings.append(
            Finding(
                rule_id="TG002",
                severity="high",
                message=RULES["TG002"],
                path=str(path),
                detail={
                    "key": match.group(1),
                    "recommendation": "Move secrets to variables or secret managers.",
                },
            )
        )

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = hcl2.load(handle)
    except Exception as exc:  # noqa: BLE001
        findings.append(
            Finding(
                rule_id="TG004",
                severity="low",
                message=f"{RULES['TG004']}: {exc}",
                path=str(path),
            )
        )
        return findings, None

    variables = data.get("variable", [])
    for block in variables:
        for name, attrs in block.items():
            if not isinstance(attrs, dict):
                continue
            if attrs.get("sensitive") is True and attrs.get("ephemeral") is not True:
                findings.append(
                    Finding(
                        rule_id="TG001",
                        severity="medium",
                        message=f"{RULES['TG001']}: {name}",
                        path=str(path),
                        detail={"recommendation": "Add ephemeral = true to this variable."},
                    )
                )

    if path.suffix == ".tfvars":
        for key in data.keys():
            if SENSITIVE_NAME_RE.search(key):
                findings.append(
                    Finding(
                        rule_id="TG002",
                        severity="high",
                        message=f"{RULES['TG002']}: {key}",
                        path=str(path),
                        detail={"recommendation": "Avoid hardcoding secrets in tfvars."},
                    )
                )

    if schema:
        findings.extend(_schema_findings(data, schema, path))

    return findings, data


def _scan_state_file(path: Path) -> tuple[list[Finding], dict | None]:
    findings: list[Finding] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        findings.append(
            Finding(
                rule_id="TG003",
                severity="low",
                message=f"Invalid state JSON: {exc}",
                path=str(path),
            )
        )
        return findings, None

    for resource in data.get("resources", []):
        for instance in resource.get("instances", []) or []:
            attrs = instance.get("attributes", {}) or {}
            for key, value in attrs.items():
                if value is None:
                    continue
                if SENSITIVE_NAME_RE.search(key):
                    findings.append(
                        Finding(
                            rule_id="TG003",
                            severity="high",
                            message=f"{RULES['TG003']}: {key}",
                            path=str(path),
                            detail={
                                "resource": resource.get("name"),
                                "recommendation": (
                                    "Use ephemeral or write-only values to keep secrets out of "
                                    "state."
                                ),
                            },
                        )
                    )

    return findings, data


def _schema_findings(hcl_data: dict, schema: dict, path: Path) -> list[Finding]:
    findings: list[Finding] = []
    for resource_type, attributes in iter_resource_blocks(hcl_data):
        allowed = allowed_keys(schema, resource_type)
        if not allowed:
            continue
        for key in attributes.keys():
            if key in allowed:
                continue
            findings.append(
                Finding(
                    rule_id="TG005",
                    severity="medium",
                    message=f"{RULES['TG005']}: {resource_type}.{key}",
                    path=str(path),
                    detail={
                        "recommendation": "Verify the attribute name against provider schema.",
                    },
                )
            )
    return findings


def _build_summary(scanned_files: int, findings: list[Finding]) -> ScanSummary:
    summary = ScanSummary(scanned_files=scanned_files, findings=len(findings))
    for finding in findings:
        if finding.severity == "high":
            summary.high += 1
        elif finding.severity == "medium":
            summary.medium += 1
        else:
            summary.low += 1
    return summary

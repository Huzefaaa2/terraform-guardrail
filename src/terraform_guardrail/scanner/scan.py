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
PUBLIC_ACLS = {"public-read", "public-read-write"}
PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}
DEFAULT_REQUIRED_TAGS = ["owner", "environment", "cost_center"]


def scan_path(
    path: Path | str,
    state_path: Path | str | None = None,
    use_schema: bool = False,
    policy_bundle: str | None = None,
    policy_bundle_path: Path | str | None = None,
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

    if policy_bundle_path:
        bundle_path = Path(policy_bundle_path)
        if not bundle_path.exists():
            raise FileNotFoundError(f"Policy bundle not found: {bundle_path}")
        if policy_bundle or policy_layers or policy_base or policy_env or policy_app:
            raise ValueError("Use --policy-bundle-path without other policy bundle flags.")
        try:
            findings.extend(
                evaluate_policy_layers(
                    bundle_ids=[],
                    registry_url=policy_registry,
                    files=policy_inputs,
                    state=policy_state,
                    policy_query=policy_query,
                    layer_names=[],
                    bundle_paths=[bundle_path],
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

    findings.extend(_resource_findings(data, path))

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


def _resource_findings(hcl_data: dict, path: Path) -> list[Finding]:
    findings: list[Finding] = []
    required_tags = _load_csv_env("GUARDRAIL_REQUIRED_TAGS") or DEFAULT_REQUIRED_TAGS
    allowed_regions = _load_csv_env("GUARDRAIL_ALLOWED_REGIONS")
    blocked_regions = _load_csv_env("GUARDRAIL_BLOCKED_REGIONS")
    allowed_instance_types = _load_csv_env("GUARDRAIL_ALLOWED_INSTANCE_TYPES")
    allowed_skus = _load_csv_env("GUARDRAIL_ALLOWED_SKUS")

    for resource_type, name, attrs in _iter_resources(hcl_data):
        resource_id = f"{resource_type}.{name}"

        if resource_type == "aws_s3_bucket":
            acl = _string_value(attrs.get("acl"))
            if acl and acl.lower() in PUBLIC_ACLS:
                findings.append(
                    Finding(
                        rule_id="TG006",
                        severity="high",
                        message=f"{RULES['TG006']}: {resource_id}",
                        path=str(path),
                        detail={"recommendation": "Remove public ACLs and use bucket policies."},
                    )
                )
            if "server_side_encryption_configuration" not in attrs:
                findings.append(
                    Finding(
                        rule_id="TG011",
                        severity="medium",
                        message=f"{RULES['TG011']}: {resource_id}",
                        path=str(path),
                        detail={"recommendation": "Enable default SSE with KMS or AES256."},
                    )
                )

        if resource_type == "aws_s3_bucket_public_access_block":
            if _s3_public_block_disabled(attrs):
                findings.append(
                    Finding(
                        rule_id="TG007",
                        severity="high",
                        message=f"{RULES['TG007']}: {resource_id}",
                        path=str(path),
                        detail={"recommendation": "Enable all public access block flags."},
                    )
                )

        if resource_type in {"aws_security_group", "aws_security_group_rule"}:
            if _security_group_is_public(resource_type, attrs):
                findings.append(
                    Finding(
                        rule_id="TG008",
                        severity="high",
                        message=f"{RULES['TG008']}: {resource_id}",
                        path=str(path),
                        detail={"recommendation": "Restrict ingress CIDRs to approved ranges."},
                    )
                )

        if resource_type in {"aws_iam_policy", "aws_iam_role_policy"}:
            if _iam_policy_is_wildcard(attrs):
                findings.append(
                    Finding(
                        rule_id="TG009",
                        severity="high",
                        message=f"{RULES['TG009']}: {resource_id}",
                        path=str(path),
                        detail={"recommendation": "Scope IAM actions/resources explicitly."},
                    )
                )

        if resource_type == "aws_instance":
            if _truthy(attrs.get("associate_public_ip_address")):
                findings.append(
                    Finding(
                        rule_id="TG010",
                        severity="medium",
                        message=f"{RULES['TG010']}: {resource_id}",
                        path=str(path),
                        detail={
                            "recommendation": "Remove public IP association for private hosts."
                        },
                    )
                )
            if "subnet_id" not in attrs:
                findings.append(
                    Finding(
                        rule_id="TG014",
                        severity="low",
                        message=f"{RULES['TG014']}: {resource_id}",
                        path=str(path),
                        detail={"recommendation": "Attach to an explicit subnet/VPC boundary."},
                    )
                )

        if resource_type in {"aws_db_instance", "aws_rds_cluster"}:
            if not _truthy(attrs.get("storage_encrypted")):
                findings.append(
                    Finding(
                        rule_id="TG012",
                        severity="medium",
                        message=f"{RULES['TG012']}: {resource_id}",
                        path=str(path),
                        detail={"recommendation": "Enable storage_encrypted and KMS keys."},
                    )
                )
            if _truthy(attrs.get("publicly_accessible")):
                findings.append(
                    Finding(
                        rule_id="TG015",
                        severity="high",
                        message=f"{RULES['TG015']}: {resource_id}",
                        path=str(path),
                        detail={"recommendation": "Disable publicly_accessible for databases."},
                    )
                )

        if resource_type in {"aws_lb_listener", "aws_alb_listener"}:
            protocol = _string_value(attrs.get("protocol"))
            if protocol and protocol.upper() == "HTTP":
                findings.append(
                    Finding(
                        rule_id="TG013",
                        severity="medium",
                        message=f"{RULES['TG013']}: {resource_id}",
                        path=str(path),
                        detail={"recommendation": "Use HTTPS listeners with TLS certificates."},
                    )
                )

        if resource_type == "aws_ebs_volume":
            if not _truthy(attrs.get("encrypted")):
                findings.append(
                    Finding(
                        rule_id="TG020",
                        severity="medium",
                        message=f"{RULES['TG020']}: {resource_id}",
                        path=str(path),
                        detail={"recommendation": "Enable encrypted volumes with KMS."},
                    )
                )

        if resource_type == "azurerm_storage_account":
            if _truthy(attrs.get("public_network_access_enabled")):
                findings.append(
                    Finding(
                        rule_id="TG019",
                        severity="medium",
                        message=f"{RULES['TG019']}: {resource_id}",
                        path=str(path),
                        detail={
                            "recommendation": (
                                "Disable public network access or use private endpoints."
                            )
                        },
                    )
                )

        missing_tags = _missing_required_tags(attrs, required_tags)
        if missing_tags:
            findings.append(
                Finding(
                    rule_id="TG016",
                    severity="low",
                    message=f"{RULES['TG016']}: {resource_id}",
                    path=str(path),
                    detail={"missing_tags": missing_tags},
                )
            )

        if allowed_regions or blocked_regions:
            for key in ("region", "location"):
                value = _string_value(attrs.get(key))
                if not value:
                    continue
                if allowed_regions and value not in allowed_regions:
                    findings.append(
                        Finding(
                            rule_id="TG017",
                            severity="medium",
                            message=f"{RULES['TG017']}: {resource_id}",
                            path=str(path),
                            detail={"value": value, "allowed": allowed_regions},
                        )
                    )
                    break
                if blocked_regions and value in blocked_regions:
                    findings.append(
                        Finding(
                            rule_id="TG017",
                            severity="medium",
                            message=f"{RULES['TG017']}: {resource_id}",
                            path=str(path),
                            detail={"value": value, "blocked": blocked_regions},
                        )
                    )
                    break

        if allowed_instance_types or allowed_skus:
            instance_type = _string_value(attrs.get("instance_type"))
            if (
                instance_type
                and allowed_instance_types
                and instance_type not in allowed_instance_types
            ):
                findings.append(
                    Finding(
                        rule_id="TG018",
                        severity="medium",
                        message=f"{RULES['TG018']}: {resource_id}",
                        path=str(path),
                        detail={"value": instance_type, "allowed": allowed_instance_types},
                    )
                )
            sku = _string_value(attrs.get("vm_size") or attrs.get("sku"))
            if sku and allowed_skus and sku not in allowed_skus:
                findings.append(
                    Finding(
                        rule_id="TG018",
                        severity="medium",
                        message=f"{RULES['TG018']}: {resource_id}",
                        path=str(path),
                        detail={"value": sku, "allowed": allowed_skus},
                    )
                )

    return findings


def _iter_resources(hcl_data: dict) -> Iterable[tuple[str, str, dict]]:
    for block in hcl_data.get("resource", []) or []:
        if not isinstance(block, dict):
            continue
        for resource_type, instances in block.items():
            if not isinstance(instances, dict):
                continue
            for name, attrs in instances.items():
                if isinstance(attrs, dict):
                    yield resource_type, name, attrs


def _as_list(value: object) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _string_value(value: object) -> str | None:
    if isinstance(value, str):
        return value
    return None


def _truthy(value: object) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "1", "enabled"}
    return False


def _load_csv_env(name: str) -> list[str]:
    value = os.getenv(name, "")
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _s3_public_block_disabled(attrs: dict) -> bool:
    keys = [
        "block_public_acls",
        "block_public_policy",
        "ignore_public_acls",
        "restrict_public_buckets",
    ]
    for key in keys:
        value = attrs.get(key)
        if value is False or (isinstance(value, str) and value.lower() == "false"):
            return True
    return False


def _security_group_is_public(resource_type: str, attrs: dict) -> bool:
    if resource_type == "aws_security_group_rule":
        if attrs.get("type") != "ingress":
            return False
        cidrs = _as_list(attrs.get("cidr_blocks")) + _as_list(attrs.get("ipv6_cidr_blocks"))
        return any(str(cidr) in PUBLIC_CIDRS for cidr in cidrs)

    for ingress in _as_list(attrs.get("ingress")):
        if not isinstance(ingress, dict):
            continue
        cidrs = _as_list(ingress.get("cidr_blocks")) + _as_list(ingress.get("ipv6_cidr_blocks"))
        if any(str(cidr) in PUBLIC_CIDRS for cidr in cidrs):
            return True
    return False


def _iam_policy_is_wildcard(attrs: dict) -> bool:
    policy = attrs.get("policy")
    if isinstance(policy, str):
        text = policy.replace(" ", "")
        return "\"Action\":\"*\"" in text or "\"Resource\":\"*\"" in text
    if isinstance(policy, dict):
        statements = policy.get("Statement") or []
        for statement in _as_list(statements):
            if not isinstance(statement, dict):
                continue
            actions = _as_list(statement.get("Action"))
            resources = _as_list(statement.get("Resource"))
            if "*" in actions or "*" in resources:
                return True
    return False


def _missing_required_tags(attrs: dict, required: list[str]) -> list[str]:
    if not required:
        return []
    tags = attrs.get("tags")
    if not isinstance(tags, dict):
        tags = attrs.get("tags_all") if isinstance(attrs.get("tags_all"), dict) else {}
    missing = [tag for tag in required if tag not in tags]
    return missing


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

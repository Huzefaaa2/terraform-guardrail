from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from terraform_guardrail.policy_registry import (
    PolicyBundle,
    download_bundle,
    get_policy_bundle,
)
from terraform_guardrail.scanner.models import Finding

DEFAULT_POLICY_QUERY = "data.guardrail.baseline.deny"


class PolicyEvalError(RuntimeError):
    pass


@dataclass(frozen=True)
class PolicyInputFile:
    path: str
    hcl: dict[str, Any]


def evaluate_policy_bundle(
    bundle_id: str,
    registry_url: str | None,
    files: list[PolicyInputFile],
    state: dict[str, Any] | None,
    policy_query: str | None = None,
) -> list[Finding]:
    bundle = get_policy_bundle(bundle_id, registry_url)
    query = policy_query or bundle.entrypoint or DEFAULT_POLICY_QUERY

    opa_path = shutil.which("opa")
    if not opa_path:
        raise PolicyEvalError("OPA CLI not found. Install OPA to evaluate policy bundles.")

    input_payload = {
        "files": [{"path": file.path, "hcl": file.hcl} for file in files],
        "state": state,
    }

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_dir_path = Path(tmp_dir)
        input_path = tmp_dir_path / "input.json"
        input_path.write_text(json.dumps(input_payload), encoding="utf-8")

        bundle_dir = download_bundle(bundle, tmp_dir_path / "bundles")

        cmd = [
            opa_path,
            "eval",
            "--format=json",
            "--input",
            str(input_path),
            "--bundle",
            str(bundle_dir),
            query,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise PolicyEvalError(result.stderr.strip())

    return _parse_opa_output(result.stdout, bundle)


def evaluate_policy_layers(
    bundle_ids: list[str],
    registry_url: str | None,
    files: list[PolicyInputFile],
    state: dict[str, Any] | None,
    policy_query: str | None = None,
    layer_names: list[str] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    names = layer_names or []
    for idx, bundle_id in enumerate(bundle_ids):
        layer = names[idx] if idx < len(names) else None
        layer_findings = evaluate_policy_bundle(
            bundle_id=bundle_id,
            registry_url=registry_url,
            files=files,
            state=state,
            policy_query=policy_query,
        )
        for finding in layer_findings:
            detail = finding.detail or {}
            detail.setdefault("bundle", bundle_id)
            if layer:
                detail.setdefault("layer", layer)
            finding.detail = detail
        findings.extend(layer_findings)
    return findings


def _parse_opa_output(output: str, bundle: PolicyBundle) -> list[Finding]:
    try:
        payload = json.loads(output)
    except json.JSONDecodeError as exc:  # noqa: PERF203
        raise PolicyEvalError(f"OPA output is not valid JSON: {exc}") from exc

    results = payload.get("result") or []
    if not results:
        return []

    expressions = results[0].get("expressions") or []
    if not expressions:
        return []

    value = expressions[0].get("value")
    if not value:
        return []

    findings: list[Finding] = []
    if isinstance(value, list):
        for entry in value:
            findings.append(_finding_from_value(entry, bundle))
        return findings

    findings.append(_finding_from_value(value, bundle))
    return findings


def _finding_from_value(value: Any, bundle: PolicyBundle) -> Finding:
    if isinstance(value, dict):
        message = value.get("message") or "Policy violation"
        severity = value.get("severity") or "medium"
        rule_id = value.get("rule_id") or f"OPA_{bundle.bundle_id.upper()}"
        path = value.get("path") or "policy"
        detail = value.get("detail")
        return Finding(
            rule_id=rule_id,
            severity=severity,
            message=message,
            path=path,
            detail=detail,
        )

    if isinstance(value, str):
        return Finding(
            rule_id=f"OPA_{bundle.bundle_id.upper()}",
            severity="medium",
            message=value,
            path="policy",
        )

    return Finding(
        rule_id=f"OPA_{bundle.bundle_id.upper()}",
        severity="medium",
        message=str(value),
        path="policy",
    )

from __future__ import annotations

from types import SimpleNamespace

from terraform_guardrail.policy_registry import PolicyBundle
from terraform_guardrail.scanner.policy_eval import (
    PolicyEvalError,
    PolicyInputFile,
    evaluate_policy_bundle,
)


def test_policy_eval_parses_findings(monkeypatch, tmp_path) -> None:
    bundle = PolicyBundle(
        bundle_id="baseline",
        title="Baseline",
        description="Test bundle",
        version="0.1.0",
        url="http://registry.local/bundles/baseline.tar.gz",
        sha256=None,
        entrypoint="data.guardrail.baseline.deny",
    )

    monkeypatch.setattr(
        "terraform_guardrail.scanner.policy_eval.get_policy_bundle",
        lambda *_: bundle,
    )
    monkeypatch.setattr(
        "terraform_guardrail.scanner.policy_eval.download_bundle",
        lambda *_: tmp_path,
    )
    monkeypatch.setattr(
        "terraform_guardrail.scanner.policy_eval.shutil.which",
        lambda _: "/usr/bin/opa",
    )

    def fake_run(*_args, **_kwargs):
        output = (
            '{"result":[{"expressions":[{"value":[{"message":"Policy hit",'
            '"severity":"high","rule_id":"OPA001","path":"main.tf"}]}]}]}'
        )
        return SimpleNamespace(returncode=0, stdout=output, stderr="")

    monkeypatch.setattr("terraform_guardrail.scanner.policy_eval.subprocess.run", fake_run)

    findings = evaluate_policy_bundle(
        bundle_id="baseline",
        registry_url=None,
        files=[PolicyInputFile(path="main.tf", hcl={"variable": []})],
        state=None,
        policy_query=None,
    )
    assert findings[0].rule_id == "OPA001"
    assert findings[0].severity == "high"


def test_policy_eval_failure(monkeypatch, tmp_path) -> None:
    bundle = PolicyBundle(
        bundle_id="baseline",
        title="Baseline",
        description="Test bundle",
        version="0.1.0",
        url="http://registry.local/bundles/baseline.tar.gz",
        sha256=None,
        entrypoint="data.guardrail.baseline.deny",
    )

    monkeypatch.setattr(
        "terraform_guardrail.scanner.policy_eval.get_policy_bundle",
        lambda *_: bundle,
    )
    monkeypatch.setattr(
        "terraform_guardrail.scanner.policy_eval.download_bundle",
        lambda *_: tmp_path,
    )
    monkeypatch.setattr(
        "terraform_guardrail.scanner.policy_eval.shutil.which",
        lambda _: "/usr/bin/opa",
    )

    def fake_run(*_args, **_kwargs):
        return SimpleNamespace(returncode=1, stdout="", stderr="bad policy")

    monkeypatch.setattr("terraform_guardrail.scanner.policy_eval.subprocess.run", fake_run)

    try:
        evaluate_policy_bundle(
            bundle_id="baseline",
            registry_url=None,
            files=[],
            state=None,
            policy_query=None,
        )
    except PolicyEvalError as exc:
        assert "bad policy" in str(exc)

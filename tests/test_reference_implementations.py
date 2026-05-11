from __future__ import annotations

from pathlib import Path

REFERENCE_FILES = [
    Path("examples/github-actions/guardrails-service-v3.yml"),
    Path("examples/gitlab-ci/service-v3.gitlab-ci.yml"),
    Path("examples/azure-devops/service-v3.yml"),
    Path("examples/aws-codepipeline/buildspec-service-v3.yml"),
]


def test_v3_reference_implementations_use_service_contract() -> None:
    for path in REFERENCE_FILES:
        text = path.read_text(encoding="utf-8")

        assert "/service/evaluate" in text
        assert "aws-control-tower" in text
        assert "request_id" in text
        assert "evidence_format" in text
        assert "guardrail-service-response.json" in text

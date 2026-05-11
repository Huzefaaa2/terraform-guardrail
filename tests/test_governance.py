from __future__ import annotations

from pathlib import Path


def test_governance_files_exist_and_reference_roadmap() -> None:
    required = [
        Path("CONTRIBUTING.md"),
        Path("CODE_OF_CONDUCT.md"),
        Path("SECURITY.md"),
        Path(".github/PULL_REQUEST_TEMPLATE.md"),
        Path(".github/ROADMAP.yml"),
        Path(".github/ISSUE_TEMPLATE/bug_report.yml"),
        Path(".github/ISSUE_TEMPLATE/feature_request.yml"),
        Path(".github/ISSUE_TEMPLATE/policy_pack.yml"),
    ]

    for path in required:
        assert path.exists(), f"missing governance file: {path}"

    contributing = Path("CONTRIBUTING.md").read_text(encoding="utf-8")
    roadmap = Path(".github/ROADMAP.yml").read_text(encoding="utf-8")

    assert "v3-ecosystem" in contributing
    assert "v4-intelligent" in contributing
    assert "Contributor governance + public roadmap" in roadmap

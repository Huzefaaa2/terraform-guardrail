from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from terraform_guardrail.aws_codepipeline import (
    AwsCodePipelineScaffoldError,
    scaffold_aws_codepipeline,
)
from terraform_guardrail.cli.app import app


def test_scaffold_aws_codepipeline_generates_buildspec_and_readme(tmp_path: Path) -> None:
    scaffold = scaffold_aws_codepipeline(
        destination=tmp_path / "aws",
        terraform_dir="infra",
        baseline="prod-baseline",
        evidence_format="pdf",
    )

    buildspec = scaffold.buildspec_path.read_text(encoding="utf-8")
    readme = scaffold.readme_path.read_text(encoding="utf-8")
    assert "GUARDRAIL_TERRAFORM_DIR: infra" in buildspec
    assert "GUARDRAIL_BASELINE: prod-baseline" in buildspec
    assert "GUARDRAIL_EVIDENCE_FORMAT: pdf" in buildspec
    assert "terraform-guardrail enterprise drift-gate" in buildspec
    assert "--evidence-format \"$GUARDRAIL_EVIDENCE_FORMAT\"" in buildspec
    assert "guardrail-evidence.pdf" in buildspec
    assert "CodeBuild guardrail-only stage" in readme


def test_scaffold_aws_codepipeline_refuses_overwrite_without_force(tmp_path: Path) -> None:
    destination = tmp_path / "aws"
    scaffold_aws_codepipeline(destination=destination)

    try:
        scaffold_aws_codepipeline(destination=destination)
    except AwsCodePipelineScaffoldError as exc:
        assert "Refusing to overwrite" in str(exc)
    else:
        raise AssertionError("Expected overwrite protection.")


def test_cli_aws_codepipeline_init(tmp_path: Path) -> None:
    runner = CliRunner()
    destination = tmp_path / "aws"

    result = runner.invoke(
        app,
        [
            "enterprise",
            "aws",
            "codepipeline",
            "init",
            "--destination",
            str(destination),
            "--terraform-dir",
            "infra",
            "--baseline",
            "prod-baseline",
            "--evidence-format",
            "pdf",
        ],
    )

    assert result.exit_code == 0
    assert (destination / "buildspec-guardrail.yml").exists()
    assert (destination / "README.md").exists()
    assert "Generated:" in result.stdout

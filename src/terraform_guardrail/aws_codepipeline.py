from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal


class AwsCodePipelineScaffoldError(RuntimeError):
    pass


@dataclass(frozen=True)
class AwsCodePipelineScaffold:
    destination: Path
    buildspec_path: Path
    readme_path: Path


def scaffold_aws_codepipeline(
    destination: Path | str,
    terraform_dir: str = ".",
    provider: str = "aws",
    baseline: str = "org-baseline",
    evidence_format: Literal["json", "csv", "pdf"] = "json",
    include_apply: bool = False,
    force: bool = False,
) -> AwsCodePipelineScaffold:
    if evidence_format not in {"json", "csv", "pdf"}:
        raise AwsCodePipelineScaffoldError("Evidence format must be json, csv, or pdf.")

    destination = Path(destination)
    buildspec_path = destination / "buildspec-guardrail.yml"
    readme_path = destination / "README.md"
    if not force:
        existing = [path for path in (buildspec_path, readme_path) if path.exists()]
        if existing:
            names = ", ".join(str(path) for path in existing)
            raise AwsCodePipelineScaffoldError(f"Refusing to overwrite existing files: {names}")

    destination.mkdir(parents=True, exist_ok=True)
    buildspec_path.write_text(
        render_buildspec(
            terraform_dir=terraform_dir,
            provider=provider,
            baseline=baseline,
            evidence_format=evidence_format,
            include_apply=include_apply,
        ),
        encoding="utf-8",
    )
    readme_path.write_text(
        render_readme(
            terraform_dir=terraform_dir,
            provider=provider,
            baseline=baseline,
            evidence_format=evidence_format,
            include_apply=include_apply,
        ),
        encoding="utf-8",
    )
    return AwsCodePipelineScaffold(
        destination=destination,
        buildspec_path=buildspec_path,
        readme_path=readme_path,
    )


def render_buildspec(
    terraform_dir: str,
    provider: str,
    baseline: str,
    evidence_format: Literal["json", "csv", "pdf"],
    include_apply: bool,
) -> str:
    evidence_file = f"guardrail-evidence.{evidence_format}"
    copy_command = _copy_evidence_command(evidence_format, evidence_file)
    build_commands = ["      - echo \"Guardrail gate complete. Add apply in a later stage.\""]
    if include_apply:
        build_commands = [
            f"      - cd {terraform_dir}",
            "      - terraform apply -auto-approve tfplan",
        ]

    return "\n".join(
        [
            "version: 0.2",
            "",
            "env:",
            "  variables:",
            f"    GUARDRAIL_TERRAFORM_DIR: {terraform_dir}",
            f"    GUARDRAIL_PROVIDER: {provider}",
            f"    GUARDRAIL_BASELINE: {baseline}",
            f"    GUARDRAIL_EVIDENCE_FORMAT: {evidence_format}",
            "",
            "phases:",
            "  install:",
            "    commands:",
            "      - curl -fsSL https://guardrail.sh/install | bash",
            "  pre_build:",
            "    commands:",
            "      - cd \"$GUARDRAIL_TERRAFORM_DIR\"",
            "      - terraform init",
            "      - terraform plan -out=tfplan",
            "      - EVALUATE_EXIT=0",
            (
                "      - terraform-guardrail enterprise drift-gate . "
                "--provider \"$GUARDRAIL_PROVIDER\" --baseline \"$GUARDRAIL_BASELINE\" "
                "--snapshot-id \"$GUARDRAIL_BASELINE\" "
                "--evidence-format \"$GUARDRAIL_EVIDENCE_FORMAT\" "
                "--format json > ../guardrail-report.json || EVALUATE_EXIT=$?"
            ),
            f"      - {copy_command}",
            "      - test \"$EVALUATE_EXIT\" -eq 0",
            "  build:",
            "    commands:",
            *build_commands,
            "artifacts:",
            "  files:",
            "    - guardrail-report.json",
            f"    - {evidence_file}",
            "",
        ]
    )


def render_readme(
    terraform_dir: str,
    provider: str,
    baseline: str,
    evidence_format: Literal["json", "csv", "pdf"],
    include_apply: bool,
) -> str:
    mode = "guardrail and apply stage" if include_apply else "guardrail-only stage"
    return "\n".join(
        [
            "# AWS CodePipeline Guardrail Scaffold",
            "",
            f"This folder contains a Terraform Guardrail CodeBuild {mode}.",
            "",
            "## Generated settings",
            "",
            f"- Terraform directory: `{terraform_dir}`",
            f"- Provider: `{provider}`",
            f"- Baseline: `{baseline}`",
            f"- Evidence format: `{evidence_format}`",
            "",
            "## Files",
            "",
            "- `buildspec-guardrail.yml`: CodeBuild buildspec for the guardrail stage.",
            "- `guardrail-report.json`: generated evaluation result artifact.",
            f"- `guardrail-evidence.{evidence_format}`: generated audit evidence artifact.",
            "",
            "## Pipeline usage",
            "",
            "1. Add a CodeBuild action after source checkout and before Terraform apply.",
            "2. Configure the action to use `buildspec-guardrail.yml`.",
            "3. Publish the generated report and evidence files as CodePipeline artifacts.",
            "4. Keep Terraform apply in a later stage unless this scaffold includes apply.",
            "",
        ]
    )


def _copy_evidence_command(evidence_format: str, evidence_file: str) -> str:
    return (
        "cp .guardrail/enterprise/evidence/*."
        f"{evidence_format} ../{evidence_file} || "
        "cp ../.guardrail/enterprise/evidence/*."
        f"{evidence_format} ../{evidence_file}"
    )

from __future__ import annotations

import importlib.metadata
import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.json import JSON

from terraform_guardrail.api.app import create_app as create_api_app
from terraform_guardrail.generator import generate_snippet
from terraform_guardrail.mcp.server import run_stdio
from terraform_guardrail.policy_registry import (
    PolicyRegistryError,
    download_bundle,
    get_policy_bundle,
    list_policy_bundles,
)
from terraform_guardrail.registry_api import create_registry_app
from terraform_guardrail.scanner.scan import scan_path
from terraform_guardrail.web.app import create_app

app = typer.Typer(add_completion=False)
policy_app = typer.Typer(help="Policy registry commands.")
app.add_typer(policy_app, name="policy")
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


if __name__ == "__main__":
    main()

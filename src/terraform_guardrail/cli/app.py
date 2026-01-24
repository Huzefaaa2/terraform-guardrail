from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.json import JSON

from terraform_guardrail.api.app import create_app as create_api_app
from terraform_guardrail.generator import generate_snippet
from terraform_guardrail.mcp.server import run_stdio
from terraform_guardrail.scanner.scan import scan_path
from terraform_guardrail.web.app import create_app

app = typer.Typer(add_completion=False)
console = Console()


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Path to a Terraform file or directory.")],
    state: Annotated[Path | None, typer.Option(help="Optional path to a .tfstate file.")] = None,
    format: Annotated[str, typer.Option(help="pretty or json")] = "pretty",
    schema: Annotated[bool, typer.Option(help="Enable schema-aware validation")] = False,
) -> None:
    try:
        report = scan_path(path=path, state_path=state, use_schema=schema)
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


def main() -> None:
    app()


if __name__ == "__main__":
    main()

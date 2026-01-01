from __future__ import annotations

import json
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from terraform_guardrail.generator import generate_snippet
from terraform_guardrail.registry_client import RegistryError, get_provider_metadata
from terraform_guardrail.scanner.scan import scan_path


@dataclass
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any]], Any]


def _tool_scan_terraform(args: dict[str, Any]) -> dict[str, Any]:
    path = args.get("path")
    if not path:
        raise ValueError("path is required")
    state_path = args.get("state_path")
    report = scan_path(path=path, state_path=state_path)
    return report.model_dump()


def _tool_provider_metadata(args: dict[str, Any]) -> dict[str, Any]:
    provider = args.get("provider", "aws")
    try:
        return get_provider_metadata(provider)
    except RegistryError as exc:
        return {"error": str(exc)}


def _tool_generate_snippet(args: dict[str, Any]) -> dict[str, Any]:
    provider = args.get("provider", "aws")
    resource_type = args.get("resource")
    name = args.get("name", "example")
    if not resource_type:
        raise ValueError("resource is required")
    snippet = generate_snippet(provider, resource_type, name)
    return {"language": snippet.language, "content": snippet.content}


TOOLS = [
    Tool(
        name="scan_terraform",
        description="Run compliance checks over Terraform configs and optional state.",
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "state_path": {"type": "string"},
            },
            "required": ["path"],
        },
        handler=_tool_scan_terraform,
    ),
    Tool(
        name="get_provider_metadata",
        description="Fetch provider metadata from Terraform Registry.",
        input_schema={
            "type": "object",
            "properties": {
                "provider": {"type": "string", "enum": ["aws", "azure", "azurerm"]}
            },
        },
        handler=_tool_provider_metadata,
    ),
    Tool(
        name="generate_snippet",
        description="Generate a Terraform snippet for a supported resource.",
        input_schema={
            "type": "object",
            "properties": {
                "provider": {"type": "string", "enum": ["aws", "azure"]},
                "resource": {"type": "string"},
                "name": {"type": "string"},
            },
            "required": ["resource"],
        },
        handler=_tool_generate_snippet,
    ),
]


def run_stdio() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            _write_error(None, "invalid_json")
            continue

        request_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        if method == "initialize":
            _write_response(
                request_id,
                {
                    "serverInfo": {"name": "terraform-guardrail", "version": "0.1.0"},
                    "capabilities": {"tools": True},
                },
            )
        elif method == "list_tools":
            _write_response(
                request_id,
                {
                    "tools": [
                        {
                            "name": tool.name,
                            "description": tool.description,
                            "inputSchema": tool.input_schema,
                        }
                        for tool in TOOLS
                    ]
                },
            )
        elif method == "call_tool":
            tool_name = params.get("name")
            args = params.get("arguments", {})
            tool = next((t for t in TOOLS if t.name == tool_name), None)
            if not tool:
                _write_error(request_id, f"unknown tool: {tool_name}")
                continue
            try:
                result = tool.handler(args)
                _write_response(request_id, {"content": result})
            except Exception as exc:  # noqa: BLE001
                _write_error(request_id, str(exc))
        else:
            _write_error(request_id, f"unknown method: {method}")


def _write_response(request_id: Any, result: dict[str, Any]) -> None:
    payload = {"jsonrpc": "2.0", "id": request_id, "result": result}
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def _write_error(request_id: Any, message: str) -> None:
    payload = {"jsonrpc": "2.0", "id": request_id, "error": {"message": message}}
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()

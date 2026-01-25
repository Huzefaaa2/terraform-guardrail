#!/usr/bin/env bash
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required. Please install Python 3.10+ first."
  exit 1
fi

if ! command -v pip3 >/dev/null 2>&1; then
  echo "pip3 not found. Installing pip..."
  python3 -m ensurepip --upgrade
fi

python3 -m pip install --user --upgrade pip
python3 -m pip install --user --upgrade terraform-guardrail

echo "Terraform Guardrail MCP installed."
echo "Ensure ~/.local/bin is on your PATH."

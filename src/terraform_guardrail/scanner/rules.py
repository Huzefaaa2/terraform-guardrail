from __future__ import annotations

import re

SENSITIVE_NAME_RE = re.compile(
    r"(?i)\b(password|secret|token|api_key|apikey|access_key|private_key|client_secret|credential)\b"
)

SENSITIVE_ASSIGN_RE = re.compile(
    r"(?i)(password|secret|token|api_key|apikey|access_key|private_key|client_secret|credential)\s*=\s*\"([^\"]+)\""
)

RULES = {
    "TG001": "Sensitive variable without ephemeral=true",
    "TG002": "Hardcoded secret in Terraform config",
    "TG003": "Sensitive-looking value stored in Terraform state",
    "TG004": "HCL parse error",
}

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
    "TG005": "Attribute not found in provider schema",
    "TG006": "Public S3 bucket ACL detected",
    "TG007": "Public S3 access block disabled",
    "TG008": "Security group ingress open to the world",
    "TG009": "IAM policy wildcard permissions",
    "TG010": "Public IP association enabled on compute",
    "TG011": "S3 bucket missing default encryption",
    "TG012": "RDS storage not encrypted",
    "TG013": "Load balancer listener uses HTTP",
    "TG014": "Instance missing subnet/VPC boundary",
    "TG015": "RDS instance publicly accessible",
    "TG016": "Missing mandatory resource tags",
    "TG017": "Resource region/location not in allowed list",
    "TG018": "Instance type or SKU not in allowed list",
    "TG019": "Azure storage account public network access enabled",
    "TG020": "EBS volume not encrypted",
}

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
    "TG021": "Cross-provider public exposure invariant violation",
    "TG022": "Cross-provider storage encryption invariant violation",
    "TG023": "Cross-provider ownership tag invariant violation",
}

RULE_METADATA = {
    "TG001": {
        "risk": "medium",
        "remediation": "Add ephemeral = true to sensitive Terraform variables.",
    },
    "TG002": {
        "risk": "high",
        "remediation": "Move hardcoded secrets to variables, secret managers, or CI secrets.",
    },
    "TG003": {
        "risk": "high",
        "remediation": "Use ephemeral or write-only values to keep secrets out of Terraform state.",
    },
    "TG004": {
        "risk": "low",
        "remediation": "Fix invalid HCL syntax before running guardrail evaluation.",
    },
    "TG005": {
        "risk": "medium",
        "remediation": "Verify the attribute name against the provider schema.",
    },
    "TG006": {
        "risk": "high",
        "remediation": "Remove public ACLs and use private bucket policies.",
    },
    "TG007": {
        "risk": "high",
        "remediation": "Enable all S3 public access block settings.",
    },
    "TG008": {
        "risk": "high",
        "remediation": "Restrict ingress CIDRs to approved network ranges.",
    },
    "TG009": {
        "risk": "high",
        "remediation": "Scope IAM actions and resources explicitly.",
    },
    "TG010": {
        "risk": "medium",
        "remediation": "Remove public IP association for private compute hosts.",
    },
    "TG011": {
        "risk": "medium",
        "remediation": "Enable S3 default encryption with KMS or AES256.",
    },
    "TG012": {
        "risk": "medium",
        "remediation": "Enable encrypted RDS storage and use managed KMS keys.",
    },
    "TG013": {
        "risk": "medium",
        "remediation": "Use HTTPS listeners with managed TLS certificates.",
    },
    "TG014": {
        "risk": "low",
        "remediation": "Attach instances to explicit subnet and VPC boundaries.",
    },
    "TG015": {
        "risk": "high",
        "remediation": "Disable publicly_accessible on database resources.",
    },
    "TG016": {
        "risk": "low",
        "remediation": "Add the mandatory tags required by your platform baseline.",
    },
    "TG017": {
        "risk": "medium",
        "remediation": "Deploy resources only in approved regions or locations.",
    },
    "TG018": {
        "risk": "medium",
        "remediation": "Use approved instance types or SKUs for the workload tier.",
    },
    "TG019": {
        "risk": "medium",
        "remediation": "Disable public network access or use private endpoints.",
    },
    "TG020": {
        "risk": "medium",
        "remediation": "Enable EBS encryption with a managed KMS key.",
    },
    "TG021": {
        "risk": "high",
        "remediation": "Disable public access and use private networking or approved ingress.",
    },
    "TG022": {
        "risk": "high",
        "remediation": "Enable provider-native encryption for storage resources.",
    },
    "TG023": {
        "risk": "low",
        "remediation": "Add consistent ownership tags or labels across all cloud resources.",
    },
}

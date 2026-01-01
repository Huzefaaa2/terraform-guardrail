from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Snippet:
    language: str
    content: str


TEMPLATES = {
    "aws": {
        "aws_s3_bucket": """
resource \"aws_s3_bucket\" \"{name}\" {{
  bucket = \"{name}-bucket\"
  tags = {{
    ManagedBy = \"terraform-guardrail\"
  }}
}}
""",
        "aws_vpc": """
resource \"aws_vpc\" \"{name}\" {{
  cidr_block           = \"10.0.0.0/16\"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {{
    Name = \"{name}\"
  }}
}}
""",
        "aws_subnet": """
resource \"aws_subnet\" \"{name}\" {{
  vpc_id                  = aws_vpc.main.id
  cidr_block              = \"10.0.1.0/24\"
  map_public_ip_on_launch = true
  availability_zone       = \"us-east-1a\"
}}
""",
        "aws_iam_role": """
resource \"aws_iam_role\" \"{name}\" {{
  name = \"{name}\"
  assume_role_policy = jsonencode({{
    Version = \"2012-10-17\"
    Statement = [{{
      Effect = \"Allow\"
      Principal = {{ Service = \"ec2.amazonaws.com\" }}
      Action = \"sts:AssumeRole\"
    }}]
  }})
}}
""",
    },
    "azure": {
        "azurerm_resource_group": """
resource \"azurerm_resource_group\" \"{name}\" {{
  name     = \"{name}-rg\"
  location = \"East US\"
}}
""",
        "azurerm_storage_account": """
resource \"azurerm_storage_account\" \"{name}\" {{
  name                     = \"{name}sa\"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = \"Standard\"
  account_replication_type = \"LRS\"
}}
""",
    },
}


def generate_snippet(provider: str, resource_type: str, name: str) -> Snippet:
    provider_templates = TEMPLATES.get(provider)
    if not provider_templates:
        raise ValueError(f"Unsupported provider '{provider}'.")

    template = provider_templates.get(resource_type)
    if not template:
        raise ValueError(f"Unsupported resource '{resource_type}' for {provider}.")

    return Snippet(language="hcl", content=template.format(name=name))

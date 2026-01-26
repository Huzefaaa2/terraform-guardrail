package guardrail.baseline

import rego.v1

default allow = true

required_tags := {"owner", "environment", "cost_center"}

resource_blocks contains block if {
  file := input.files[_]
  resource := file.hcl.resource[_]
  resource_type := object.keys(resource)[_]
  instances := resource[resource_type]
  name := object.keys(instances)[_]
  attrs := instances[name]
  block := {
    "file": file,
    "type": resource_type,
    "name": name,
    "attrs": attrs,
  }
}

public_cidr(cidr) if {
  cidr == "0.0.0.0/0"
}

public_cidr(cidr) if {
  cidr == "::/0"
}

public_acl(acl) if {
  acl == "public-read"
}

public_acl(acl) if {
  acl == "public-read-write"
}

public_access_block_disabled(attrs) if {
  attrs.block_public_acls == false
}

public_access_block_disabled(attrs) if {
  attrs.block_public_policy == false
}

public_access_block_disabled(attrs) if {
  attrs.ignore_public_acls == false
}

public_access_block_disabled(attrs) if {
  attrs.restrict_public_buckets == false
}

has_public_cidr(block) if {
  cidr := block.cidr_blocks[_]
  public_cidr(cidr)
}

has_public_cidr(block) if {
  cidr := block.ipv6_cidr_blocks[_]
  public_cidr(cidr)
}

value_in_list(value, list) if {
  value == list[_]
}

iam_policy_wildcard(policy) if {
  regex.match("(?i)\\\"Action\\\"\\s*:\\s*\\\"\\*\\\"", policy)
}

iam_policy_wildcard(policy) if {
  regex.match("(?i)\\\"Resource\\\"\\s*:\\s*\\\"\\*\\\"", policy)
}

is_rds_resource(resource_type) if {
  resource_type == "aws_db_instance"
}

is_rds_resource(resource_type) if {
  resource_type == "aws_rds_cluster"
}

is_lb_listener(resource_type) if {
  resource_type == "aws_lb_listener"
}

is_lb_listener(resource_type) if {
  resource_type == "aws_alb_listener"
}

# TG001 - sensitive variables without ephemeral

deny contains output if {
  file := input.files[_]
  var_block := file.hcl.variable[_]
  name := object.keys(var_block)[_]
  attrs := var_block[name]
  attrs.sensitive == true
  not attrs.ephemeral

  output := {
    "message": sprintf("Variable %s should be marked ephemeral.", [name]),
    "severity": "medium",
    "rule_id": "TG001",
    "path": file.path,
  }
}

# TG006 - public S3 ACL

deny contains output if {
  block := resource_blocks[_]
  block.type == "aws_s3_bucket"
  acl := lower(block.attrs.acl)
  public_acl(acl)

  output := {
    "message": sprintf("%s.%s has a public ACL", [block.type, block.name]),
    "severity": "high",
    "rule_id": "TG006",
    "path": block.file.path,
  }
}

# TG007 - public access block disabled

deny contains output if {
  block := resource_blocks[_]
  block.type == "aws_s3_bucket_public_access_block"
  public_access_block_disabled(block.attrs)

  output := {
    "message": sprintf("%s.%s disables S3 public access blocking", [block.type, block.name]),
    "severity": "high",
    "rule_id": "TG007",
    "path": block.file.path,
  }
}

# TG008 - security group ingress open to world

deny contains output if {
  block := resource_blocks[_]
  block.type == "aws_security_group"
  ingress := block.attrs.ingress[_]
  has_public_cidr(ingress)

  output := {
    "message": sprintf("%s.%s allows public ingress", [block.type, block.name]),
    "severity": "high",
    "rule_id": "TG008",
    "path": block.file.path,
  }
}

deny contains output if {
  block := resource_blocks[_]
  block.type == "aws_security_group_rule"
  block.attrs.type == "ingress"
  has_public_cidr(block.attrs)

  output := {
    "message": sprintf("%s.%s allows public ingress", [block.type, block.name]),
    "severity": "high",
    "rule_id": "TG008",
    "path": block.file.path,
  }
}

# TG009 - IAM wildcard permissions

deny contains output if {
  block := resource_blocks[_]
  block.type == "aws_iam_policy"
  policy := block.attrs.policy
  iam_policy_wildcard(policy)

  output := {
    "message": sprintf("%s.%s contains wildcard IAM permissions", [block.type, block.name]),
    "severity": "high",
    "rule_id": "TG009",
    "path": block.file.path,
  }
}

deny contains output if {
  block := resource_blocks[_]
  block.type == "aws_iam_role_policy"
  policy := block.attrs.policy
  iam_policy_wildcard(policy)

  output := {
    "message": sprintf("%s.%s contains wildcard IAM permissions", [block.type, block.name]),
    "severity": "high",
    "rule_id": "TG009",
    "path": block.file.path,
  }
}

# TG010 - public IP association

deny contains output if {
  block := resource_blocks[_]
  block.type == "aws_instance"
  block.attrs.associate_public_ip_address == true

  output := {
    "message": sprintf("%s.%s associates a public IP", [block.type, block.name]),
    "severity": "medium",
    "rule_id": "TG010",
    "path": block.file.path,
  }
}

# TG011 - S3 encryption missing

deny contains output if {
  block := resource_blocks[_]
  block.type == "aws_s3_bucket"
  not block.attrs.server_side_encryption_configuration

  output := {
    "message": sprintf("%s.%s lacks default encryption", [block.type, block.name]),
    "severity": "medium",
    "rule_id": "TG011",
    "path": block.file.path,
  }
}

# TG012 - RDS storage not encrypted

deny contains output if {
  block := resource_blocks[_]
  is_rds_resource(block.type)
  not block.attrs.storage_encrypted

  output := {
    "message": sprintf("%s.%s has storage_encrypted disabled", [block.type, block.name]),
    "severity": "medium",
    "rule_id": "TG012",
    "path": block.file.path,
  }
}

# TG013 - HTTP listener

deny contains output if {
  block := resource_blocks[_]
  is_lb_listener(block.type)
  upper(block.attrs.protocol) == "HTTP"

  output := {
    "message": sprintf("%s.%s uses HTTP", [block.type, block.name]),
    "severity": "medium",
    "rule_id": "TG013",
    "path": block.file.path,
  }
}

# TG014 - instance missing subnet

deny contains output if {
  block := resource_blocks[_]
  block.type == "aws_instance"
  not block.attrs.subnet_id

  output := {
    "message": sprintf("%s.%s missing subnet_id", [block.type, block.name]),
    "severity": "low",
    "rule_id": "TG014",
    "path": block.file.path,
  }
}

# TG015 - RDS publicly accessible

deny contains output if {
  block := resource_blocks[_]
  block.type == "aws_db_instance"
  block.attrs.publicly_accessible == true

  output := {
    "message": sprintf("%s.%s is publicly accessible", [block.type, block.name]),
    "severity": "high",
    "rule_id": "TG015",
    "path": block.file.path,
  }
}

# TG016 - missing mandatory tags

deny contains output if {
  block := resource_blocks[_]
  not block.attrs.tags
  output := {
    "message": sprintf("%s.%s missing required tags", [block.type, block.name]),
    "severity": "low",
    "rule_id": "TG016",
    "path": block.file.path,
  }
}

# TG017 - region/location not allowed (driven by data.guardrail.allowed_regions)

deny contains output if {
  block := resource_blocks[_]
  allowed := data.guardrail.allowed_regions
  allowed
  value := block.attrs.location
  not value_in_list(value, allowed)

  output := {
    "message": sprintf("%s.%s uses disallowed location %s", [block.type, block.name, value]),
    "severity": "medium",
    "rule_id": "TG017",
    "path": block.file.path,
  }
}

# TG018 - instance type/SKU not allowed (driven by data.guardrail.allowed_instance_types)

deny contains output if {
  block := resource_blocks[_]
  allowed := data.guardrail.allowed_instance_types
  allowed
  value := block.attrs.instance_type
  not value_in_list(value, allowed)

  output := {
    "message": sprintf("%s.%s uses disallowed instance type %s", [block.type, block.name, value]),
    "severity": "medium",
    "rule_id": "TG018",
    "path": block.file.path,
  }
}

# TG019 - Azure storage public network access enabled

deny contains output if {
  block := resource_blocks[_]
  block.type == "azurerm_storage_account"
  block.attrs.public_network_access_enabled == true

  output := {
    "message": sprintf("%s.%s has public network access enabled", [block.type, block.name]),
    "severity": "medium",
    "rule_id": "TG019",
    "path": block.file.path,
  }
}

# TG020 - EBS volume not encrypted

deny contains output if {
  block := resource_blocks[_]
  block.type == "aws_ebs_volume"
  not block.attrs.encrypted

  output := {
    "message": sprintf("%s.%s has encryption disabled", [block.type, block.name]),
    "severity": "medium",
    "rule_id": "TG020",
    "path": block.file.path,
  }
}

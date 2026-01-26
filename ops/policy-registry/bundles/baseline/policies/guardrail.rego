package guardrail.baseline

default allow = true

required_tags := {"owner", "environment", "cost_center"}

resource_blocks[file, resource_type, name, attrs] {
  file := input.files[_]
  resource := file.hcl.resource[_]
  resource_type := object.keys(resource)[_]
  instances := resource[resource_type]
  name := object.keys(instances)[_]
  attrs := instances[name]
}

public_cidr(cidr) {
  cidr == "0.0.0.0/0"
}

public_cidr(cidr) {
  cidr == "::/0"
}

has_public_cidr(block) {
  cidr := block.cidr_blocks[_]
  public_cidr(cidr)
}

has_public_cidr(block) {
  cidr := block.ipv6_cidr_blocks[_]
  public_cidr(cidr)
}

value_in_list(value, list) {
  value == list[_]
}

missing_required_tags(tags, missing) {
  missing := {tag | required_tags[tag]; not tags[tag]}
}

# TG001 - sensitive variables without ephemeral

deny[output] {
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

deny[output] {
  resource_blocks[file, "aws_s3_bucket", name, attrs]
  acl := lower(attrs.acl)
  acl == "public-read" or acl == "public-read-write"

  output := {
    "message": sprintf("%s.%s has a public ACL", ["aws_s3_bucket", name]),
    "severity": "high",
    "rule_id": "TG006",
    "path": file.path,
  }
}

# TG007 - public access block disabled

deny[output] {
  resource_blocks[file, "aws_s3_bucket_public_access_block", name, attrs]
  attrs.block_public_acls == false or attrs.block_public_policy == false or attrs.ignore_public_acls == false or attrs.restrict_public_buckets == false

  output := {
    "message": sprintf("%s.%s disables S3 public access blocking", ["aws_s3_bucket_public_access_block", name]),
    "severity": "high",
    "rule_id": "TG007",
    "path": file.path,
  }
}

# TG008 - security group ingress open to world

deny[output] {
  resource_blocks[file, "aws_security_group", name, attrs]
  ingress := attrs.ingress[_]
  has_public_cidr(ingress)

  output := {
    "message": sprintf("%s.%s allows public ingress", ["aws_security_group", name]),
    "severity": "high",
    "rule_id": "TG008",
    "path": file.path,
  }
}

deny[output] {
  resource_blocks[file, "aws_security_group_rule", name, attrs]
  attrs.type == "ingress"
  has_public_cidr(attrs)

  output := {
    "message": sprintf("%s.%s allows public ingress", ["aws_security_group_rule", name]),
    "severity": "high",
    "rule_id": "TG008",
    "path": file.path,
  }
}

# TG009 - IAM wildcard permissions

deny[output] {
  resource_blocks[file, "aws_iam_policy", name, attrs]
  policy := attrs.policy
  re_match("(?i)\"Action\"\\s*:\\s*\"\\*\"", policy) or re_match("(?i)\"Resource\"\\s*:\\s*\"\\*\"", policy)

  output := {
    "message": sprintf("%s.%s contains wildcard IAM permissions", ["aws_iam_policy", name]),
    "severity": "high",
    "rule_id": "TG009",
    "path": file.path,
  }
}

deny[output] {
  resource_blocks[file, "aws_iam_role_policy", name, attrs]
  policy := attrs.policy
  re_match("(?i)\"Action\"\\s*:\\s*\"\\*\"", policy) or re_match("(?i)\"Resource\"\\s*:\\s*\"\\*\"", policy)

  output := {
    "message": sprintf("%s.%s contains wildcard IAM permissions", ["aws_iam_role_policy", name]),
    "severity": "high",
    "rule_id": "TG009",
    "path": file.path,
  }
}

# TG010 - public IP association

deny[output] {
  resource_blocks[file, "aws_instance", name, attrs]
  attrs.associate_public_ip_address == true

  output := {
    "message": sprintf("%s.%s associates a public IP", ["aws_instance", name]),
    "severity": "medium",
    "rule_id": "TG010",
    "path": file.path,
  }
}

# TG011 - S3 encryption missing

deny[output] {
  resource_blocks[file, "aws_s3_bucket", name, attrs]
  not attrs.server_side_encryption_configuration

  output := {
    "message": sprintf("%s.%s lacks default encryption", ["aws_s3_bucket", name]),
    "severity": "medium",
    "rule_id": "TG011",
    "path": file.path,
  }
}

# TG012 - RDS storage not encrypted

deny[output] {
  resource_blocks[file, resource_type, name, attrs]
  resource_type == "aws_db_instance" or resource_type == "aws_rds_cluster"
  not attrs.storage_encrypted

  output := {
    "message": sprintf("%s.%s has storage_encrypted disabled", [resource_type, name]),
    "severity": "medium",
    "rule_id": "TG012",
    "path": file.path,
  }
}

# TG013 - HTTP listener

deny[output] {
  resource_blocks[file, resource_type, name, attrs]
  resource_type == "aws_lb_listener" or resource_type == "aws_alb_listener"
  upper(attrs.protocol) == "HTTP"

  output := {
    "message": sprintf("%s.%s uses HTTP", [resource_type, name]),
    "severity": "medium",
    "rule_id": "TG013",
    "path": file.path,
  }
}

# TG014 - instance missing subnet

deny[output] {
  resource_blocks[file, "aws_instance", name, attrs]
  not attrs.subnet_id

  output := {
    "message": sprintf("%s.%s missing subnet_id", ["aws_instance", name]),
    "severity": "low",
    "rule_id": "TG014",
    "path": file.path,
  }
}

# TG015 - RDS publicly accessible

deny[output] {
  resource_blocks[file, "aws_db_instance", name, attrs]
  attrs.publicly_accessible == true

  output := {
    "message": sprintf("%s.%s is publicly accessible", ["aws_db_instance", name]),
    "severity": "high",
    "rule_id": "TG015",
    "path": file.path,
  }
}

# TG016 - missing mandatory tags

deny[output] {
  resource_blocks[file, resource_type, name, attrs]
  tags := attrs.tags
  not tags
  output := {
    "message": sprintf("%s.%s missing required tags", [resource_type, name]),
    "severity": "low",
    "rule_id": "TG016",
    "path": file.path,
  }
}

# TG017 - region/location not allowed (driven by data.guardrail.allowed_regions)

deny[output] {
  resource_blocks[file, resource_type, name, attrs]
  allowed := data.guardrail.allowed_regions
  allowed
  value := attrs.location
  not value_in_list(value, allowed)

  output := {
    "message": sprintf("%s.%s uses disallowed location %s", [resource_type, name, value]),
    "severity": "medium",
    "rule_id": "TG017",
    "path": file.path,
  }
}

# TG018 - instance type/SKU not allowed (driven by data.guardrail.allowed_instance_types)

deny[output] {
  resource_blocks[file, resource_type, name, attrs]
  allowed := data.guardrail.allowed_instance_types
  allowed
  value := attrs.instance_type
  not value_in_list(value, allowed)

  output := {
    "message": sprintf("%s.%s uses disallowed instance type %s", [resource_type, name, value]),
    "severity": "medium",
    "rule_id": "TG018",
    "path": file.path,
  }
}

# TG019 - Azure storage public network access enabled

deny[output] {
  resource_blocks[file, "azurerm_storage_account", name, attrs]
  attrs.public_network_access_enabled == true

  output := {
    "message": sprintf("%s.%s has public network access enabled", ["azurerm_storage_account", name]),
    "severity": "medium",
    "rule_id": "TG019",
    "path": file.path,
  }
}

# TG020 - EBS volume not encrypted

deny[output] {
  resource_blocks[file, "aws_ebs_volume", name, attrs]
  not attrs.encrypted

  output := {
    "message": sprintf("%s.%s has encryption disabled", ["aws_ebs_volume", name]),
    "severity": "medium",
    "rule_id": "TG020",
    "path": file.path,
  }
}

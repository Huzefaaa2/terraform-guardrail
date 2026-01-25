package guardrail.baseline

default allow = true

deny contains output if {
  file := input.files[_]
  var_block := file.hcl.variable[_]
  some name
  attrs := var_block[name]
  attrs.sensitive == true
  not attrs.ephemeral

  output := {
    "message": sprintf("Variable %s should be marked ephemeral.", [name]),
    "severity": "medium",
    "rule_id": "OPA001",
    "path": file.path,
  }
}

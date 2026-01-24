package guardrail.baseline

default allow = true

deny[msg] {
  input.resource_type == "aws_iam_access_key"
  msg := "IAM access keys must be stored as ephemeral values."
}

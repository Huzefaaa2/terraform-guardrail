variable "db_password" {
  type      = string
  sensitive = true
}

resource "aws_s3_bucket" "bad" {
  bucket = "guardrail-bad-example"
  invalid_attr = "oops"
}

resource "aws_s3_bucket" "broken" {
  bucket = "missing_quote
}

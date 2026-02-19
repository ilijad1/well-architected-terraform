resource "aws_cloudwatch_log_group" "good" {
  name              = "/aws/good"
  retention_in_days = 30
  kms_key_id        = "arn:aws:kms:us-east-1:123:key/abc"
  tags              = { Environment = "prod" }
}

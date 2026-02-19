resource "aws_kinesis_stream" "good" {
  name             = "good-stream"
  shard_count      = 1
  encryption_type  = "KMS"
  kms_key_id       = "arn:aws:kms:us-east-1:123:key/abc"
  retention_period = 48
  tags             = { Environment = "prod" }
}

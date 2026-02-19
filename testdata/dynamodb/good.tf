resource "aws_dynamodb_table" "good" {
  name           = "good-table"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "id"
  deletion_protection_enabled = true
  tags = { Environment = "prod" }

  attribute {
    name = "id"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
  }

  point_in_time_recovery {
    enabled = true
  }
}

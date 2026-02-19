resource "aws_kinesis_firehose_delivery_stream" "no_encryption" {
  name        = "no-encryption-stream"
  destination = "s3"

  s3_configuration {
    role_arn   = "arn:aws:iam::123456789012:role/firehose-role"
    bucket_arn = "arn:aws:s3:::my-bucket"
  }
}

resource "aws_kinesis_firehose_delivery_stream" "no_backup" {
  name        = "no-backup-stream"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn   = "arn:aws:iam::123456789012:role/firehose-role"
    bucket_arn = "arn:aws:s3:::my-bucket"

    s3_backup_mode = "Disabled"
  }

  server_side_encryption {
    enabled = true
  }
}

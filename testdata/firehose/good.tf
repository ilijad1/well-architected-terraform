resource "aws_kinesis_firehose_delivery_stream" "encrypted_with_backup" {
  name        = "encrypted-backup-stream"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn       = "arn:aws:iam::123456789012:role/firehose-role"
    bucket_arn     = "arn:aws:s3:::my-bucket"
    s3_backup_mode = "Enabled"

    s3_backup_configuration {
      role_arn   = "arn:aws:iam::123456789012:role/firehose-role"
      bucket_arn = "arn:aws:s3:::my-backup-bucket"
    }
  }

  server_side_encryption {
    enabled = true
  }
}

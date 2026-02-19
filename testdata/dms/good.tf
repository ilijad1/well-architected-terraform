resource "aws_dms_replication_instance" "good" {
  replication_instance_class = "dms.r5.large"
  replication_instance_id    = "good-dms"
  publicly_accessible        = false
  kms_key_arn                = "arn:aws:kms:us-east-1:123456789012:key/example"
  auto_minor_version_upgrade = true
}

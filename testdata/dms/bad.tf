resource "aws_dms_replication_instance" "bad" {
  replication_instance_class = "dms.r5.large"
  replication_instance_id    = "bad-dms"
  publicly_accessible        = true
  auto_minor_version_upgrade = false
}

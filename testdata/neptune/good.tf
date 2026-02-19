resource "aws_neptune_cluster" "good" {
  cluster_identifier                  = "good-cluster"
  engine                              = "neptune"
  storage_encrypted                   = true
  deletion_protection                 = true
  iam_database_authentication_enabled = true
  backup_retention_period             = 7
  copy_tags_to_snapshot               = true
  enable_cloudwatch_logs_exports      = ["audit"]
}

resource "aws_efs_file_system" "good" {
  encrypted = true
  tags = {
    Environment = "prod"
  }
}

resource "aws_efs_backup_policy" "good" {
  file_system_id = "fs-123"

  backup_policy {
    status = "ENABLED"
  }
}

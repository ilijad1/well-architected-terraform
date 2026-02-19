resource "aws_efs_file_system" "bad" {
  creation_token = "bad-efs"
}

resource "aws_efs_backup_policy" "bad" {
  file_system_id = "fs-456"

  backup_policy {
    status = "DISABLED"
  }
}

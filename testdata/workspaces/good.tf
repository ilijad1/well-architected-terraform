resource "aws_workspaces_workspace" "good" {
  directory_id = "d-1234567890"
  bundle_id    = "wsb-abc123"
  user_name    = "user@example.com"

  root_volume_encryption_enabled = true
  user_volume_encryption_enabled = true
  volume_encryption_key          = "arn:aws:kms:us-east-1:123456789012:key/example"
}

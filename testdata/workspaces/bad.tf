resource "aws_workspaces_workspace" "bad" {
  directory_id = "d-1234567890"
  bundle_id    = "wsb-abc123"
  user_name    = "user@example.com"
}

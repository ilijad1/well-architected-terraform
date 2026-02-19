resource "aws_ssm_document" "good" {
  name          = "good-doc"
  document_type = "Command"
  content       = "{}"

  permissions {
    type        = "Share"
    account_ids = "123456789012"
  }
}

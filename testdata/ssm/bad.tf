resource "aws_ssm_document" "bad" {
  name          = "bad-doc"
  document_type = "Command"
  content       = "{}"

  permissions {
    type        = "Share"
    account_ids = "all"
  }
}

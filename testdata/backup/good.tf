resource "aws_backup_vault" "good" {
  name        = "good-vault"
  kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/example"
}

resource "aws_backup_plan" "good" {
  name = "good-plan"

  rule {
    rule_name         = "daily"
    target_vault_name = "good-vault"
    schedule          = "cron(0 12 * * ? *)"

    lifecycle {
      cold_storage_after = 30
      delete_after       = 365
    }
  }
}

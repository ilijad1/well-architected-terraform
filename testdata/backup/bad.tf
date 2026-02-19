resource "aws_backup_vault" "bad" {
  name = "bad-vault"
}

resource "aws_backup_plan" "bad" {
  name = "bad-plan"

  rule {
    rule_name         = "daily"
    target_vault_name = "bad-vault"
    schedule          = "cron(0 12 * * ? *)"
  }
}

resource "aws_kms_key" "good" {
  description             = "Good KMS key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = { Environment = "prod" }
}

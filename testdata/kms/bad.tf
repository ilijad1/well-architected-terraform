resource "aws_kms_key" "bad" {
  description             = "Bad KMS key"
  deletion_window_in_days = 7
}

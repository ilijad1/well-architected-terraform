resource "aws_transfer_server" "good" {
  protocols    = ["SFTP"]
  logging_role = "arn:aws:iam::123456789012:role/transfer-logging"
}

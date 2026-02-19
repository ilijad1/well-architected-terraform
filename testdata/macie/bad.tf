resource "aws_macie2_account" "disabled" {
  status = "PAUSED"
}

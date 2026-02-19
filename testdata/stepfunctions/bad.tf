resource "aws_sfn_state_machine" "bad" {
  name     = "bad-sfn"
  role_arn = "arn:aws:iam::123456789012:role/sfn"
  definition = "{}"
}

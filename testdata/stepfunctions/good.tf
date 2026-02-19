resource "aws_sfn_state_machine" "good" {
  name     = "good-sfn"
  role_arn = "arn:aws:iam::123456789012:role/sfn"
  definition = "{}"

  logging_configuration {
    level                  = "ALL"
    include_execution_data = true
    log_destination        = "arn:aws:logs:us-east-1:123456789012:log-group:/aws/sfn:*"
  }

  tracing_configuration {
    enabled = true
  }
}

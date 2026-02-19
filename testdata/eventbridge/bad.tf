resource "aws_cloudwatch_event_rule" "disabled" {
  name        = "disabled-rule"
  description = "A disabled rule"
  schedule_expression = "rate(5 minutes)"
  state       = "DISABLED"
}

resource "aws_cloudwatch_event_rule" "default_bus" {
  name        = "default-bus-rule"
  description = "Rule using default event bus"
  schedule_expression = "rate(1 hour)"
  state       = "ENABLED"
}

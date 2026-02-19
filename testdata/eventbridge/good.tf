resource "aws_cloudwatch_event_rule" "enabled_custom_bus" {
  name           = "enabled-custom-bus-rule"
  description    = "Rule using custom event bus"
  event_bus_name = "arn:aws:events:us-east-1:123456789012:event-bus/my-custom-bus"
  state          = "ENABLED"
  event_pattern  = jsonencode({ source = ["myapp.orders"] })
}

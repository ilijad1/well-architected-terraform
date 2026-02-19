resource "aws_sns_topic" "bad" {
  name = "bad-topic"
}

resource "aws_sns_topic_subscription" "bad" {
  topic_arn = "arn:aws:sns:us-east-1:123:bad-topic"
  protocol  = "sqs"
  endpoint  = "arn:aws:sqs:us-east-1:123:queue"
}

resource "aws_sns_topic" "good" {
  name              = "good-topic"
  kms_master_key_id = "arn:aws:kms:us-east-1:123:key/abc"
  tags              = { Environment = "prod" }
}

resource "aws_sns_topic_subscription" "good" {
  topic_arn     = "arn:aws:sns:us-east-1:123:good-topic"
  protocol      = "sqs"
  endpoint      = "arn:aws:sqs:us-east-1:123:queue"
  redrive_policy = jsonencode({ deadLetterTargetArn = "arn:aws:sqs:us-east-1:123:dlq" })
}

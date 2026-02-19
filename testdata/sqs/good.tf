resource "aws_sqs_queue" "good" {
  name              = "good-queue"
  kms_master_key_id = "arn:aws:kms:us-east-1:123:key/abc"
  redrive_policy    = jsonencode({ deadLetterTargetArn = "arn:aws:sqs:us-east-1:123:dlq", maxReceiveCount = 5 })
  tags              = { Environment = "prod" }
}

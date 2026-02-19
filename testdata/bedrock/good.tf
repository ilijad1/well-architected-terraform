resource "aws_bedrock_model_invocation_logging_configuration" "good" {
  logging_config {
    text_data_delivery_enabled = true

    s3_config {
      bucket_name = "bedrock-logs"
    }
  }
}

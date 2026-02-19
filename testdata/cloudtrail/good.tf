resource "aws_cloudtrail" "good" {
  name                       = "good-trail"
  s3_bucket_name             = "my-bucket"
  is_multi_region_trail      = true
  enable_log_file_validation = true
  kms_key_id                 = "arn:aws:kms:us-east-1:123:key/abc"
  cloud_watch_logs_group_arn = "arn:aws:logs:us-east-1:123:log-group:trail"
  enable_logging             = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }
}

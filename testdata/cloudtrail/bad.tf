resource "aws_cloudtrail" "bad" {
  name           = "bad-trail"
  s3_bucket_name = "my-bucket"
}

resource "aws_cloudtrail" "disabled" {
  name           = "disabled-trail"
  s3_bucket_name = "my-bucket"
  enable_logging = false
}

resource "aws_cloudtrail" "no_s3_events" {
  name           = "no-s3-events-trail"
  s3_bucket_name = "my-bucket"
  enable_logging = true
}

resource "aws_config_configuration_recorder" "main" {
  name     = "default"
  role_arn = "arn:aws:iam::123456789012:role/config-role"

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = "default"
  is_enabled = true
}

resource "aws_config_delivery_channel" "main" {
  name           = "default"
  s3_bucket_name = "my-config-bucket"
}

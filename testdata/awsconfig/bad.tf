resource "aws_config_configuration_recorder" "partial" {
  name     = "default"
  role_arn = "arn:aws:iam::123456789012:role/config-role"

  recording_group {
    all_supported = false
  }
}

resource "aws_config_configuration_recorder_status" "disabled" {
  name       = "default"
  is_enabled = false
}

resource "aws_config_delivery_channel" "no_bucket" {
  name = "default"
}

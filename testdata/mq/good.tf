resource "aws_mq_broker" "good" {
  broker_name                = "good-broker"
  engine_type                = "ActiveMQ"
  engine_version             = "5.17.6"
  host_instance_type         = "mq.m5.large"
  publicly_accessible        = false
  auto_minor_version_upgrade = true

  user {
    username = "admin"
    password = "password"
  }

  logs {
    general = true
    audit   = true
  }

  encryption_options {
    use_aws_owned_key = false
    kms_key_id        = "arn:aws:kms:us-east-1:123:key/abc"
  }
}

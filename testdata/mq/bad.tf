resource "aws_mq_broker" "bad" {
  broker_name         = "bad-broker"
  engine_type         = "ActiveMQ"
  engine_version      = "5.17.6"
  host_instance_type  = "mq.m5.large"
  publicly_accessible = true

  user {
    username = "admin"
    password = "password"
  }
}

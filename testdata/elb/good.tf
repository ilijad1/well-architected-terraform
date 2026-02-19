resource "aws_lb" "good" {
  name               = "good-lb"
  internal           = false
  load_balancer_type = "application"
  drop_invalid_header_fields = true
  enable_deletion_protection = true
  tags = { Environment = "prod" }

  access_logs {
    bucket  = "lb-logs"
    enabled = true
  }
}

resource "aws_lb_listener" "good" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123:lb"
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:us-east-1:123:cert"

  default_action {
    type             = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:123:tg"
  }
}

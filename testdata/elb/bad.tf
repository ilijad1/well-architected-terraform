resource "aws_lb" "bad" {
  name               = "bad-lb"
  internal           = false
  load_balancer_type = "application"
}

resource "aws_lb_listener" "bad" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123:lb"
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:123:tg"
  }
}

resource "aws_security_group" "restricted_ssh" {
  name        = "allow-ssh-from-office"
  description = "Allow SSH from office only"
  vpc_id      = "vpc-123456"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_flow_log" "main" {
  vpc_id          = "vpc-123456"
  traffic_type    = "ALL"
  iam_role_arn    = "arn:aws:iam::123456789012:role/flow-log-role"
  log_destination = "arn:aws:logs:us-east-1:123456789012:log-group:flow-logs"
}

resource "aws_default_security_group" "restricted" {
  vpc_id = "vpc-123456"
}

resource "aws_network_acl_rule" "restricted_ssh" {
  network_acl_id = "acl-123"
  rule_number    = 100
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "10.0.0.0/8"
  from_port      = 22
  to_port        = 22
}

resource "aws_subnet" "private_no_auto_ip" {
  vpc_id                  = "vpc-123456"
  cidr_block              = "10.0.2.0/24"
  map_public_ip_on_launch = false
}

resource "aws_route" "private_to_nat" {
  route_table_id         = "rtb-123456"
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = "nat-abc123"
}

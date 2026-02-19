resource "aws_security_group" "open_ssh" {
  name        = "allow-ssh-from-anywhere"
  description = "Allow SSH from anywhere"
  vpc_id      = "vpc-123456"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "open_rdp" {
  name   = "allow-rdp-from-anywhere"
  vpc_id = "vpc-123456"

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_default_security_group" "unrestricted" {
  vpc_id = "vpc-123456"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_network_acl_rule" "open_ssh" {
  network_acl_id = "acl-123"
  rule_number    = 100
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 22
  to_port        = 22
}

resource "aws_subnet" "public_auto_ip" {
  vpc_id                  = "vpc-123456"
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
}

resource "aws_route" "default_to_igw" {
  route_table_id         = "rtb-123456"
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = "igw-abc123"
}

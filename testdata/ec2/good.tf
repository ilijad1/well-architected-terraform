resource "aws_instance" "secure" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  monitoring    = true

  metadata_options {
    http_tokens = "required"
    http_endpoint = "enabled"
  }

  tags = {
    Environment = "production"
    Project     = "example"
  }
}

resource "aws_ebs_volume" "encrypted" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = true
  kms_key_id        = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234"
}

resource "aws_autoscaling_group" "ha" {
  min_size         = 2
  max_size         = 6
  desired_capacity = 3

  launch_template {
    id      = "lt-12345"
    version = "$Latest"
  }
}

resource "aws_ebs_encryption_by_default" "enabled" {
  enabled = true
}

resource "aws_instance" "no_public_ip" {
  ami                         = "ami-12345678"
  instance_type               = "t3.micro"
  associate_public_ip_address = false
  iam_instance_profile        = "my-instance-profile"
  ebs_optimized               = true
}

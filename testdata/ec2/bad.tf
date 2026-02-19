resource "aws_instance" "no_imdsv2" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
}

resource "aws_instance" "old_gen" {
  ami           = "ami-12345678"
  instance_type = "m4.large"

  metadata_options {
    http_tokens = "optional"
  }
}

resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-east-1a"
  size              = 40
}

resource "aws_autoscaling_group" "single_az" {
  min_size         = 1
  max_size         = 3
  desired_capacity = 1

  launch_template {
    id      = "lt-12345"
    version = "$Latest"
  }
}

resource "aws_ebs_encryption_by_default" "disabled" {
  enabled = false
}

resource "aws_instance" "public_ip" {
  ami                         = "ami-12345678"
  instance_type               = "t3.micro"
  associate_public_ip_address = true
}

resource "aws_instance" "no_profile" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
}

resource "aws_instance" "not_ebs_optimized" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  ebs_optimized = false
}

resource "aws_emr_cluster" "good" {
  name          = "good-emr"
  release_label = "emr-6.0.0"
  service_role  = "arn:aws:iam::123456789012:role/emr"
  log_uri       = "s3://my-logs/emr/"
  security_configuration = "my-security-config"

  ec2_attributes {
    subnet_id        = "subnet-12345"
    instance_profile = "arn:aws:iam::123456789012:instance-profile/emr"
  }

  kerberos_attributes {
    realm    = "EXAMPLE.COM"
    kdc_admin_password = "password"
  }
}

resource "aws_db_instance" "insecure" {
  allocated_storage    = 20
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.m4.large"
  db_name              = "mydb"
  username             = "admin"
  password             = "password"
  publicly_accessible  = true
  storage_encrypted    = false
  multi_az             = false
  backup_retention_period = 0
  skip_final_snapshot  = true
  auto_minor_version_upgrade = false
}

resource "aws_rds_cluster" "insecure" {
  cluster_identifier = "insecure-cluster"
  engine             = "aurora-mysql"
  master_username    = "admin"
  master_password    = "password"
}

resource "aws_db_instance" "no_enhanced_monitoring" {
  allocated_storage = 20
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  username          = "mydbuser"
  password          = "password"
}

resource "aws_db_instance" "default_admin" {
  allocated_storage = 20
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  username          = "postgres"
  password          = "password"
}

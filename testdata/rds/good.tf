resource "aws_db_instance" "secure" {
  allocated_storage       = 20
  engine                  = "mysql"
  engine_version          = "8.0"
  instance_class          = "db.m6g.large"
  db_name                 = "mydb"
  username                = "admin"
  password                = "password"
  publicly_accessible     = false
  storage_encrypted       = true
  multi_az                = true
  backup_retention_period = 7
  skip_final_snapshot     = true
  iam_database_authentication_enabled = true
  auto_minor_version_upgrade = true

  tags = {
    Environment = "production"
    Project     = "example"
  }
}

resource "aws_rds_cluster" "secure" {
  cluster_identifier                  = "secure-cluster"
  engine                              = "aurora-mysql"
  storage_encrypted                   = true
  master_username                     = "admin"
  master_password                     = "password"
  deletion_protection                 = true
  iam_database_authentication_enabled = true
}

resource "aws_db_instance" "enhanced_monitoring" {
  allocated_storage    = 20
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  username             = "mydbuser"
  password             = "password"
  monitoring_interval  = 60
  deletion_protection  = true
}

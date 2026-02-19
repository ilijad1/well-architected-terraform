resource "aws_transfer_server" "bad" {
  protocols = ["FTP", "SFTP"]
}

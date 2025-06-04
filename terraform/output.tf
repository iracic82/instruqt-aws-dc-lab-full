output "domain_controllers" {
  description = "Public IPs of the deployed Windows Server Domain Controllers (RDP enabled)"
  value = {
    dc1 = aws_instance.dc1.public_ip
    dc2 = aws_instance.dc2.public_ip
  }
}

output "rdp_connection_instructions" {
  description = "How to connect to your DCs using RDP"
  value = <<EOT
Download the private key from:
  ${local_sensitive_file.private_key.filename}

Use the following commands (from your local machine):

  # For DC1
  ssh -i ./instruqt-dc-key.pem Administrator@${aws_instance.dc1.public_ip}

  # For DC2
  ssh -i ./instruqt-dc-key.pem Administrator@${aws_instance.dc2.public_ip}

OR

  Open Windows Remote Desktop (mstsc.exe) and connect to:
    ${aws_instance.dc1.public_ip}  or  ${aws_instance.dc2.public_ip}

  Username: Administrator
  Password: (get from AWS Console: select instance → Connect → Get Password, using your private key)
EOT
}

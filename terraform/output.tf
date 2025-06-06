output "domain_controllers" {
  description = "Public IPs of the deployed Windows Server Domain Controllers (RDP enabled)"
  value = {
    dc1 = aws_eip.dc1_eip.public_ip
    dc2 = aws_eip.dc2_eip.public_ip
  }
}

output "rdp_connection_instructions" {
  description = "How to connect to your DCs using RDP"
  value = <<EOT
Download the private key from:
  ${local_sensitive_file.private_key.filename}

Use the following commands (from your local machine):

  # For DC1
  ssh -i ./instruqt-dc-key.pem Administrator@${aws_eip.dc1_eip.public_ip}

  # For DC2
  ssh -i ./instruqt-dc-key.pem Administrator@${aws_eip.dc2_eip.public_ip}

OR

  Open Windows Remote Desktop (mstsc.exe) and connect to:
    ${aws_eip.dc1_eip.public_ip}  or  ${aws_eip.dc2_eip.public_ip}

  Username: Administrator
  Password: (retrieve from AWS Console → Connect → Get Password using your key)
EOT
}

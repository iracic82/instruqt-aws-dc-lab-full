output "domain_controllers" {
  description = "Public IPs of the deployed Windows Server Domain Controllers (RDP enabled)"
  value = {
    dc1 = aws_eip.dc1_eip.public_ip
    dc2 = aws_eip.dc2_eip.public_ip
    dc3 = aws_eip.dc3_eip.public_ip
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

  # For Client
  ssh -i ./instruqt-dc-key.pem Administrator@${aws_eip.dc3_eip.public_ip}

OR

  Open Windows Remote Desktop (mstsc.exe) and connect to:
    ${aws_eip.dc1_eip.public_ip}  or  ${aws_eip.dc2_eip.public_ip}

  Username: Administrator
  Password: (retrieve from AWS Console → Connect → Get Password using your key)
EOT
}

output "infoblox_vnios_public_ips" {
  description = "Public IPs of Infoblox vNIOS GM and GMC"
  value = {
    gm  = aws_eip.gm_eip.public_ip
    gmc = aws_eip.gmc_eip.public_ip
  }
}

output "infoblox_ui_access" {
  description = "Access Infoblox Grid Manager and Grid Member Candidate via HTTPS UI"
  value = <<EOT
Grid Master (GM):
  https://${aws_eip.gm_eip.public_ip}

Grid Member Candidate (GMC):
  https://${aws_eip.gmc_eip.public_ip}

Default UI login:
  Username: admin
  Password: Proba123!
EOT
}


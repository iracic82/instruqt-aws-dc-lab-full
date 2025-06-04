output "dc_public_ips" {
  description = "Public IP addresses of the Domain Controllers"
  value       = [aws_instance.dc1.public_ip, aws_instance.dc2.public_ip]
}

output "private_key_path" {
  description = "Path to the private key for RDP access"
  value       = local_sensitive_file.private_key.filename
}

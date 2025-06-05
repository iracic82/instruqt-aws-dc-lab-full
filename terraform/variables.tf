variable "aws_region" {
  type    = string
  default = "eu-central-1"
}

variable "vpc_cidr" {
  type    = string
  default = "10.100.0.0/16"
}

variable "subnet_a_cidr" {
  type    = string
  default = "10.100.1.0/24"
}

variable "subnet_b_cidr" {
  type    = string
  default = "10.100.2.0/24"
}

variable "windows_admin_password" {
  description = "Password for the Windows Administrator account"
  type        = string
  sensitive   = true
}

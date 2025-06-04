variable "aws_region" {
  default = "us-east-1"
}

variable "Access_Key_AWS" {
  type = string
}

variable "Access_Secret_AWS" {
  type = string
}

variable "vpc_cidr" {
  default = "10.100.0.0/16"
}

variable "subnet_a_cidr" {
  default = "10.100.1.0/24"
}

variable "subnet_b_cidr" {
  default = "10.100.2.0/24"
}

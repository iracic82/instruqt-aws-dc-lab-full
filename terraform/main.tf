terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.20.0"
    }
  }
  required_version = ">= 1.3.0"
}

provider "aws" {
  region     = var.aws_region
  access_key = var.Access_Key_AWS
  secret_key = var.Access_Secret_AWS
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "instruqt-vpc"
  }
}

resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.subnet_a_cidr
  map_public_ip_on_launch = true
  availability_zone       = data.aws_availability_zones.available.names[0]
  tags = {
    Name = "public-a"
  }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.subnet_b_cidr
  map_public_ip_on_launch = true
  availability_zone       = data.aws_availability_zones.available.names[1]
  tags = {
    Name = "public-b"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "igw"
  }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }
  tags = {
    Name = "public-rt"
  }
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_security_group" "rdp_sg" {
  name        = "allow_rdp"
  vpc_id      = aws_vpc.main.id
  description = "Allow RDP"
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "rdp_sg"
  }
}

resource "tls_private_key" "rdp_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "rdp" {
  key_name   = "instruqt-dc-key"
  public_key = tls_private_key.rdp_key.public_key_openssh
}

resource "local_sensitive_file" "private_key" {
  content         = tls_private_key.rdp_key.private_key_pem
  filename        = "${path.module}/instruqt-dc-key.pem"
  file_permission = "0400"
}

data "aws_ami" "windows" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["Windows_Server-2022-English-Full-Base-*"]
  }
}

resource "aws_instance" "dc1" {
  ami                    = data.aws_ami.windows.id
  instance_type          = "t3.medium"
  subnet_id              = aws_subnet.public_a.id
  key_name               = aws_key_pair.rdp.key_name
  vpc_security_group_ids = [aws_security_group.rdp_sg.id]
  user_data              = file("${path.module}/scripts/winrm-init.ps1")
  tags = {
    Name = "dc1"
  }
}

resource "aws_instance" "dc2" {
  ami                    = data.aws_ami.windows.id
  instance_type          = "t3.medium"
  subnet_id              = aws_subnet.public_a.id
  key_name               = aws_key_pair.rdp.key_name
  vpc_security_group_ids = [aws_security_group.rdp_sg.id]
  user_data              = file("${path.module}/scripts/winrm-init.ps1")
  tags = {
    Name = "dc2"
  }
}

output "dc_public_ips" {
  value = [aws_instance.dc1.public_ip, aws_instance.dc2.public_ip]
}

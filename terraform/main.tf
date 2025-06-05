
data "aws_availability_zones" "available" {
  provider = aws.eu-central-1
  state = "available"
}

resource "aws_vpc" "main" {
  provider             = aws.eu-central-1
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "Infoblox-Lab"
  }
}

resource "aws_subnet" "public_a" {
  provider                = aws.eu-central-1
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.subnet_a_cidr
  map_public_ip_on_launch = true
  availability_zone       = data.aws_availability_zones.available.names[0]
  tags = {
    Name = "DC-subnet"
  }
}

resource "aws_subnet" "public_b" {
  provider                = aws.eu-central-1
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.subnet_b_cidr
  map_public_ip_on_launch = true
  availability_zone       = data.aws_availability_zones.available.names[1]
  tags = {
    Name = "Mgmt-subnet"
  }
}

resource "aws_internet_gateway" "gw" {
  provider = aws.eu-central-1
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "igw"
  }
}

resource "aws_route_table" "public_rt" {
  provider = aws.eu-central-1
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
  provider = aws.eu-central-1
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "public_b" {
  provider = aws.eu-central-1
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_security_group" "rdp_sg" {
  provider = aws.eu-central-1
  name        = "allow_rdp"
  vpc_id      = aws_vpc.main.id
  description = "Allow RDP"
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "WinRM HTTPS"
    from_port   = 5986
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "WinRM HTTP (optional, demo only!)"
    from_port   = 5985
    to_port     = 5985
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
  provider = aws.eu-central-1
  key_name   = "instruqt-dc-key"
  public_key = tls_private_key.rdp_key.public_key_openssh
}

resource "local_sensitive_file" "private_key" {
  
  content         = tls_private_key.rdp_key.private_key_pem
  filename        = "${path.module}/instruqt-dc-key.pem"
  file_permission = "0400"
}

data "aws_ami" "windows" {
  provider = aws.eu-central-1
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["Windows_Server-2025-English-Full-Base-*"]
  }
}

resource "aws_instance" "dc1" {
  provider = aws.eu-central-1
  ami                    = data.aws_ami.windows.id
  instance_type          = "t3.medium"
  subnet_id              = aws_subnet.public_a.id
  key_name               = aws_key_pair.rdp.key_name
  vpc_security_group_ids = [aws_security_group.rdp_sg.id]
  user_data = templatefile("./scripts/winrm-init.ps1.tpl", {
    admin_password = var.windows_admin_password
  })
  tags = {
    Name = "dc1"
  }
}

resource "aws_instance" "dc2" {
  provider = aws.eu-central-1
  ami                    = data.aws_ami.windows.id
  instance_type          = "t3.medium"
  subnet_id              = aws_subnet.public_b.id
  key_name               = aws_key_pair.rdp.key_name
  vpc_security_group_ids = [aws_security_group.rdp_sg.id]
  user_data = templatefile("./scripts/winrm-init.ps1.tpl", {
    admin_password = var.windows_admin_password
  })
  tags = {
    Name = "dc2"
  }
}

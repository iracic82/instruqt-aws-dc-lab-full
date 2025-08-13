data "aws_availability_zones" "available" {
  provider = aws.eu-central-1
  state    = "available"
}

data "aws_ami" "windows" {
  provider    = aws.eu-central-1
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Windows_Server-2025-English-Full-Base-*"]
  }
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
  availability_zone       = data.aws_availability_zones.available.names[0]

  tags = {
    Name = "Mgmt-subnet"
  }
}

resource "aws_internet_gateway" "gw" {
  provider = aws.eu-central-1
  vpc_id   = aws_vpc.main.id

  tags = {
    Name = "igw"
  }
}

resource "aws_route_table" "public_rt" {
  provider = aws.eu-central-1
  vpc_id   = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = {
    Name = "public-rt"
  }
}

resource "aws_route_table_association" "public_a" {
  provider       = aws.eu-central-1
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "public_b" {
  provider       = aws.eu-central-1
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_security_group" "rdp_sg" {
  provider    = aws.eu-central-1
  name        = "allow_rdp_and_ad"
  vpc_id      = aws_vpc.main.id
  description = "Allow RDP + Active Directory Ports"

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 5986
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 5985
    to_port     = 5985
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  dynamic "ingress" {
    for_each = toset([
      { from = 53, to = 53, protocol = "tcp" },
      { from = 53, to = 53, protocol = "udp" },
      { from = 1194, to = 1194, protocol = "udp" },
      { from = 2114, to = 2114, protocol = "udp" },
      { from = 8787, to = 8787, protocol = "tcp" },
      { from = 88, to = 88, protocol = "tcp" },
      { from = 88, to = 88, protocol = "udp" },
      { from = 135, to = 135, protocol = "tcp" },
      { from = 389, to = 389, protocol = "tcp" },
      { from = 389, to = 389, protocol = "udp" },
      { from = 445, to = 445, protocol = "tcp" },
      { from = 636, to = 636, protocol = "tcp" },
      { from = 3268, to = 3268, protocol = "tcp" },
      { from = 3269, to = 3269, protocol = "tcp" },
      { from = 49152, to = 65535, protocol = "tcp" }
    ])
    content {
      from_port   = ingress.value.from
      to_port     = ingress.value.to
      protocol    = ingress.value.protocol
      cidr_blocks = ["10.100.0.0/16"]
    }
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
  provider   = aws.eu-central-1
  key_name   = "instruqt-dc-key"
  public_key = tls_private_key.rdp_key.public_key_openssh
}

resource "local_sensitive_file" "private_key" {
  content         = tls_private_key.rdp_key.private_key_pem
  filename        = "${path.module}/instruqt-dc-key.pem"
  file_permission = "0400"
}

resource "aws_eip" "dc1_eip" {
  provider = aws.eu-central-1
  vpc      = true

  tags = {
    Name = "dc1-eip"
  }
}

resource "aws_eip" "dc2_eip" {
  provider = aws.eu-central-1
  vpc      = true

  tags = {
    Name = "dc2-eip"
  }
}

resource "aws_network_interface" "dc1_eni" {
  subnet_id       = aws_subnet.public_a.id
  private_ips     = ["10.100.1.100"]
  security_groups = [aws_security_group.rdp_sg.id]

  tags = {
    Name = "dc1-eni"
  }
}

resource "aws_network_interface" "dc2_eni" {
  subnet_id       = aws_subnet.public_b.id
  private_ips     = ["10.100.2.100"]
  security_groups = [aws_security_group.rdp_sg.id]

  tags = {
    Name = "dc2-eni"
  }
}

resource "aws_instance" "dc1" {
  ami           = data.aws_ami.windows.id
  instance_type = "t3.medium"
  key_name      = aws_key_pair.rdp.key_name

  network_interface {
    network_interface_id = aws_network_interface.dc1_eni.id
    device_index         = 0
  }

  user_data = templatefile("./scripts/winrm-init.ps1.tpl", {
    admin_password = var.windows_admin_password
  })

  tags = {
    Name = "dc1"
  }

  depends_on = [aws_internet_gateway.gw]
}

resource "aws_instance" "dc2" {
  ami           = data.aws_ami.windows.id
  instance_type = "t3.medium"
  key_name      = aws_key_pair.rdp.key_name

  network_interface {
    network_interface_id = aws_network_interface.dc2_eni.id
    device_index         = 0
  }

  user_data = templatefile("./scripts/winrm-init.ps1.tpl", {
    admin_password = var.windows_admin_password
  })

  tags = {
    Name = "dc2"
  }

  depends_on = [aws_internet_gateway.gw]
}

resource "aws_eip_association" "dc1_assoc" {
  network_interface_id = aws_network_interface.dc1_eni.id
  allocation_id        = aws_eip.dc1_eip.id
  private_ip_address   = "10.100.1.100"
}

resource "aws_eip_association" "dc2_assoc" {
  network_interface_id = aws_network_interface.dc2_eni.id
  allocation_id        = aws_eip.dc2_eip.id
  private_ip_address   = "10.100.2.100"
}

# Elastic IP for client
resource "aws_eip" "client_eip" {
  provider = aws.eu-central-1
  vpc      = true
  tags = { Name = "client-vm-eip" }
}

# ENI for client (single NIC)
resource "aws_network_interface" "client_eni" {
  provider        = aws.eu-central-1
  subnet_id       = aws_subnet.public_b.id
  private_ips     = ["10.100.2.111"]
  security_groups = [aws_security_group.rdp_sg.id]
  tags = { Name = "client-vm-eni" }
}

# Windows client instance
resource "aws_instance" "client_vm" {
  provider      = aws.eu-central-1
  ami           = data.aws_ami.windows.id
  instance_type = "t3.medium"
  key_name      = aws_key_pair.rdp.key_name

  network_interface {
    network_interface_id = aws_network_interface.client_eni.id
    device_index         = 0
  }

  user_data = templatefile("./scripts/winrm-init.ps1.tpl", {
    admin_password = var.windows_admin_password
  })

  tags = { Name = "client_vm" }

  depends_on = [aws_internet_gateway.gw]
}

# Associate EIP to client ENI
resource "aws_eip_association" "client_assoc" {
  provider              = aws.eu-central-1
  network_interface_id  = aws_network_interface.client_eni.id
  allocation_id         = aws_eip.client_eip.id
  private_ip_address    = "10.100.2.111"
}

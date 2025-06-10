locals {
  infoblox_ami_id = "ami-008772a29d4c2f558"
}



# --- GM Network Interfaces ---
resource "aws_network_interface" "gm_mgmt" {
  provider        = aws.eu-central-1
  subnet_id       = aws_subnet.public_a.id
  private_ips     = ["10.100.1.10"]
  security_groups = [aws_security_group.rdp_sg.id]

  tags = {
    Name = "gm-mgmt-nic"
  }
}

resource "aws_network_interface" "gm_lan1" {
  provider        = aws.eu-central-1
  subnet_id       = aws_subnet.public_b.id
  private_ips     = ["10.100.2.11"]
  security_groups = [aws_security_group.rdp_sg.id]

  tags = {
    Name = "gm-lan1-nic"
  }
}

# --- GM EC2 Instance ---
resource "aws_instance" "gm" {
  provider      = aws.eu-central-1
  ami           = local.infoblox_ami_id
  instance_type = "m5.2xlarge"
  key_name      = aws_key_pair.rdp.key_name

  network_interface {
    network_interface_id = aws_network_interface.gm_mgmt.id
    device_index         = 0
  }

  network_interface {
    network_interface_id = aws_network_interface.gm_lan1.id
    device_index         = 1
  }

  user_data = <<-EOF
#infoblox-config
temp_license: nios IB-V825 enterprise dns dhcp cloud
remote_console_enabled: y
default_admin_password: "Proba123!"
lan1:
  v4_addr: 10.100.2.11
  v4_netmask: 255.255.255.0
  v4_gw: 10.100.2.1
mgmt:
  v4_addr: 10.100.1.10
  v4_netmask: 255.255.255.0
  v4_gw: 10.100.1.1
EOF

  tags = {
    Name = "Infoblox-GM"
  }
}

# --- EIP for GM (Mgmt) ---
resource "aws_eip" "gm_eip" {
  provider = aws.eu-central-1
  domain   = "vpc"
  tags = {
    Name = "gm-eip"
  }
}

resource "aws_eip_association" "gm_eip_assoc" {
  provider               = aws.eu-central-1
  network_interface_id   = aws_network_interface.gm_lan1.id
  allocation_id          = aws_eip.gm_eip.id
}

# --- GMC Network Interfaces ---
resource "aws_network_interface" "gmc_mgmt" {
  provider        = aws.eu-central-1
  subnet_id       = aws_subnet.public_a.id
  private_ips     = ["10.100.1.20"]
  security_groups = [aws_security_group.rdp_sg.id]

  tags = {
    Name = "gmc-mgmt-nic"
  }
}

resource "aws_network_interface" "gmc_lan1" {
  provider        = aws.eu-central-1
  subnet_id       = aws_subnet.public_b.id
  private_ips     = ["10.100.2.21"]
  security_groups = [aws_security_group.rdp_sg.id]

  tags = {
    Name = "gmc-lan1-nic"
  }
}

# --- GMC EC2 Instance ---
resource "aws_instance" "gmc" {
  provider      = aws.eu-central-1
  ami           = local.infoblox_ami_id
  instance_type = "m5.2xlarge"
  key_name      = aws_key_pair.rdp.key_name

  network_interface {
    network_interface_id = aws_network_interface.gmc_mgmt.id
    device_index         = 0
  }

  network_interface {
    network_interface_id = aws_network_interface.gmc_lan1.id
    device_index         = 1
  }

  user_data = <<-EOF
#infoblox-config
temp_license: nios IB-V825 enterprise dns dhcp cloud
remote_console_enabled: y
default_admin_password: "Proba123!"

lan1:
ip_addr: 10.100.2.11
netmask: 255.255.255.0

mgmt:
ip_addr: 10.100.1.10
netmask: 255.255.255.0
gateway: 10.100.1.1
EOF

  tags = {
    Name = "Infoblox-GMC"
  }
}

# --- EIP for GMC (Mgmt) ---
resource "aws_eip" "gmc_eip" {
  provider = aws.eu-central-1
  domain   = "vpc"
  tags = {
    Name = "gmc-eip"
  }
}

resource "aws_eip_association" "gmc_eip_assoc" {
  provider               = aws.eu-central-1
  network_interface_id   = aws_network_interface.gmc_lan1.id
  allocation_id          = aws_eip.gmc_eip.id
}

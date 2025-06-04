# Instruqt AWS AD/DC Lab

This repository sets up a complete Active Directory and DNS/DHCP-enabled environment on AWS using Terraform and Ansible, tailored for Instruqt tracks.

## Lab Architecture

- **VPC with CIDR:** Custom defined via `variables.tf`
- **Two Subnets:**
  - `subnet_a`: Hosts the Domain Controllers
  - `subnet_b`: Reserved for future use (e.g., clients)
- **Two Windows Server EC2 Instances**:
  - `dc1`: Primary Domain Controller
  - `dc2`: Joins domain and acts as a secondary DC
- **Security Group**:
  - Allows RDP (3389), WinRM (5985), ICMP, and necessary ports
- **Route Table**:
  - With default route to Internet Gateway

## Automation Flow

### Terraform
- Provisions all AWS infrastructure
- Deploys Windows EC2 instances
- Outputs public IPs for remote access
- Generates a `.pem` file for RDP access

### Ansible
- Configures:
  - Active Directory Domain Services
  - DNS Server
  - DHCP Server
- Promotes `dc1` to create a new AD forest
- Joins `dc2` to domain and reboots

## Usage Instructions

1. **Clone the repo in your Instruqt container**
2. **Run the setup script:**
   ```bash
   ./setup/setup.sh
   ```
3. **Terraform will deploy infrastructure**
4. **Ansible will configure the domain controllers**

## Cleanup

Run:
```bash
./teardown/teardown.sh
```

## Requirements

- Instruqt environment with AWS credentials exposed via environment variables
- Internet access for package installation
- Ansible 2.10+
- Terraform >= 1.1

---

© 2025 | Infoblox Labs | Built for training, demos, and secure DNS/AD experimentation
# instruqt-aws-dc-lab-full

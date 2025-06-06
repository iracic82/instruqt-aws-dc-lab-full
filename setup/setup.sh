#!/bin/bash
apt update -y
apt install git -y
wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor | tee /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/hashicorp.list
apt update -y
apt install -y git terraform ansible python3-pip jq
apt install -y netcat-openbsd
apt-get update && apt-get install -y libxml2-utils
pip3 install pywinrm
pip3 install requests

mkdir -p /root/infoblox-lab
git clone https://github.com/iracic82/instruqt-aws-dc-lab-full.git
cp -r /root/instruqt-aws-dc-lab-full /root/infoblox-lab/

echo "export TF_VAR_Access_Key_AWS=${INSTRUQT_AWS_ACCOUNT_INFOBLOX_DEMO_AWS_ACCESS_KEY_ID} " >> /root/.bashrc
echo "export TF_VAR_Access_Secret_AWS=${INSTRUQT_AWS_ACCOUNT_INFOBLOX_DEMO_AWS_SECRET_ACCESS_KEY} " >> /root/.bashrc
echo "export TF_VAR_windows_admin_password=${TF_VAR_windows_admin_password} " >> /root/.bashrc
echo "export DEMO_AWS_ACCESS_KEY_ID=${DEMO_AWS_ACCESS_KEY_ID} " >> /root/.bashrc
echo "export DEMO_AWS_SECRET_ACCESS_KEY=${DEMO_AWS_SECRET_ACCESS_KEY} " >> /root/.bashrc
echo "export DEMO_HOSTED_ZONE_ID=${DEMO_HOSTED_ZONE_ID} " >> /root/.bashrc
echo "export AWS_REGION=eu-central-1" >> /root/.bashrc
source ~/.bashrc

cd /root/infoblox-lab/instruqt-aws-dc-lab-full/terraform
terraform init
terraform apply -auto-approve

sleep 60



# Make sure region is exported NOW for this script/process
export AWS_REGION="eu-central-1"

# --- 5. Guacamole XML Automation (after TF apply) ---
cd /root/infoblox-lab/instruqt-aws-dc-lab-full/terraform

# Fetch DC IPs from TF output (plain text format)
DC1_IP=$(terraform output domain_controllers | grep dc1 | awk -F '"' '{print $4}')
DC2_IP=$(terraform output domain_controllers | grep dc2 | awk -F '"' '{print $4}')

# Export to current session
export DC1_IP
export DC2_IP

# Persist to bashrc
echo "export DC1_IP=${DC1_IP}" >> /root/.bashrc
echo "export DC2_IP=${DC2_IP}" >> /root/.bashrc


# Get Instance IDs
DC1_ID=$(aws ec2 describe-instances --region $AWS_REGION --filters "Name=ip-address,Values=${DC1_IP}" --query "Reservations[].Instances[].InstanceId" --output text)
DC2_ID=$(aws ec2 describe-instances --region $AWS_REGION --filters "Name=ip-address,Values=${DC2_IP}" --query "Reservations[].Instances[].InstanceId" --output text)

if [[ -z "$DC1_ID" || "$DC1_ID" == "None" ]]; then
  echo "ERROR: DC1_ID not found. Check region and IP."
  exit 1
fi
if [[ -z "$DC2_ID" || "$DC2_ID" == "None" ]]; then
  echo "ERROR: DC2_ID not found. Check region and IP."
  exit 1
fi

# Wait and fetch Windows admin passwords
function get_password {
  local instance_id=$1
  local privkey=$2
  for i in {1..12}; do
    pass=$(aws ec2 get-password-data --region $AWS_REGION --instance-id "$instance_id" --priv-launch-key "$privkey" --query 'PasswordData' --output text)
    if [[ "$pass" != "None" && "$pass" != "" ]]; then
      echo "$pass"
      return 0
    fi
    echo "Waiting for password for instance $instance_id..."
    sleep 10
  done
  echo "FAILED-TO-GET-PASSWORD"
}

escape_xml() {
  # Escapes &, <, >, ", and ' for safe XML insertion
  echo "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g' -e "s/'/\&apos;/g"
}

DC1_PASS_RAW=$(get_password "$DC1_ID" ./instruqt-dc-key.pem)
DC2_PASS_RAW=$(get_password "$DC2_ID" ./instruqt-dc-key.pem)

DC1_PASS=$(escape_xml "$DC1_PASS_RAW")
DC2_PASS=$(escape_xml "$DC2_PASS_RAW")

# Write Guacamole XML
mkdir -p /config/guacamole
cat <<EOF > /config/guacamole/user-mapping.xml
<user-mapping>
  <authorize username="instruqt" password="Passw0rd!">
    <connection name="DomainController1">
      <protocol>rdp</protocol>
      <param name="hostname">${DC1_IP}</param>
      <param name="port">3389</param>
      <param name="username">Administrator</param>
      <param name="password">${DC1_PASS}</param>
      <param name="ignore-cert">true</param>
      <param name="resize-method">display-update</param>
      <param name="enable-font-smoothing">true</param>
    </connection>
    <connection name="DomainController2">
      <protocol>rdp</protocol>
      <param name="hostname">${DC2_IP}</param>
      <param name="port">3389</param>
      <param name="username">Administrator</param>
      <param name="password">${DC2_PASS}</param>
      <param name="ignore-cert">true</param>
      <param name="resize-method">display-update</param>
      <param name="enable-font-smoothing">true</param>
    </connection>
  </authorize>
</user-mapping>
EOF


# Path to user-mapping.xml (guacamole XML output)
XML="/config/guacamole/user-mapping.xml"

# Option 1: Parse from Terraform output (replace with your real terraform output logic if needed)
#DC1_IP=$(terraform output domain_controllers | grep dc1 | awk -F '"' '{print $4}')
#DC2_IP=$(terraform output domain_controllers | grep dc2 | awk -F '"' '{print $4}')
#DC1_PASS=$(get_password "$DC1_ID" ./instruqt-dc-key.pem)
#DC2_PASS=$(get_password "$DC2_ID" ./instruqt-dc-key.pem)

# Option 2: Parse directly from user-mapping.xml (requires xmllint, and XML must be well-formed!)
DC1_IP=$(xmllint --xpath 'string(//connection[@name="DomainController1"]/param[@name="hostname"])' "$XML")
DC2_IP=$(xmllint --xpath 'string(//connection[@name="DomainController2"]/param[@name="hostname"])' "$XML")
DC1_PASS=$(xmllint --xpath 'string(//connection[@name="DomainController1"]/param[@name="password"])' "$XML")
DC2_PASS=$(xmllint --xpath 'string(//connection[@name="DomainController2"]/param[@name="password"])' "$XML")

echo "DC1_IP: $DC1_IP"
echo "DC2_IP: $DC2_IP"
echo "DC1_PASS: $DC1_PASS"
echo "DC2_PASS: $DC2_PASS"

# Output to Ansible inventory
cat <<EOF > /root/infoblox-lab/instruqt-aws-dc-lab-full/ansible/inventory.ini
[windows]
dc1 ansible_host=${DC1_IP} ansible_password='Inf0blox2025!'
dc2 ansible_host=${DC2_IP} ansible_password='Inf0blox2025!'

[windows:vars]
ansible_user=Administrator
ansible_connection=winrm
ansible_winrm_transport=basic
ansible_winrm_server_cert_validation=ignore
ansible_port=5985
EOF

echo "Ansible inventory generated at /root/infoblox-lab/instruqt-aws-dc-lab-full/ansible/inventory.ini"

# Write to group_vars/all.yml
cat <<EOF > /root/infoblox-lab/instruqt-aws-dc-lab-full/ansible/group_vars/all.yml
---
# Global variables for all hosts

domain_admin_password: "Inf0blox2025!"
# Optionally, other group/global vars can go here.
EOF

echo "Wrote domain_admin_password to group_vars/all.yml"

#DC1_IP=$(terraform output -json dc_public_ips | jq -r '.[0]')
#DC2_IP=$(terraform output -json dc_public_ips | jq -r '.[1]')

#cat <<EOF > /root/infoblox-lab/instruqt-aws-dc-lab-full/ansible/inventory.ini
#[windows]
##dc1 ansible_host=$DC1_IP
#dc2 ansible_host=$DC2_IP

#[windows:vars]
#ansible_user=Administrator
#ansible_password=P@ssword123
#ansible_connection=winrm
#ansible_winrm_transport=basic
#ansible_winrm_server_cert_validation=ignore
#EOF

cd /root/infoblox-lab/instruqt-aws-dc-lab-full/ansible
ansible-galaxy collection install -r requirements.yml --force
#ansible-playbook -i inventory.ini bootstrap-dc.yml

# Wait until RDP is available on both Domain Controllers
#for ip in "$DC1_IP" "$DC2_IP"; do
#  echo "Waiting for RDP on $ip:3389 to be available..."
 # while ! nc -z "$ip" 3389; do
 #   sleep 1
 # done
 # echo "RDP is now available on $ip:3389"
#done

echo "Guacamole user-mapping.xml created successfully."

# Run Python scripts
cd /root/infoblox-lab/instruqt-aws-dc-lab-full/terraform/scripts
python3 setup_dns.py
sleep 10


# Set AWS creds
cp ~/.aws/credentials /root/infoblox-lab/instruqt-aws-dc-lab-full/terraform

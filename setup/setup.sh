#!/bin/bash
apt update -y
apt install -y git terraform ansible python3-pip jq
pip3 install pywinrm

mkdir -p /root/infoblox-lab
git clone https://github.com/iracic82/Infoblox-PoC.git /root/infoblox-lab || true

echo "export AWS_ACCESS_KEY_ID=${INSTRUQT_AWS_ACCOUNT_INFOBLOX_DEMO_AWS_ACCESS_KEY_ID}" >> ~/.bashrc
echo "export AWS_SECRET_ACCESS_KEY=${INSTRUQT_AWS_ACCOUNT_INFOBLOX_DEMO_AWS_SECRET_ACCESS_KEY}" >> ~/.bashrc
source ~/.bashrc

cd /root/infoblox-lab/Infoblox-PoC/terraform
terraform init
terraform apply -auto-approve

DC1_IP=$(terraform output -json dc_public_ips | jq -r '.[0]')
DC2_IP=$(terraform output -json dc_public_ips | jq -r '.[1]')

cat <<EOF > /root/infoblox-lab/Infoblox-PoC/ansible/inventory.ini
[windows]
dc1 ansible_host=$DC1_IP
dc2 ansible_host=$DC2_IP

[windows:vars]
ansible_user=Administrator
ansible_password=P@ssword123
ansible_connection=winrm
ansible_winrm_transport=basic
ansible_winrm_server_cert_validation=ignore
EOF

cd /root/infoblox-lab/Infoblox-PoC/ansible
ansible-playbook -i inventory.ini bootstrap-dc.yml

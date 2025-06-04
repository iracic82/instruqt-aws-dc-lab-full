#!/bin/bash
cd /root/infoblox-lab/Infoblox-PoC/terraform
echo 'Destroying resources...'
terraform destroy -auto-approve

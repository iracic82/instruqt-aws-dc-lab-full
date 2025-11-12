#!/bin/bash
# ---------------------------------------------------
# Terraform-injected user data for Enterprise Portal
# ---------------------------------------------------

# Exit immediately on error
set -e

# Log everything for debugging
exec > >(tee /var/log/user-data.log | logger -t user-data -s 2>/dev/console) 2>&1

echo "🚀 Starting Enterprise Portal deployment..."

# ---------------------------------------------------
# Variables injected by Terraform
# ---------------------------------------------------
SANDBOX_ID="${sandbox_id}"
LDAP_BASE_DN="${ldap_base_dn}"
LDAP_SERVER="${ldap_server}"
LDAP_USER_SEARCH_BASE="${ldap_user_search_base}"
LDAP_BIND_DN="${ldap_bind_dn}"
LDAP_BIND_PASSWORD="${ldap_bind_password}"
PINGONE_ADMIN_ENV_ID="${pingone_admin_env_id}"
PINGONE_APPLICATION_ID="${pingone_application_id}"
PINGONE_CLIENT_ID="${pingone_client_id}"
PINGONE_CLIENT_SECRET="${pingone_client_secret}"
PINGONE_CLIENT_SECRET_APP="${pingone_client_secret_app}"
PINGONE_ISSUER="${pingone_issuer}"
PINGONE_TARGET_ENV_ID="${pingone_target_env_id}"
AWS_REGION="${aws_region}"

# ---------------------------------------------------
# System setup
# ---------------------------------------------------
yum update -y
yum install -y unzip wget curl jq python3-pip

# ---------------------------------------------------
# Docker setup
# ---------------------------------------------------
yum install -y docker
systemctl enable docker
systemctl start docker
usermod -a -G docker ec2-user

# ---------------------------------------------------
# AWS CLI v2 install
# ---------------------------------------------------
curl -s "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
unzip -q /tmp/awscliv2.zip -d /tmp
/tmp/aws/install || true  # skip if already installed

# ---------------------------------------------------
# Install Python libs for redirect script
# ---------------------------------------------------
pip3 install --quiet python-dotenv requests

# ---------------------------------------------------
# Install Caddy (binary install for reliability)
# ---------------------------------------------------
cd /tmp
wget -q https://github.com/caddyserver/caddy/releases/download/v2.7.6/caddy_2.7.6_linux_amd64.tar.gz
tar xzf caddy_2.7.6_linux_amd64.tar.gz
mv caddy /usr/local/bin/
chmod +x /usr/local/bin/caddy

echo "✅ Caddy installed successfully."

# ---------------------------------------------------
# Docker image pull
# ---------------------------------------------------
docker pull iracic82/enterprise-portal:caddy-test

# ---------------------------------------------------
# Portal setup
# ---------------------------------------------------
mkdir -p /home/ec2-user/portal
chown ec2-user:ec2-user /home/ec2-user/portal

cat > /home/ec2-user/portal/.env <<ENVEOF
FLASK_SECRET_KEY=your-secret-key-here
AUTH_MODE=AD
LDAP_SERVER=${ldap_server}
LDAP_BASE_DN=${ldap_base_dn}
LDAP_BIND_DN=${ldap_bind_dn}
LDAP_BIND_PASSWORD=${ldap_bind_password}
LDAP_USER_SEARCH_BASE=${ldap_user_search_base}
PINGONE_TARGET_ENV_ID=${pingone_target_env_id}
PINGONE_ISSUER=${pingone_issuer}
PINGONE_CLIENT_ID=${pingone_application_id}
PINGONE_CLIENT_SECRET=${pingone_client_secret_app}
PINGONE_REDIRECT_URI=https://student${sandbox_id}.highvelocitynetworking.com/callback
PINGONE_SCOPES=openid profile email
PINGONE_POPULATION_ID=116c337a-ec76-4869-add3-86757a6d517c
ENVEOF

# ---------------------------------------------------
# Start Portal container
# ---------------------------------------------------
docker run -d \
  --name enterprise-portal \
  --restart unless-stopped \
  -p 5045:5045 \
  --env-file /home/ec2-user/portal/.env \
  --health-cmd "curl -f http://localhost:5045/ || exit 1" \
  --health-interval=30s \
  --health-timeout=10s \
  --health-retries=3 \
  iracic82/enterprise-portal:caddy-test

echo "✅ Portal container started."

# ---------------------------------------------------
# Configure and start Caddy reverse proxy
# ---------------------------------------------------
cat > /tmp/Caddyfile <<CADDYEOF
student${sandbox_id}.highvelocitynetworking.com {
    reverse_proxy localhost:5045
}
CADDYEOF

/usr/local/bin/caddy start --config /tmp/Caddyfile --adapter caddyfile >/var/log/caddy.log 2>&1 &

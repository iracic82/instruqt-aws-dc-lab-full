import requests
import os
from urllib.parse import urlparse

# ==== CONFIG ====
GM_IP = "3.65.87.230"  # Replace with real IP
USERNAME = "admin"
PASSWORD = "Proba123!"
WAPI_VERSION = "v2.11"
MEMBER_HOSTNAME = "nios-member1.iracictechguru.com"
MEMBER_IP = "10.100.2.21"
SUBNET_MASK = "255.255.255.0"
GATEWAY = "10.100.2.1"
GRID_MASTER_HOSTNAME = "infoblox.iracictechguru.com"
CLOUD_INIT_FILE = "./cloud-init.yaml"

session = requests.Session()
session.auth = (USERNAME, PASSWORD)
session.verify = False
session.headers.update({"Content-Type": "application/json"})
session.headers.pop("Sec-Fetch-Site", None)  # Remove if exists

# ==== Step 1: Add Offline Member ====
print("Adding offline member...")
add_resp = session.post(
    f"https://{GM_IP}/wapi/{WAPI_VERSION}/member",
    json={
        "host_name": MEMBER_HOSTNAME,
        "platform": "VNIOS",
        "vip_setting": {
            "address": MEMBER_IP,
            "subnet_mask": SUBNET_MASK,
            "gateway": GATEWAY
        }
    }
)
if not add_resp.ok:
    print("❌ WAPI Error Response:")
    print(add_resp.text)
    add_resp.raise_for_status()

# ==== Step 2: Get Member Reference ====
print("Getting member reference...")
ref_resp = session.get(
    f"https://{GM_IP}/wapi/{WAPI_VERSION}/member?host_name={MEMBER_HOSTNAME}"
)
ref_resp.raise_for_status()
member_ref = ref_resp.json()[0]['_ref']

# ==== Step 3: Pre-provision ====
print("Pre-provisioning member...")
preprov_payload = {
    "pre_provisioning": {
        "licenses": ["dns", "dhcp", "enterprise", "nios"],
        "hardware_info": [{"hwtype": "IB-V926"}]
    }
}
session.put(
    f"https://{GM_IP}/wapi/{WAPI_VERSION}/{member_ref}",
    json=preprov_payload
).raise_for_status()

# ==== Step 4: Create Join Token ====
print("Creating join token...")
token_resp = session.post(
    f"https://{GM_IP}/wapi/{WAPI_VERSION}/{member_ref}?_function=create_token",
    json={}
)
token_resp.raise_for_status()
join_token = token_resp.json()["pnode_tokens"][0]["token"]

# ==== Step 5: Get GM Certificate ====
print("Downloading GM certificate metadata...")
cert_meta = session.post(
    f"https://{GM_IP}/wapi/{WAPI_VERSION}/fileop?_function=downloadcertificate",
    json={
        "certificate_usage": "ADMIN",
        "member": GRID_MASTER_HOSTNAME
    }
)
cert_meta.raise_for_status()
cert_url = cert_meta.json()["url"]

# Download the Grid Master's Certificate
print("Downloading certificate file...")
# Patch internal IP in cert_url if needed
parsed_url = urlparse(cert_url)
fixed_cert_url = f"https://{GM_IP}{parsed_url.path}"

print(f"Using corrected cert URL: {fixed_cert_url}")

cert_raw = session.get(fixed_cert_url)
cert_raw.raise_for_status()
cert_pem = cert_raw.text

# ==== Step 6: Generate cloud-init ====
print("Generating cloud-init.yaml...")
with open(CLOUD_INIT_FILE, "w") as f:
    f.write("#infoblox-config\n")
    f.write("temp_license: nios IB-V926 enterprise dns dhcp\n")
    f.write("remote_console_enabled: y\n")
    f.write("lan1:\n")
    f.write(f"  v4_addr: {MEMBER_IP}\n")
    f.write(f"  v4_netmask: {SUBNET_MASK}\n")
    f.write(f"  v4_gw: {GATEWAY}\n")
    f.write("gridmaster:\n")
    f.write(f"  ip_addr: {GM_IP}\n")
    f.write(f"  token: {join_token}\n")
    f.write("  certificate: |\n")
    for line in cert_pem.strip().splitlines():
        f.write(f"    {line}\n")

print(f"✅ cloud-init YAML written to {CLOUD_INIT_FILE}")

#!/usr/bin/env python3

import os
import boto3
import sys
from datetime import datetime

# ---------------------------
# Setup logging
# ---------------------------
log_file = "dns_log_gm_cleanup.txt"
timestamp = datetime.utcnow().isoformat()
log_lines = [f"\n--- DNS Record Cleanup Log [{timestamp}] ---\n"]

def log(msg):
    print(msg)
    log_lines.append(msg + "\n")

# ---------------------------
# Required ENV
# ---------------------------
aws_access_key_id = os.getenv("DEMO_AWS_ACCESS_KEY_ID")
aws_secret_access_key = os.getenv("DEMO_AWS_SECRET_ACCESS_KEY")
region = os.getenv("DEMO_AWS_REGION", "us-east-1")
hosted_zone_id = os.getenv("DEMO_HOSTED_ZONE_ID")
gm_ip = os.getenv("GM_IP")

if not aws_access_key_id or not aws_secret_access_key or not hosted_zone_id:
    log("❌ ERROR: Missing AWS credentials or Hosted Zone ID")
    sys.exit(1)

if not gm_ip:
    log("❌ ERROR: GM_IP environment variable not set")
    sys.exit(1)

fqdn = "infoblox.iracictechguru.com."

# ---------------------------
# Delete A record from Route 53
# ---------------------------
log(f"🧹 Deleting A record: {fqdn} -> {gm_ip}")
try:
    session = boto3.Session(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region
    )
    route53 = session.client("route53")

    route53.change_resource_record_sets(
        HostedZoneId=hosted_zone_id,
        ChangeBatch={
            "Comment": "Delete A record for Infoblox GM",
            "Changes": [
                {
                    "Action": "DELETE",
                    "ResourceRecordSet": {
                        "Name": fqdn,
                        "Type": "A",
                        "TTL": 300,
                        "ResourceRecords": [{"Value": gm_ip}]
                    }
                }
            ]
        }
    )

    log(f"✅ Deleted A record: {fqdn} -> {gm_ip}")

except Exception as e:
    log(f"❌ ERROR: Failed to delete A record: {e}")
    sys.exit(1)

# ---------------------------
# Write log to file
# ---------------------------
with open(log_file, "a") as f:
    f.writelines(log_lines)

log(f"📄 Cleanup log written to {log_file}")

#!/usr/bin/env python3

import os
import boto3
import sys
from datetime import datetime, timezone
import re

# ---------------------------
# Setup logging
# ---------------------------
log_file = "dns_record_cleanup_log.txt"
source_log_file = "dns_record_log.txt"
timestamp = datetime.now(timezone.utc).isoformat()
log_lines = [f"\n--- DNS Record Deletion Log [{timestamp}] ---\n"]

def log(message):
    print(message)
    log_lines.append(message + "\n")

# ---------------------------
# AWS credentials from DEMO_ env vars
# ---------------------------
aws_access_key_id = os.getenv("DEMO_AWS_ACCESS_KEY_ID")
aws_secret_access_key = os.getenv("DEMO_AWS_SECRET_ACCESS_KEY")
region = os.getenv("DEMO_AWS_REGION", "us-east-1")
hosted_zone_id = os.getenv("DEMO_HOSTED_ZONE_ID")

if not aws_access_key_id or not aws_secret_access_key or not hosted_zone_id:
    log("❌ ERROR: DEMO_AWS_ACCESS_KEY_ID, DEMO_AWS_SECRET_ACCESS_KEY, and DEMO_HOSTED_ZONE_ID must be set")
    sys.exit(1)

# ---------------------------
# Parse records from dns_record_log.txt
# ---------------------------
if not os.path.exists(source_log_file):
    log(f"❌ ERROR: {source_log_file} not found")
    sys.exit(1)

records = {}

with open(source_log_file, "r") as f:
    for line in f:
        match = re.search(r"A record.*: (.+?) -> ([\d.]+)", line)
        if match:
            fqdn = match.group(1).strip()
            ip = match.group(2).strip()
            records[fqdn] = ip

if not records:
    log("❌ ERROR: No valid A records found in log file.")
    sys.exit(1)

# ---------------------------
# Create boto3 session
# ---------------------------
session = boto3.Session(
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,
    region_name=region
)

route53 = session.client("route53")

# ---------------------------
# Delete each record
# ---------------------------
for fqdn, ip in records.items():
    log(f"🗑️  Deleting A record: {fqdn} -> {ip}")
    try:
        response = route53.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={
                "Comment": f"Delete A record for {fqdn}",
                "Changes": [
                    {
                        "Action": "DELETE",
                        "ResourceRecordSet": {
                            "Name": fqdn,
                            "Type": "A",
                            "TTL": 300,
                            "ResourceRecords": [{"Value": ip}]
                        }
                    }
                ]
            }
        )
        log(f"✅  Deleted: {fqdn} -> {ip}")
        log(f"📡  Change status: {response['ChangeInfo']['Status']}")
    except route53.exceptions.InvalidChangeBatch as e:
        log(f"⚠️  Record {fqdn} may not exist or already deleted: {e}")
    except Exception as e:
        log(f"❌ Failed to delete A record {fqdn}: {e}")
        sys.exit(1)

# ---------------------------
# Write cleanup log
# ---------------------------
with open(log_file, "a") as f:
    f.writelines(log_lines)

log(f"📄 Cleanup log written to {log_file}")

#!/usr/bin/env python3

import os
import boto3
import sys
from datetime import datetime, timezone

# ---------------------------
# Setup logging
# ---------------------------
log_file = "dns_record_cleanup_log.txt"
timestamp = datetime.now(timezone.utc).isoformat()
log_lines = [f"\n--- DNS Record Deletion Log [{timestamp}] ---\n"]

def log(message):
    print(message)
    log_lines.append(message + "\n")

# ---------------------------
# AWS credentials from env vars
# ---------------------------
aws_access_key_id = os.getenv("DEMO_AWS_ACCESS_KEY_ID")
aws_secret_access_key = os.getenv("DEMO_AWS_SECRET_ACCESS_KEY")
region = os.getenv("DEMO_AWS_REGION", "us-east-1")
hosted_zone_id = os.getenv("DEMO_HOSTED_ZONE_ID")

if not aws_access_key_id or not aws_secret_access_key or not hosted_zone_id:
    log("❌ ERROR: DEMO_AWS_ACCESS_KEY_ID, DEMO_AWS_SECRET_ACCESS_KEY, and DEMO_HOSTED_ZONE_ID must be set")
    sys.exit(1)

# ---------------------------
# Participant + IPs from env
# ---------------------------
participant_id = os.getenv("INSTRUQT_PARTICIPANT_ID")
dc1_ip = os.getenv("DC1_IP")
dc2_ip = os.getenv("DC2_IP")

if not participant_id:
    log("❌ ERROR: INSTRUQT_PARTICIPANT_ID is not set")
    sys.exit(1)

if not dc1_ip or not dc2_ip:
    log("❌ ERROR: DC1_IP and DC2_IP must both be set")
    sys.exit(1)

# ---------------------------
# FQDN mappings for deletion
# ---------------------------
records = {
    f"{participant_id}-dc1.iracictechguru.com.": dc1_ip,
    f"{participant_id}-dc2.iracictechguru.com.": dc2_ip,
}

# ---------------------------
# Initialize boto3 session
# ---------------------------
session = boto3.Session(
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,
    region_name=region
)

route53 = session.client("route53")

# ---------------------------
# Delete A records from Route 53
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
        status = response['ChangeInfo']['Status']
        log(f"✅  Deleted: {fqdn} -> {ip}")
        log(f"📡  Change status: {status}")
    except route53.exceptions.InvalidChangeBatch as e:
        log(f"⚠️  Record {fqdn} not found or already deleted: {e}")
    except Exception as e:
        log(f"❌ Failed to delete A record {fqdn}: {e}")
        sys.exit(1)

# ---------------------------
# Write log to file
# ---------------------------
with open(log_file, "a") as f:
    f.writelines(log_lines)

log(f"📄 Cleanup log written to {log_file}")

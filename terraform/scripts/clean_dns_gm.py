#!/usr/bin/env python3

import os
import boto3
import sys
from datetime import datetime

log_file = "dns_log_gm_cleanup.txt"
timestamp = datetime.utcnow().isoformat()
log_lines = [f"\n--- DNS Record Cleanup Log [{timestamp}] ---\n"]

def log(msg):
    print(msg)
    log_lines.append(msg + "\n")

# --- ENV ---
aws_access_key_id = os.getenv("DEMO_AWS_ACCESS_KEY_ID")
aws_secret_access_key = os.getenv("DEMO_AWS_SECRET_ACCESS_KEY")
region = os.getenv("DEMO_AWS_REGION", "us-east-1")
hosted_zone_id = os.getenv("DEMO_HOSTED_ZONE_ID")
gm_ip = os.getenv("GM_IP")
prefix = os.getenv("INSTRUQT_PARTICIPANT_ID", "").strip()

if not aws_access_key_id or not aws_secret_access_key or not hosted_zone_id:
    log("❌ Missing AWS credentials or Hosted Zone ID")
    sys.exit(1)

if not gm_ip:
    log("❌ GM_IP not set in environment")
    sys.exit(1)

fqdn = f"{prefix + '-' if prefix else ''}infoblox.iracictechguru.com."

# --- Boto3 session ---
session = boto3.Session(
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,
    region_name=region
)
route53 = session.client("route53")

# --- Lookup existing record ---
try:
    response = route53.list_resource_record_sets(
        HostedZoneId=hosted_zone_id,
        StartRecordName=fqdn,
        StartRecordType="A",
        MaxItems="1"
    )
    records = response["ResourceRecordSets"]
    if not records or records[0]["Name"] != fqdn:
        log(f"❌ No matching A record found for {fqdn}")
        sys.exit(1)

    record = records[0]
    ttl = record["TTL"]
    values = record["ResourceRecords"]

    log(f"➡️  Deleting A record: {fqdn} with TTL {ttl} and value(s): {[v['Value'] for v in values]}")

    route53.change_resource_record_sets(
        HostedZoneId=hosted_zone_id,
        ChangeBatch={
            "Comment": f"Delete A record for {fqdn}",
            "Changes": [
                {
                    "Action": "DELETE",
                    "ResourceRecordSet": {
                        "Name": fqdn,
                        "Type": "A",
                        "TTL": ttl,
                        "ResourceRecords": values
                    }
                }
            ]
        }
    )

    log(f"✅ Successfully deleted: {fqdn}")

except Exception as e:
    log(f"❌ ERROR: {e}")
    sys.exit(1)

# --- Write log ---
with open(log_file, "a") as f:
    f.writelines(log_lines)

log(f"📄 Log written to {log_file}")

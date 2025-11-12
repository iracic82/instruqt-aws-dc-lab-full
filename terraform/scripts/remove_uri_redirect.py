#!/usr/bin/env python3
"""
Script to REMOVE one redirect URI from a PingOne OIDC Application
Uses INSTRUQT_PARTICIPANT_ID from environment for dynamic redirect URL
"""

import requests
import json
import base64
import os
from dotenv import load_dotenv

load_dotenv()

# Configuration
ENVIRONMENT_ID = os.getenv('TF_VAR_pingone_target_env_id')
APPLICATION_ID = os.getenv('TF_VAR_pingone_application_id')
REGION = 'northamerica'

# Worker App Credentials
WORKER_CLIENT_ID = os.getenv('PINGONE_CLIENT_ID')
WORKER_CLIENT_SECRET = os.getenv('PINGONE_CLIENT_SECRET')
WORKER_ENV_ID = os.getenv('PINGONE_ADMIN_ENV_ID')
PARTICIPANT_ID = os.getenv('INSTRUQT_PARTICIPANT_ID')

if not PARTICIPANT_ID:
    raise RuntimeError("❌ Missing environment variable INSTRUQT_PARTICIPANT_ID")

# Build redirect URI dynamically
target_uri = f"https://student{PARTICIPANT_ID}.highvelocitynetworking.com/callback"

# PingOne API Base URLs
if REGION == 'europe':
    API_BASE = 'https://api.pingone.eu'
    AUTH_BASE = 'https://auth.pingone.eu'
else:
    API_BASE = 'https://api.pingone.com'
    AUTH_BASE = 'https://auth.pingone.com'

def get_access_token():
    """Get access token using client credentials"""
    auth_url = f'{AUTH_BASE}/{WORKER_ENV_ID}/as/token'
    creds = f"{WORKER_CLIENT_ID}:{WORKER_CLIENT_SECRET}"
    encoded = base64.b64encode(creds.encode()).decode()

    headers = {
        'Authorization': f'Basic {encoded}',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {'grant_type': 'client_credentials'}

    resp = requests.post(auth_url, headers=headers, data=data)
    resp.raise_for_status()
    return resp.json()['access_token']

def remove_one_redirect_uri(access_token, uri_to_remove):
    """Remove a specific redirect URI"""
    url = f'{API_BASE}/v1/environments/{ENVIRONMENT_ID}/applications/{APPLICATION_ID}'
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    print(f"Fetching current application configuration...")
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    app_config = resp.json()

    redirect_uris = app_config.get('redirectUris', [])
    print(f"\nCurrent Redirect URIs ({len(redirect_uris)}):")
    for u in redirect_uris:
        print(f"  - {u}")

    if uri_to_remove not in redirect_uris:
        print(f"\n⚠️ URI not found: {uri_to_remove}")
        return app_config

    updated_uris = [u for u in redirect_uris if u != uri_to_remove]

    payload = {
        "name": app_config.get("name"),
        "enabled": app_config.get("enabled"),
        "type": app_config.get("type"),
        "protocol": app_config.get("protocol"),
        "tokenEndpointAuthMethod": app_config.get("tokenEndpointAuthMethod"),
        "grantTypes": app_config.get("grantTypes"),
        "responseTypes": app_config.get("responseTypes"),
        "redirectUris": updated_uris,
        "pkceEnforcement": app_config.get("pkceEnforcement"),
        "refreshTokenDuration": app_config.get("refreshTokenDuration"),
        "refreshTokenRollingDuration": app_config.get("refreshTokenRollingDuration"),
    }

    print(f"\n🗑️ Removing URI: {uri_to_remove}")
    resp = requests.put(url, headers=headers, json=payload)

    if resp.status_code != 200:
        print(f"\nError Response ({resp.status_code}):\n{resp.text}")
    else:
        print(f"\n✅ Successfully removed URI!")

    updated_config = resp.json()
    print(f"\nUpdated Redirect URIs ({len(updated_config.get('redirectUris', []))}):")
    for u in updated_config.get('redirectUris', []):
        print(f"  - {u}")

    return updated_config

def main():
    print(f"PingOne Redirect URI Removal")
    print("=" * 60)
    print(f"Environment: {ENVIRONMENT_ID}")
    print(f"Application: {APPLICATION_ID}")
    print(f"Participant ID: {PARTICIPANT_ID}")
    print("=" * 60)
    print(f"\nRedirect URI to remove:\n{target_uri}\n")

    access_token = get_access_token()
    print("✅ Authenticated successfully")

    remove_one_redirect_uri(access_token, target_uri)

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

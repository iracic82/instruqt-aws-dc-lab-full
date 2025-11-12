#!/usr/bin/env python3
"""
Script to add one redirect URI to a PingOne OIDC Application
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
test_uri = f"https://student{PARTICIPANT_ID}.highvelocitynetworking.com/callback"

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

    credentials = f"{WORKER_CLIENT_ID}:{WORKER_CLIENT_SECRET}"
    encoded = base64.b64encode(credentials.encode()).decode()

    headers = {
        'Authorization': f'Basic {encoded}',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    data = {'grant_type': 'client_credentials'}

    response = requests.post(auth_url, headers=headers, data=data)
    response.raise_for_status()
    return response.json()['access_token']

def add_one_redirect_uri(access_token, new_uri):
    """Add one redirect URI to the existing list"""
    url = f'{API_BASE}/v1/environments/{ENVIRONMENT_ID}/applications/{APPLICATION_ID}'

    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    print("Fetching current application configuration...")
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    current_config = response.json()

    current_uris = current_config.get('redirectUris', [])
    print(f"\nCurrent Redirect URIs ({len(current_uris)}):")
    for uri in current_uris:
        print(f"  - {uri}")

    if new_uri in current_uris:
        print(f"\n⚠️ URI already exists: {new_uri}")
        return current_config

    updated_uris = current_uris + [new_uri]

    payload = {
        "name": current_config.get("name"),
        "enabled": current_config.get("enabled"),
        "type": current_config.get("type"),
        "protocol": current_config.get("protocol"),
        "tokenEndpointAuthMethod": current_config.get("tokenEndpointAuthMethod"),
        "grantTypes": current_config.get("grantTypes"),
        "responseTypes": current_config.get("responseTypes"),
        "redirectUris": updated_uris,
        "pkceEnforcement": current_config.get("pkceEnforcement"),
        "refreshTokenDuration": current_config.get("refreshTokenDuration"),
        "refreshTokenRollingDuration": current_config.get("refreshTokenRollingDuration"),
    }

    print(f"\n\n➕ Adding new URI: {new_uri}")
    response = requests.put(url, headers=headers, json=payload)

    if response.status_code != 200:
        print(f"\nError Response ({response.status_code}):\n{response.text}")
    else:
        print(f"\n✅ Successfully added!")

    updated_config = response.json()
    print(f"\nUpdated Redirect URIs ({len(updated_config.get('redirectUris', []))}):")
    for uri in updated_config.get('redirectUris', []):
        print(f"  - {uri}")

    return updated_config

def main():
    print(f"PingOne Redirect URI Update")
    print("=" * 60)
    print(f"Environment: {ENVIRONMENT_ID}")
    print(f"Application: {APPLICATION_ID}")
    print(f"Participant ID: {PARTICIPANT_ID}")
    print("=" * 60)
    print(f"\nRedirect URI to add:\n{test_uri}\n")

    access_token = get_access_token()
    print("✅ Authenticated successfully")

    add_one_redirect_uri(access_token, test_uri)

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

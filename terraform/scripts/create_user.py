import os
import json
import requests

BASE_URL = "https://csp.infoblox.com/v2"
TOKEN = os.environ.get("Infoblox_Token")
SANDBOX_ID = os.environ.get("INSTRUQT_PARTICIPANT_ID")  # Used as user name
USER_EMAIL = os.environ.get("INSTRUQT_EMAIL")            # Used as user email
USER_ID_FILE = "user_id.txt"

GROUP_IDS = [
    "identity/groups/4e54e56e-f0e9-4669-9d44-640b9802c044",
    "identity/groups/876452b7-15ab-4748-8172-0bb6047572e8"
]

# === Validate environment ===
if not TOKEN or not SANDBOX_ID or not USER_EMAIL:
    print("❌ Environment variables missing. Please set Infoblox_Token, INSTRUQT_PARTICIPANT_ID, and INSTRUQT_EMAIL.")
    exit(1)

# === Prepare request ===
headers = {
    "Authorization": f"token {TOKEN}",
    "Content-Type": "application/json",
    "Accept": "application/json"
}

payload = {
    "name": SANDBOX_ID,
    "email": USER_EMAIL,
    "type": "interactive",
    "group_ids": GROUP_IDS
}

endpoint = f"{BASE_URL}/users"

# === Execute request ===
try:
    print(f"📤 Sending POST to {endpoint} to create user '{SANDBOX_ID}'...")
    response = requests.post(endpoint, headers=headers, data=json.dumps(payload))
    response.raise_for_status()

    result = response.json()
    print("✅ User created successfully:")
    print(json.dumps(result, indent=2))

    # === Extract and save user ID ===
    user_id = result.get("result", {}).get("id")
    if user_id and user_id.startswith("identity/users/"):
        user_id = user_id.split("/")[-1]
        with open(USER_ID_FILE, "w") as f:
            f.write(user_id)
        print(f"📝 User ID saved to {USER_ID_FILE}: {user_id}")
    else:
        print("⚠️ User ID not found or in unexpected format.")

except requests.exceptions.HTTPError as http_err:
    print(f"❌ HTTP Error: {http_err}")
    print(f"Response: {response.text}")
except Exception as e:
    print(f"❌ Unexpected Error: {e}")

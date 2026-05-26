"""
test_webhook.py — send a fake vulnerability alert to your local server.

Use this to test your pipeline without waiting for GitHub Dependabot to fire.
Just make sure your server is running (uvicorn main:app --port 3000) before running this.
"""

import requests
import hashlib
import hmac
import json
import os
from dotenv import load_dotenv

load_dotenv()

# ── Build a realistic fake webhook payload ─────────────────────────────────
payload = {
    "action": "create",
    "alert": {
        "dependency": {
            "package": {
                "name": "requests",
                "ecosystem": "pip"
            }
        },
        "security_advisory": {
            "patched_versions": ">= 2.31.0",
            "summary": "Requests vulnerable to proxy-authorization header leak"
        }
    },
    "repository": {
        "name": "test-auto-patcher",        # ← change this
        "owner": {
            "login": "Sarvjais12"  # ← change this
        }
    }
}

payload_bytes = json.dumps(payload).encode("utf-8")

# ── Sign it exactly the way GitHub would ──────────────────────────────────
secret = os.getenv("GITHUB_WEBHOOK_SECRET", "").encode()
signature = "sha256=" + hmac.new(secret, payload_bytes, hashlib.sha256).hexdigest()

# ── Fire it at your local server ──────────────────────────────────────────
response = requests.post(
    "http://localhost:3000/webhook",
    data=payload_bytes,
    headers={
        "Content-Type": "application/json",
        "X-Hub-Signature-256": signature,
        "X-GitHub-Event": "repository_vulnerability_alert"
    }
)

print(f"Status : {response.status_code}")
print(f"Response: {response.json()}")
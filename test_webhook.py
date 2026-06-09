"""
test_webhook.py — Fire a synthetic vulnerability alert at your local server.

Simulates exactly what GitHub sends for a repository_vulnerability_alert event,
signed with the same HMAC-SHA256 method. Use this to test without waiting for
Dependabot to detect a real vulnerability.

Prerequisites:
    1. Copy .env.example → .env and fill in your values
    2. Start the server:  uvicorn main:app --port 3000
    3. Run this script:   python test_webhook.py
"""

import hashlib
import hmac
import json
import os
import sys

import requests
from dotenv import load_dotenv

load_dotenv()


# ── Test parameters — edit these to match your repo ──────────────────────────

REPO_OWNER   = "Sarvjais12"
REPO_NAME    = "test-auto-patcher"
PACKAGE_NAME = "requests"
PATCHED_VER  = ">= 2.31.0"
SERVER_URL   = "http://localhost:3000/webhook"


# ── Build a realistic fake webhook payload ────────────────────────────────────

payload = {
    "action": "create",
    "alert": {
        "dependency": {
            "package": {
                "name": PACKAGE_NAME,
                "ecosystem": "pip",
            },
        },
        "security_advisory": {
            "patched_versions": PATCHED_VER,
            "summary": "Requests vulnerable to proxy-authorization header leak",
        },
    },
    "repository": {
        "name": REPO_NAME,
        "owner": {
            "login": REPO_OWNER,
        },
    },
}

# Use compact separators so the bytes we sign are the exact bytes we send
payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")


# ── Resolve the correct secret (mirrors the server-side lookup logic) ─────────

env_key = (
    f"WEBHOOK_SECRET_{REPO_OWNER}_{REPO_NAME}"
    .upper()
    .replace("-", "_")
    .replace(".", "_")
)
secret_str = os.getenv(env_key) or os.getenv("GITHUB_WEBHOOK_SECRET", "")

if not secret_str:
    print(
        f"\nERROR: No webhook secret found.\n"
        f"  Set {env_key} or GITHUB_WEBHOOK_SECRET in your .env file.\n",
        file=sys.stderr,
    )
    sys.exit(1)

secret    = secret_str.encode()
signature = "sha256=" + hmac.new(secret, payload_bytes, hashlib.sha256).hexdigest()


# ── Send the request ──────────────────────────────────────────────────────────

print(f"\n→  Server  : {SERVER_URL}")
print(f"   Repo    : {REPO_OWNER}/{REPO_NAME}")
print(f"   Package : {PACKAGE_NAME} → {PATCHED_VER}")
print(f"   Secret  : {'per-repo (' + env_key + ')' if os.getenv(env_key) else 'global (GITHUB_WEBHOOK_SECRET)'}\n")

try:
    resp = requests.post(
        SERVER_URL,
        data=payload_bytes,
        headers={
            "Content-Type":          "application/json",
            "X-Hub-Signature-256":   signature,
            "X-GitHub-Event":        "repository_vulnerability_alert",
        },
        timeout=15,
    )
    print(f"Status   : {resp.status_code}")
    print(f"Response : {resp.json()}")
    print()
    if resp.status_code == 200:
        print("✅  Webhook accepted. Watch your server logs — the patch pipeline is running.")
    else:
        print("❌  Server returned a non-200 status. Check server logs for details.")

except requests.exceptions.ConnectionError:
    print(
        "\nERROR: Connection refused.\n"
        "  Is the server running?  →  uvicorn main:app --port 3000\n",
        file=sys.stderr,
    )
    sys.exit(1)

except requests.exceptions.Timeout:
    print("\nERROR: Request timed out after 15 seconds.\n", file=sys.stderr)
    sys.exit(1)

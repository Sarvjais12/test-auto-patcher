import os
import base64
import hashlib
import hmac
from fastapi import FastAPI, Request, HTTPException
from github import Github
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

# ── Clients ──────────────────────────────────────────────────────────────────
groq_client   = Groq(api_key=os.getenv("GROQ_API_KEY"))
github_client = Github(os.getenv("GITHUB_TOKEN"))


# ── Helpers ───────────────────────────────────────────────────────────────────

def verify_github_signature(payload_bytes: bytes, signature_header: str):
    secret = os.getenv("GITHUB_WEBHOOK_SECRET", "").encode()
    mac = hmac.new(secret, msg=payload_bytes, digestmod=hashlib.sha256)
    expected = "sha256=" + mac.hexdigest()
    if not hmac.compare_digest(expected, signature_header):
        raise HTTPException(status_code=401, detail="Signature mismatch — not from GitHub")


def find_manifest(repo):
    """
    Look for the dependency file in the root of the repo.
    We check requirements.txt first (Python), then package.json (Node).
    Returns (path, decoded_content, file_sha) or (None, None, None).
    """
    for path in ["requirements.txt", "package.json"]:
        try:
            file_obj = repo.get_contents(path)
            # GitHub sends file content as Base64 — we decode it to plain text
            content = base64.b64decode(file_obj.content).decode("utf-8")
            return path, content, file_obj.sha
        except Exception:
            continue
    return None, None, None


def ask_groq_to_fix(file_content: str, dep_name: str, target_ver: str) -> str:
    """
    Send the manifest file + the vulnerability info to Groq (Llama 3).
    We explicitly tell it: raw file only, no markdown, no explanations.
    """
    response = groq_client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a strict backend utility that edits dependency files. "
                    "Your output must be ONLY the raw updated file contents. "
                    "No markdown code fences. No backticks. No explanations. Just the file."
                )
            },
            {
                "role": "user",
                "content": (
                    f"Edit this file to upgrade the package '{dep_name}' "
                    f"so it satisfies the version constraint: '{target_ver}'.\n\n"
                    f"Here is the current file:\n\n{file_content}"
                )
            }
        ],
        temperature=0.1  # keep it deterministic — we want a precise file edit, not creativity
    )
    return response.choices[0].message.content.strip()


def open_pull_request(repo, manifest_path: str, fixed_content: str, file_sha: str, dep_name: str):
    """
    4-step GitHub API sequence to push the fix and open a PR:
      A. Get the SHA of the latest commit on main
      B. Create a new branch off that SHA
      C. Commit the updated file onto that branch
      D. Open the Pull Request
    """
    # A — find where main currently is
    main_branch = repo.get_branch("main")
    main_sha    = main_branch.commit.sha

    # B — create fix branch
    branch_name = "fix/security-update"
    try:
        repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=main_sha)
        print(f"🌿  Created branch: {branch_name}")
    except Exception:
        # branch already exists from a previous run — that's fine, just reuse it
        print(f"⚠️   Branch '{branch_name}' already exists — reusing it")

    # C — push the patched file
    repo.update_file(
        path=manifest_path,
        message=f"fix: upgrade {dep_name} to a patched version",
        content=fixed_content,
        sha=file_sha,
        branch=branch_name
    )
    print(f"📝  Committed updated {manifest_path} to {branch_name}")

    # D — open the PR
    pr = repo.create_pull(
        title="🔒 [AI Patch] Upgrade vulnerable dependency",
        body=(
            f"### Automated Security Patch\n\n"
            f"**Package:** `{dep_name}`\n"
            f"**Action:** Upgraded to a safe version\n\n"
            f"This PR was opened automatically by the GitHub Auto-Patcher.\n"
            f"Please review the change before merging."
        ),
        head=branch_name,
        base="main"
    )
    print(f"✅  Pull Request opened: {pr.html_url}")


# ── Main pipeline ─────────────────────────────────────────────────────────────

def run_patch_pipeline(repo_owner: str, repo_name: str, dep_name: str, target_ver: str):
    print(f"\n🚨  Vulnerability detected!")
    print(f"    Package  : {dep_name}")
    print(f"    Fix to   : {target_ver}")
    print(f"    Repo     : {repo_owner}/{repo_name}\n")

    repo = github_client.get_repo(f"{repo_owner}/{repo_name}")

    # Step 2 — read the manifest
    manifest_path, file_content, file_sha = find_manifest(repo)
    if not manifest_path:
        print("❌  Couldn't find requirements.txt or package.json — nothing to patch.")
        return

    print(f"📄  Found manifest: {manifest_path}")

    # Step 3 — get the AI fix
    print("🤖  Asking Groq to generate the patch...")
    fixed_content = ask_groq_to_fix(file_content, dep_name, target_ver)
    print("✅  Groq returned the patched file\n")

    # Step 4 — push and open PR
    open_pull_request(repo, manifest_path, fixed_content, file_sha, dep_name)
    print("\n🎉  Done! Check your GitHub repo for the new Pull Request.\n")


# ── Webhook endpoint ──────────────────────────────────────────────────────────

@app.post("/webhook")
async def webhook(request: Request):
    """
    GitHub sends a POST here every time a repository_vulnerability_alert fires.
    We verify it's real, extract the key info, and kick off the patch pipeline.
    """
    payload_bytes = await request.body()

    # Verify the request is genuinely from GitHub
    signature = request.headers.get("X-Hub-Signature-256", "")
    verify_github_signature(payload_bytes, signature)

    payload = await request.json()
    action  = payload.get("action", "")

    # We only care about newly-created alerts, not dismissals or auto-dismissals
    if action != "create":
        print(f"ℹ️   Webhook received but action was '{action}' — skipping.")
        return {"status": "ignored", "reason": f"action was '{action}'"}

    # Pull the four fields we need
    repo_owner = payload["repository"]["owner"]["login"]
    repo_name  = payload["repository"]["name"]
    dep_name   = payload["alert"]["dependency"]["package"]["name"]
    target_ver = payload["alert"]["security_advisory"]["patched_versions"]

    run_patch_pipeline(repo_owner, repo_name, dep_name, target_ver)

    return {"status": "patch pipeline completed"}


# ── Health check (handy to confirm the server is alive) ──────────────────────

@app.get("/")
def health():
    return {"status": "GitHub Auto-Patcher is running 🚀"}
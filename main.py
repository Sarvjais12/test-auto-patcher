"""
main.py — GitHub Auto-Patcher

Receives GitHub repository_vulnerability_alert webhook events, asks Groq
(Llama 3.3-70b) to patch the dependency manifest, and opens a Pull Request
with the fix — all without human triage.

Security design decisions:
  - Per-repo webhook secrets: a leaked secret for one repo cannot be used to
    forge payloads for any other repo this service handles (see _get_webhook_secret).
  - GITHUB_TOKEN must be a fine-grained PAT scoped ONLY to the target repos,
    with Contents (Read & write) and Pull requests (Read & write) permissions.
    Do NOT use a classic token with the broad 'repo' scope.
  - Signature verification uses hmac.compare_digest (constant-time) to prevent
    timing-based secret extraction.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime

from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from github import Github, GithubException
from groq import Groq

load_dotenv()


# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# ── App lifespan (startup validation) ────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Validate critical env vars at startup so problems surface immediately."""
    missing = [v for v in ("GITHUB_TOKEN", "GROQ_API_KEY") if not os.getenv(v)]
    if missing:
        logger.warning("Missing environment variables: %s", ", ".join(missing))

    has_any_secret = os.getenv("GITHUB_WEBHOOK_SECRET") or any(
        k.startswith("WEBHOOK_SECRET_") for k in os.environ
    )
    if not has_any_secret:
        logger.error(
            "No webhook secret configured — every incoming request will be rejected. "
            "Set GITHUB_WEBHOOK_SECRET (or per-repo secrets) in your .env."
        )
    yield


app = FastAPI(lifespan=lifespan)


# ── API clients ───────────────────────────────────────────────────────────────

groq_client   = Groq(api_key=os.getenv("GROQ_API_KEY"))
github_client = Github(os.getenv("GITHUB_TOKEN"))


# ── Security helpers ──────────────────────────────────────────────────────────

def _get_webhook_secret(repo_owner: str, repo_name: str) -> bytes:
    """
    Return the webhook secret for a specific repo.

    We support per-repo secrets to contain blast radius: if one repo's webhook
    configuration is ever leaked, an attacker cannot forge valid payloads for
    any other repo this service handles.

    Convention (env var): WEBHOOK_SECRET_{OWNER}_{REPO}
      e.g. github.com/alice/my-api  →  WEBHOOK_SECRET_ALICE_MY_API
           (uppercased, hyphens and dots replaced with underscores)

    Falls back to the global GITHUB_WEBHOOK_SECRET if no per-repo secret is
    set, but logs a warning so operators know which repos still share it.
    """
    env_key = (
        f"WEBHOOK_SECRET_{repo_owner}_{repo_name}"
        .upper()
        .replace("-", "_")
        .replace(".", "_")
    )
    per_repo = os.getenv(env_key)
    if per_repo:
        return per_repo.encode()

    global_secret = os.getenv("GITHUB_WEBHOOK_SECRET", "")
    if not global_secret:
        # We can't safely process this request — refuse it so the caller knows
        raise HTTPException(status_code=500, detail="No webhook secret configured for this repo")

    logger.warning(
        "No per-repo secret found for %s/%s (expected env var: %s). "
        "Falling back to shared GITHUB_WEBHOOK_SECRET.",
        repo_owner, repo_name, env_key,
    )
    return global_secret.encode()


def verify_signature(payload_bytes: bytes, signature_header: str, secret: bytes) -> None:
    """
    Verify the GitHub HMAC-SHA256 payload signature.

    hmac.compare_digest performs a constant-time comparison, which prevents
    timing attacks that could otherwise be used to brute-force the secret.
    """
    if not signature_header:
        raise HTTPException(status_code=401, detail="Missing X-Hub-Signature-256 header")

    mac      = hmac.new(secret, msg=payload_bytes, digestmod=hashlib.sha256)
    expected = "sha256=" + mac.hexdigest()

    if not hmac.compare_digest(expected, signature_header):
        raise HTTPException(status_code=401, detail="Signature mismatch — not from GitHub")


# ── Core pipeline helpers ─────────────────────────────────────────────────────

def find_manifest(repo):
    """
    Locate the dependency manifest file in the repo root.

    Tries requirements.txt first (Python), then package.json (Node).
    Returns (path, decoded_content, file_sha), or (None, None, None) if neither exists.

    Only silences 404s — other GitHub errors (auth failures, rate-limits, etc.)
    are logged as warnings so they don't hide real infrastructure problems.
    """
    for path in ("requirements.txt", "package.json"):
        try:
            file_obj = repo.get_contents(path)
            content  = base64.b64decode(file_obj.content).decode("utf-8")
            return path, content, file_obj.sha
        except GithubException as exc:
            if exc.status == 404:
                continue  # File simply doesn't exist here — try the next
            logger.warning("GitHub error reading '%s' (status %s): %s", path, exc.status, exc)
            continue
        except Exception as exc:
            logger.warning("Unexpected error reading '%s': %s", path, exc)
            continue

    return None, None, None


def ask_groq_to_fix(file_content: str, dep_name: str, target_ver: str) -> str:
    """
    Ask Groq / Llama 3 to upgrade dep_name in the manifest to satisfy target_ver.
    Returns the raw file content (no markdown, no explanations).
    """
    response = groq_client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a strict backend utility that edits dependency files. "
                    "Your output must be ONLY the raw updated file contents. "
                    "No markdown code fences. No backticks. No explanations. "
                    "Return the file exactly as it would appear on disk."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Edit this file to upgrade the package '{dep_name}' "
                    f"so it satisfies the version constraint '{target_ver}'.\n\n"
                    f"Current file:\n\n{file_content}"
                ),
            },
        ],
        temperature=0.1,  # low temperature for deterministic file edits
    )

    result = response.choices[0].message.content.strip()

    # Strip accidental markdown fences — the model sometimes ignores its instructions
    if result.startswith("```"):
        lines  = result.splitlines()
        end    = len(lines) - 1 if lines and lines[-1].strip() == "```" else len(lines)
        result = "\n".join(lines[1:end]).strip()

    return result


def open_pull_request(
    repo,
    manifest_path: str,
    fixed_content:  str,
    dep_name:       str,
    target_ver:     str,
) -> object:
    """
    Four-step GitHub API workflow to push the patch and open a PR.

    A. Resolve the current tip of the default branch
    B. Create a fresh, uniquely-named fix branch off that tip
    C. Fetch the file SHA directly from the new branch (avoids stale-SHA 409s
       if main was pushed to between find_manifest and now), then commit
    D. Open the Pull Request

    If step C fails, the orphaned branch is deleted before raising so the
    repo isn't littered with empty branches.
    """
    # A — resolve default branch (never assume it's called "main")
    default_branch = repo.default_branch
    base_sha       = repo.get_branch(default_branch).commit.sha

    # B — unique branch name: concurrent alerts or re-runs never collide
    safe_dep    = dep_name.replace("/", "-").replace(".", "-").lower()
    ts          = datetime.now().strftime("%Y%m%d%H%M%S")
    branch_name = f"fix/{safe_dep}-{ts}"

    repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=base_sha)
    logger.info("Created branch: %s", branch_name)

    # C — fetch the file's SHA from our new branch to avoid stale-SHA conflicts
    #     (main could have been updated between find_manifest and now)
    try:
        file_on_branch = repo.get_contents(manifest_path, ref=branch_name)
        current_sha    = file_on_branch.sha
    except GithubException as exc:
        logger.error("Could not read %s from branch %s: %s", manifest_path, branch_name, exc)
        _delete_branch(repo, branch_name)
        raise RuntimeError(f"Could not read manifest from {branch_name}") from exc

    try:
        repo.update_file(
            path=manifest_path,
            message=f"fix: upgrade {dep_name} to satisfy {target_ver}",
            content=fixed_content,
            sha=current_sha,
            branch=branch_name,
        )
    except GithubException as exc:
        # Commit failed — don't try to open a PR against an unchanged branch
        logger.error("Failed to commit patch to %s: %s", branch_name, exc)
        _delete_branch(repo, branch_name)
        raise RuntimeError(f"Commit failed on {branch_name}: {exc}") from exc

    logger.info("Committed updated %s → %s", manifest_path, branch_name)

    # D — open the PR
    pr = repo.create_pull(
        title=f"🔒 [Auto-Patch] Upgrade {dep_name} → {target_ver}",
        body=(
            f"### Automated Security Patch\n\n"
            f"| Field | Value |\n"
            f"|---|---|\n"
            f"| Package | `{dep_name}` |\n"
            f"| Patched constraint | `{target_ver}` |\n\n"
            f"Generated by the GitHub Auto-Patcher. "
            f"**Review the diff carefully before merging.**"
        ),
        head=branch_name,
        base=default_branch,
    )
    logger.info("Pull Request opened: %s", pr.html_url)
    return pr


def _delete_branch(repo, branch_name: str) -> None:
    """Best-effort branch cleanup — logs but never raises."""
    try:
        repo.get_git_ref(f"heads/{branch_name}").delete()
        logger.info("Cleaned up empty branch: %s", branch_name)
    except Exception as exc:
        logger.warning("Could not delete branch %s: %s", branch_name, exc)


# ── End-to-end pipeline ───────────────────────────────────────────────────────

def run_patch_pipeline(
    repo_owner: str,
    repo_name:  str,
    dep_name:   str,
    target_ver: str,
) -> None:
    """
    Orchestrates the full patch flow. Each step fails fast with a clear log
    message rather than cascading into confusing downstream errors.

    This is a synchronous function called from a FastAPI BackgroundTask, which
    runs it in a thread-pool executor — so blocking GitHub / Groq API calls
    don't stall the event loop or delay responses to GitHub's webhook delivery.
    """
    logger.info(
        "Patch pipeline started — package=%s  constraint=%s  repo=%s/%s",
        dep_name, target_ver, repo_owner, repo_name,
    )

    # Step 1 — connect to the repo
    try:
        repo = github_client.get_repo(f"{repo_owner}/{repo_name}")
    except GithubException as exc:
        logger.error("Cannot access repo %s/%s: %s", repo_owner, repo_name, exc)
        return

    # Step 2 — locate the dependency manifest
    manifest_path, file_content, _ = find_manifest(repo)
    if not manifest_path:
        logger.error(
            "No supported manifest (requirements.txt / package.json) found in %s/%s",
            repo_owner, repo_name,
        )
        return
    logger.info("Found manifest: %s", manifest_path)

    # Step 3 — generate the patch via Groq
    try:
        fixed_content = ask_groq_to_fix(file_content, dep_name, target_ver)
    except Exception as exc:
        logger.error("Groq API error: %s", exc)
        return

    if not fixed_content:
        logger.error("Groq returned empty content — aborting")
        return

    if fixed_content.strip() == file_content.strip():
        # Groq understood the task but the dep was already at the right version,
        # or it made no change — either way, a PR would be a no-op.
        logger.warning(
            "Groq output is identical to the original file for %s. "
            "The package may already satisfy %s — skipping PR.",
            dep_name, target_ver,
        )
        return

    # Step 4 — push the fix and open the PR
    try:
        pr = open_pull_request(repo, manifest_path, fixed_content, dep_name, target_ver)
        logger.info("Pipeline complete. PR: %s", pr.html_url)
    except Exception as exc:
        logger.error("PR creation failed: %s", exc)


# ── Webhook endpoint ──────────────────────────────────────────────────────────

@app.post("/webhook")
async def webhook(request: Request, background_tasks: BackgroundTasks):
    """
    Receives GitHub repository_vulnerability_alert events.

    The response is sent immediately (before the patch pipeline runs) so
    GitHub's 10-second webhook delivery timeout is never a concern.
    The pipeline executes asynchronously via BackgroundTasks.

    Request flow:
      1. Check X-GitHub-Event header — bounce anything that isn't a vuln alert
      2. Parse repo owner + name (needed to look up the right webhook secret)
      3. Verify HMAC-SHA256 signature
      4. Validate action == "create"
      5. Extract dep name + target version
      6. Queue the patch pipeline and return 200 immediately
    """
    payload_bytes = await request.body()

    # 1. Event type gate — handle ping (wiring test) and reject unknowns early
    event_type = request.headers.get("X-GitHub-Event", "")
    if event_type == "ping":
        logger.info("GitHub ping received — webhook is configured correctly")
        return {"status": "pong"}
    if event_type != "repository_vulnerability_alert":
        logger.info("Ignoring unsupported event type: '%s'", event_type)
        return {"status": "ignored", "reason": f"unsupported event '{event_type}'"}

    # 2. Parse payload to identify the repo (required before secret lookup)
    try:
        payload = json.loads(payload_bytes)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    repo_owner = payload.get("repository", {}).get("owner", {}).get("login", "")
    repo_name  = payload.get("repository", {}).get("name", "")
    if not repo_owner or not repo_name:
        raise HTTPException(status_code=400, detail="Payload is missing repository info")

    # 3. Verify signature using the correct per-repo (or fallback) secret
    secret    = _get_webhook_secret(repo_owner, repo_name)
    signature = request.headers.get("X-Hub-Signature-256", "")
    verify_signature(payload_bytes, signature, secret)

    # 4. We only act on newly-created alerts, not dismissals or auto-resolutions
    action = payload.get("action", "")
    if action != "create":
        logger.info("Alert action='%s' — nothing to do", action)
        return {"status": "ignored", "reason": f"action='{action}'"}

    # 5. Extract the two fields the pipeline needs, with clear error messages
    try:
        dep_name   = payload["alert"]["dependency"]["package"]["name"]
        target_ver = payload["alert"]["security_advisory"]["patched_versions"]
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=f"Malformed payload — missing field: {exc}")

    # 6. Queue and respond — GitHub gets its 200 before we touch a single API
    background_tasks.add_task(run_patch_pipeline, repo_owner, repo_name, dep_name, target_ver)
    return {"status": "patch pipeline queued"}


# ── Health check ──────────────────────────────────────────────────────────────

@app.get("/")
def health():
    return {"status": "GitHub Auto-Patcher is running 🚀"}

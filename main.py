"""
main.py — GitHub Auto-Patcher

Receives GitHub repository_vulnerability_alert webhook events, asks Groq
(Llama 3.3-70b) to patch the dependency manifest, and opens a Pull Request
with the fix — fully automated, no human triage required.

Security design:
  - Per-repo webhook secrets limit blast radius (see _get_webhook_secret).
  - GITHUB_TOKEN must be a fine-grained PAT scoped only to target repos with
    Contents (Read & write) and Pull requests (Read & write) permissions.
    Never use a classic token with the broad 'repo' scope.
  - Signature comparison is constant-time (hmac.compare_digest) to prevent
    timing-based secret extraction.
  - X-GitHub-Delivery header is logged for full request traceability.
  - Duplicate PR guard prevents PR spam when the same alert fires repeatedly.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from github import Auth, Github, GithubException
from groq import Groq

load_dotenv()


# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# ── App lifespan (startup diagnostics) ───────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Surface config problems at startup rather than silently failing on the first request."""
    missing = [v for v in ("GITHUB_TOKEN", "GROQ_API_KEY") if not os.getenv(v)]
    if missing:
        logger.warning("Missing environment variables: %s", ", ".join(missing))

    has_any_secret = os.getenv("GITHUB_WEBHOOK_SECRET") or any(
        k.startswith("WEBHOOK_SECRET_") for k in os.environ
    )
    if not has_any_secret:
        logger.error(
            "No webhook secret configured — every incoming request will be rejected. "
            "Set GITHUB_WEBHOOK_SECRET or WEBHOOK_SECRET_OWNER_REPO in .env."
        )
    yield


app = FastAPI(lifespan=lifespan)


# ── API clients ───────────────────────────────────────────────────────────────
# timeout=30  : prevents a hung GitHub API call from blocking the thread indefinitely
# timeout=60.0: gives the LLM enough time to respond without hanging the pipeline forever
_gh_token     = os.getenv("GITHUB_TOKEN")
github_client = Github(auth=Auth.Token(_gh_token) if _gh_token else None, timeout=30)
groq_client   = Groq(api_key=os.getenv("GROQ_API_KEY"), timeout=60.0)


# ── Security helpers ──────────────────────────────────────────────────────────

def _get_webhook_secret(repo_owner: str, repo_name: str) -> bytes:
    """
    Return the HMAC secret for a specific repo.

    Per-repo secrets limit blast radius: if one repo's webhook config leaks,
    an attacker cannot forge valid payloads for any other repo this service
    handles.

    Convention: WEBHOOK_SECRET_{OWNER}_{REPO}  (uppercase, hyphens/dots → _)
      e.g. github.com/alice/my-api.v2  →  WEBHOOK_SECRET_ALICE_MY_API_V2

    Falls back to GITHUB_WEBHOOK_SECRET with a warning so operators know
    which repos still need a dedicated secret.
    """
    env_key = (
        f"WEBHOOK_SECRET_{repo_owner}_{repo_name}"
        .upper()
        .replace("-", "_")
        .replace(".", "_")
    )
    per_repo = os.getenv(env_key)
    if per_repo:                        # non-empty per-repo secret — best case
        return per_repo.encode()

    global_secret = os.getenv("GITHUB_WEBHOOK_SECRET", "")
    if not global_secret:               # catches both missing and empty-string
        raise HTTPException(
            status_code=500,
            detail="No webhook secret configured for this repo",
        )

    logger.warning(
        "No per-repo secret for %s/%s (expected env var: %s). "
        "Falling back to shared GITHUB_WEBHOOK_SECRET.",
        repo_owner, repo_name, env_key,
    )
    return global_secret.encode()


def verify_signature(payload_bytes: bytes, signature_header: str, secret: bytes) -> None:
    """
    Verify the GitHub HMAC-SHA256 signature.

    hmac.compare_digest is constant-time — it won't leak the secret length
    through a timing side-channel even if an attacker sends crafted payloads.
    """
    if not signature_header:
        raise HTTPException(
            status_code=401,
            detail="Missing X-Hub-Signature-256 header",
        )

    mac      = hmac.new(secret, msg=payload_bytes, digestmod=hashlib.sha256)
    expected = "sha256=" + mac.hexdigest()

    if not hmac.compare_digest(expected, signature_header):
        raise HTTPException(status_code=401, detail="Signature mismatch")


# ── Core pipeline helpers ─────────────────────────────────────────────────────

def find_manifest(repo) -> tuple:
    """
    Locate the dependency manifest in the repo root.
    Tries requirements.txt (Python), then package.json (Node).
    Returns (path, decoded_content, file_sha) or (None, None, None).

    Only silences 404s — other GitHub errors are logged as warnings so they
    don't hide real infrastructure problems (auth failures, rate-limits, etc.).
    """
    for path in ("requirements.txt", "package.json"):
        try:
            file_obj = repo.get_contents(path)

            # get_contents returns a list when the path resolves to a directory
            if isinstance(file_obj, list):
                logger.warning(
                    "'%s' resolved to a directory listing, not a file — skipping", path
                )
                continue

            content = base64.b64decode(file_obj.content).decode("utf-8")
            return path, content, file_obj.sha

        except GithubException as exc:
            if exc.status == 404:
                continue          # file simply doesn't exist here — try next
            logger.warning("GitHub error reading '%s' (status %s): %s", path, exc.status, exc)
            continue

        except (ValueError, UnicodeDecodeError) as exc:
            # Non-UTF-8 content is almost certainly a repo misconfiguration;
            # log it and try the next manifest type rather than crashing.
            logger.warning("Could not decode '%s' as UTF-8: %s", path, exc)
            continue

        except Exception as exc:
            logger.warning("Unexpected error reading '%s': %s", path, exc)
            continue

    return None, None, None


def ask_groq_to_fix(file_content: str, dep_name: str, target_ver: str) -> str:
    """
    Ask Groq / Llama 3 to upgrade dep_name in the manifest to satisfy target_ver.
    Returns the raw updated file content (no markdown, no prose).

    The prompt explicitly tells the model the CURRENT version line so it knows
    exactly which token to change, reducing ambiguity and identical-output cases.
    """
    # Extract the current version spec line so Groq has exact context
    current_spec = _extract_dep_line(file_content, dep_name)
    context = (
        f"The current entry for '{dep_name}' in this file is: {current_spec!r}."
        if current_spec
        else f"'{dep_name}' does not yet appear in this file."
    )

    response = groq_client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a strict backend utility that edits dependency files. "
                    "Your output must be ONLY the raw updated file contents. "
                    "No markdown code fences. No backticks. No explanations. "
                    "Change ONLY the specified package version. "
                    "Return the file exactly as it would appear on disk."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"{context}\n\n"
                    f"Edit this file so that '{dep_name}' satisfies the version "
                    f"constraint '{target_ver}'. Change only the '{dep_name}' line; "
                    f"leave every other line exactly as-is.\n\n"
                    f"Current file:\n\n{file_content}"
                ),
            },
        ],
        temperature=0.1,   # deterministic edits — precision over creativity
    )

    result = response.choices[0].message.content.strip()

    # Strip accidental markdown fences — the model sometimes ignores its own instructions
    if result.startswith("```"):
        lines  = result.splitlines()
        end    = len(lines) - 1 if lines and lines[-1].strip() == "```" else len(lines)
        result = "\n".join(lines[1:end]).strip()

    return result


def _extract_dep_line(file_content: str, dep_name: str) -> Optional[str]:
    """
    Return the exact line specifying dep_name in a requirements.txt / package.json.
    Used to give Groq precise context about what it needs to change.

    Normalises both the dep name AND each line for underscore↔hyphen equivalence
    (PEP 508: 'python-dotenv' and 'python_dotenv' are the same distribution).
    """
    # Normalise once so comparisons are underscore/hyphen-agnostic
    dep_lower = dep_name.lower().replace("_", "-")
    for line in file_content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # requirements.txt style: "requests==2.28.0", "python-dotenv>=1.0.0", etc.
        normalized = stripped.lower().replace("_", "-")
        if normalized.startswith(dep_lower):
            remainder = normalized[len(dep_lower):]
            if not remainder or remainder[0] in ("=", ">", "<", "~", "!", "[", " ", ";"):
                return stripped
    return None


def _find_open_pr_for_dep(repo, dep_name: str) -> Optional[str]:
    """
    Return the HTML URL of an existing open Auto-Patch PR for dep_name, or None.

    This is the idempotency guard: if Dependabot fires the same vulnerability
    alert twice (e.g. after a push retry), we skip creating a second PR that
    would be identical to the first and clutter the PR queue.

    A missed duplicate is far less damaging than a missed real patch, so on any
    GitHub API error we log a warning and allow the pipeline to continue.
    """
    try:
        for pr in repo.get_pulls(state="open", base=repo.default_branch):
            if "[Auto-Patch]" in pr.title and dep_name.lower() in pr.title.lower():
                return pr.html_url
    except GithubException as exc:
        logger.warning(
            "Could not check for existing PRs (will proceed anyway): %s", exc
        )
    return None


def _delete_branch(repo, branch_name: str) -> None:
    """Best-effort orphan-branch cleanup. Logs but never raises."""
    try:
        repo.get_git_ref(f"heads/{branch_name}").delete()
        logger.info("Cleaned up empty branch: %s", branch_name)
    except Exception as exc:
        logger.warning("Could not delete branch '%s': %s", branch_name, exc)


def open_pull_request(
    repo,
    manifest_path: str,
    fixed_content:  str,
    dep_name:       str,
    target_ver:     str,
) -> object:
    """
    Four-step GitHub API workflow:
      A. Resolve the current tip of the default branch
      B. Create a fresh, uniquely-named fix branch off that tip
      C. Fetch the file SHA directly from our new branch — avoids stale-SHA 409s
         if main was pushed between find_manifest and now — then commit
      D. Open the Pull Request

    If step C or D fails, the orphaned branch is cleaned up before raising so
    the repo isn't littered with empty branches.
    """
    # A — never hardcode "main"; repos legitimately use master/trunk/etc.
    default_branch = repo.default_branch
    base_sha       = repo.get_branch(default_branch).commit.sha

    # B — unique branch name: concurrent alerts and re-runs never collide.
    #     Truncate dep name at 40 chars to stay well under GitHub's 255-char ref limit.
    #     %f adds microseconds so two simultaneous alerts for the same dep can't clash.
    safe_dep    = dep_name.replace("/", "-").replace(".", "-").lower()[:40]
    ts          = datetime.now().strftime("%Y%m%d%H%M%S%f")
    branch_name = f"fix/{safe_dep}-{ts}"

    repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=base_sha)
    logger.info("Created branch: %s", branch_name)

    # C — re-fetch file SHA from our branch, not from main.
    #     This is the only safe approach: main could have been pushed between
    #     find_manifest (which read from main) and now.
    try:
        file_on_branch = repo.get_contents(manifest_path, ref=branch_name)

        # Defensive: get_contents returns a list for directories
        if isinstance(file_on_branch, list):
            raise ValueError(f"'{manifest_path}' resolved to a directory on {branch_name}")

        current_sha = file_on_branch.sha

    except (GithubException, ValueError) as exc:
        logger.error(
            "Could not read '%s' from branch '%s': %s", manifest_path, branch_name, exc
        )
        _delete_branch(repo, branch_name)
        raise RuntimeError(f"Could not read manifest from {branch_name}") from exc

    # Commit — abort immediately if this fails; opening a PR against an
    # unchanged branch would be noise and is misleading.
    try:
        repo.update_file(
            path=manifest_path,
            message=f"fix: upgrade {dep_name} to satisfy {target_ver}",
            content=fixed_content,
            sha=current_sha,
            branch=branch_name,
        )
    except GithubException as exc:
        logger.error("Failed to commit patch to '%s': %s", branch_name, exc)
        _delete_branch(repo, branch_name)
        raise RuntimeError(f"Commit failed on {branch_name}: {exc}") from exc

    logger.info("Committed updated '%s' → '%s'", manifest_path, branch_name)

    # D — open the PR. Even this can fail (branch protections, PRs disabled, etc.)
    try:
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
    except GithubException as exc:
        # Branch + commit succeeded; only the PR failed.
        # The branch is still useful (can be PRed manually), so don't clean it up.
        logger.error(
            "Failed to open PR from '%s' → '%s': %s", branch_name, default_branch, exc
        )
        raise RuntimeError(f"PR creation failed: {exc}") from exc

    logger.info("Pull Request opened: %s", pr.html_url)
    return pr


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

    Called from a FastAPI BackgroundTask which runs it in a thread-pool
    executor — blocking GitHub / Groq API calls do not stall the event loop
    and GitHub's 10-second webhook delivery timeout is never a concern.
    """
    logger.info(
        "Patch pipeline started — package=%s  constraint=%s  repo=%s/%s",
        dep_name, target_ver, repo_owner, repo_name,
    )

    # 1 — connect to the repo
    try:
        repo = github_client.get_repo(f"{repo_owner}/{repo_name}")
    except GithubException as exc:
        logger.error("Cannot access repo %s/%s: %s", repo_owner, repo_name, exc)
        return

    # 2 — idempotency: skip if an open Auto-Patch PR already exists for this dep
    existing_pr = _find_open_pr_for_dep(repo, dep_name)
    if existing_pr:
        logger.info(
            "Open Auto-Patch PR already exists for '%s': %s — skipping duplicate",
            dep_name, existing_pr,
        )
        return

    # 3 — locate the dependency manifest
    manifest_path, file_content, _ = find_manifest(repo)
    if not manifest_path:
        logger.error(
            "No supported manifest (requirements.txt / package.json) found in %s/%s",
            repo_owner, repo_name,
        )
        return

    logger.info("Found manifest: %s", manifest_path)

    # 4 — generate the patch via Groq
    try:
        fixed_content = ask_groq_to_fix(file_content, dep_name, target_ver)
    except Exception as exc:
        logger.error("Groq API error: %s", exc)
        return

    if not fixed_content:
        logger.error("Groq returned empty content — aborting to avoid data loss")
        return

    if fixed_content.strip() == file_content.strip():
        # Groq made no change — the package may already satisfy the constraint,
        # or the model misunderstood. A no-diff PR is useless noise.
        logger.warning(
            "Groq output is identical to the original for '%s'. "
            "The package may already satisfy '%s'. Skipping PR.\n"
            "  → To trigger a real patch: downgrade '%s' to an old version in "
            "your repo's requirements.txt (e.g. %s==2.28.0) and try again.",
            dep_name, target_ver, dep_name, dep_name,
        )
        return

    # 5 — push the fix and open the PR
    try:
        pr = open_pull_request(repo, manifest_path, fixed_content, dep_name, target_ver)
        logger.info("Pipeline complete ✓  PR: %s", pr.html_url)
    except Exception as exc:
        logger.error("PR creation failed: %s", exc)


# ── Webhook helpers ───────────────────────────────────────────────────────────

# GitHub has two event types for dependency vulnerabilities:
#   repository_vulnerability_alert — legacy, action="create"
#   dependabot_alert               — current, action="created", different schema
# We support both so the service keeps working as GitHub migrates users.
_VULN_EVENTS = frozenset({"repository_vulnerability_alert", "dependabot_alert"})


def _extract_target_version(payload: dict, event_type: str) -> Optional[str]:
    """
    Extract the patched/target version from either event schema.

    repository_vulnerability_alert:
        alert.security_advisory.patched_versions  (e.g. ">= 2.31.0")

    dependabot_alert:
        alert.security_vulnerability.first_patched_version.identifier  (e.g. "2.31.0")

    Returns None when no fix is available yet (patched_versions is null, the
    advisory pre-dates a fix, etc.).  Callers treat None as "skip gracefully".
    """
    try:
        if event_type == "dependabot_alert":
            vuln  = (payload.get("alert") or {}).get("security_vulnerability") or {}
            patch = vuln.get("first_patched_version") or {}
            ver   = patch.get("identifier")
        else:
            ver = payload["alert"]["security_advisory"]["patched_versions"]
        return ver or None          # treat empty string the same as None
    except (KeyError, TypeError):
        return None


# ── Webhook endpoint ──────────────────────────────────────────────────────────

@app.post("/webhook")
async def webhook(request: Request, background_tasks: BackgroundTasks):
    """
    Receives GitHub repository_vulnerability_alert events.

    Responds immediately (before the patch pipeline runs) so GitHub's
    10-second webhook delivery timeout is never a concern. The pipeline
    executes asynchronously via FastAPI's BackgroundTasks.

    Request flow:
      1. X-GitHub-Event gate — reject anything that isn't a vuln alert
      2. Parse repo info — needed to look up the right per-repo secret
      3. Verify HMAC-SHA256 signature
      4. Validate action == "create"
      5. Extract dep name + target version
      6. Queue pipeline, return 200 immediately
    """
    payload_bytes = await request.body()
    delivery_id   = request.headers.get("X-GitHub-Delivery", "local-test")

    # 1 — event type gate
    event_type = request.headers.get("X-GitHub-Event", "")
    if event_type == "ping":
        logger.info("GitHub ping received [delivery=%s] — webhook wiring confirmed", delivery_id)
        return {"status": "pong"}
    if event_type not in _VULN_EVENTS:
        logger.info(
            "Ignoring event type '%s' [delivery=%s]", event_type, delivery_id
        )
        return {"status": "ignored", "reason": f"unsupported event '{event_type}'"}

    # 2 — parse before signature verification so we can look up the right secret
    try:
        payload = json.loads(payload_bytes)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Direct key access (not chained .get) so a null owner/name raises TypeError,
    # caught cleanly, rather than silently propagating None into downstream code.
    try:
        repo_owner = payload["repository"]["owner"]["login"]
        repo_name  = payload["repository"]["name"]
    except (KeyError, TypeError):
        raise HTTPException(status_code=400, detail="Payload missing repository info")

    if not repo_owner or not repo_name:
        raise HTTPException(status_code=400, detail="Empty repository owner or name")

    # 3 — signature verification (per-repo secret where possible)
    secret    = _get_webhook_secret(repo_owner, repo_name)
    signature = request.headers.get("X-Hub-Signature-256", "")
    verify_signature(payload_bytes, signature, secret)

    # 4 — action gate: "create" for legacy event, "created" for dependabot_alert
    action = payload.get("action", "")
    if action not in ("create", "created"):
        logger.info(
            "Alert action='%s' [delivery=%s] — nothing to do", action, delivery_id
        )
        return {"status": "ignored", "reason": f"action='{action}'"}

    # 5 — extract dep name (both schemas share the same path for this field)
    try:
        dep_name = payload["alert"]["dependency"]["package"]["name"]
    except (KeyError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=f"Malformed payload — missing dep info: {exc}")

    if not dep_name:
        raise HTTPException(status_code=400, detail="Empty dependency name in payload")

    # 5b — extract target version (schema differs between the two event types)
    target_ver = _extract_target_version(payload, event_type)
    if not target_ver:
        # No known fix yet (patched_versions is null) — nothing we can do
        logger.info(
            "No patched version available for '%s' [delivery=%s] — skipping",
            dep_name, delivery_id,
        )
        return {"status": "skipped", "reason": "no patched version available yet"}

    logger.info(
        "Vulnerability alert [delivery=%s]: %s → %s in %s/%s",
        delivery_id, dep_name, target_ver, repo_owner, repo_name,
    )

    # 6 — queue and respond; GitHub gets its 200 before we touch a single API
    background_tasks.add_task(
        run_patch_pipeline, repo_owner, repo_name, dep_name, target_ver
    )
    return {"status": "patch pipeline queued"}


# ── Health check ──────────────────────────────────────────────────────────────

@app.get("/")
def health():
    return {"status": "GitHub Auto-Patcher is running 🚀"}

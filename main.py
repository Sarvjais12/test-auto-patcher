"""
main.py — GitHub Auto-Patcher

Dependabot tells you what's broken. This fixes it.

When a vulnerability alert fires, the service reads the manifest, asks Groq
(Llama 3.3-70b) to patch the dependency, commits the fix, and opens a PR.
The whole thing usually takes under 10 seconds from alert to open PR.

A few things I was deliberate about:
  - each repo gets its own webhook secret so one leak doesn't blow up everything
  - GitHub token is scoped to only what this actually needs (Contents + PRs)
  - HMAC check uses compare_digest instead of == because == short-circuits,
    which leaves a timing side-channel an attacker could use to brute-force
    the secret byte by byte. compare_digest always takes the same time.
  - webhook responds to GitHub immediately and patches in the background,
    so we never hit the 10-second delivery timeout
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


# ── logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# ── startup check ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # better to know about missing config immediately than to find out
    # when the first real alert comes in at 2am
    missing = [v for v in ("GITHUB_TOKEN", "GROQ_API_KEY") if not os.getenv(v)]
    if missing:
        logger.warning("Missing env vars: %s — server will start but requests will fail", ", ".join(missing))

    has_secret = os.getenv("GITHUB_WEBHOOK_SECRET") or any(
        k.startswith("WEBHOOK_SECRET_") for k in os.environ
    )
    if not has_secret:
        logger.error("No webhook secret set — every request will be rejected. Set GITHUB_WEBHOOK_SECRET in .env")
    yield


app = FastAPI(lifespan=lifespan)


# ── clients ───────────────────────────────────────────────────────────────────

# 30s on GitHub so a slow API call doesn't freeze the worker thread forever.
# Groq gets 60s — the model can be sluggish on cold starts.
_gh_token     = os.getenv("GITHUB_TOKEN")
github_client = Github(auth=Auth.Token(_gh_token) if _gh_token else None, timeout=30)
groq_client   = Groq(api_key=os.getenv("GROQ_API_KEY"), timeout=60.0)


# ── security ──────────────────────────────────────────────────────────────────

def _get_webhook_secret(repo_owner: str, repo_name: str) -> bytes:
    """
    Per-repo secrets mean a leaked secret is contained to one repo, not all of them.
    The env var name follows the pattern WEBHOOK_SECRET_{OWNER}_{REPO} (uppercased,
    hyphens and dots become underscores). Falls back to the global secret if there's
    no per-repo one, but logs a warning so I remember to set one up properly.
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

    fallback = os.getenv("GITHUB_WEBHOOK_SECRET", "")
    if not fallback:
        raise HTTPException(status_code=500, detail="No webhook secret configured for this repo")

    logger.warning(
        "Using shared fallback secret for %s/%s — ideally set %s in .env",
        repo_owner, repo_name, env_key,
    )
    return fallback.encode()


def verify_signature(payload_bytes: bytes, signature_header: str, secret: bytes) -> None:
    if not signature_header:
        raise HTTPException(status_code=401, detail="Missing X-Hub-Signature-256 header")

    expected = "sha256=" + hmac.new(secret, msg=payload_bytes, digestmod=hashlib.sha256).hexdigest()

    # compare_digest is constant-time — stops someone from measuring response
    # time to figure out how many bytes of the signature are correct
    if not hmac.compare_digest(expected, signature_header):
        raise HTTPException(status_code=401, detail="Signature mismatch")


# ── manifest helpers ──────────────────────────────────────────────────────────

def find_manifest(repo) -> tuple:
    """
    Looks for requirements.txt first (Python), then package.json (Node).
    Only ignores 404s — anything else (auth error, rate limit) gets logged
    because I want to know if something is actually broken.
    """
    for path in ("requirements.txt", "package.json"):
        try:
            file_obj = repo.get_contents(path)

            # get_contents returns a list when the path is a directory, not a file
            if isinstance(file_obj, list):
                logger.warning("'%s' is a directory, not a file — skipping", path)
                continue

            content = base64.b64decode(file_obj.content).decode("utf-8")
            return path, content, file_obj.sha

        except GithubException as exc:
            if exc.status == 404:
                continue
            logger.warning("GitHub error on '%s' (status %s): %s", path, exc.status, exc)
            continue

        except (ValueError, UnicodeDecodeError) as exc:
            # binary content in a dependency file is almost always a misconfiguration
            logger.warning("Couldn't decode '%s' as UTF-8: %s", path, exc)
            continue

        except Exception as exc:
            logger.warning("Unexpected error reading '%s': %s", path, exc)
            continue

    return None, None, None


def _extract_dep_line(file_content: str, dep_name: str) -> Optional[str]:
    """
    Finds the exact line in the manifest for dep_name so we can hand Groq
    precise context about what it needs to change.

    PEP 508 says python-dotenv and python_dotenv are the same package, so
    I normalise both the dep name and each line before comparing — otherwise
    you miss matches when GitHub and the manifest use different forms.
    """
    dep_lower = dep_name.lower().replace("_", "-")
    for line in file_content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        normalized = stripped.lower().replace("_", "-")
        if normalized.startswith(dep_lower):
            remainder = normalized[len(dep_lower):]
            if not remainder or remainder[0] in ("=", ">", "<", "~", "!", "[", " ", ";"):
                return stripped
    return None


# ── LLM patch ─────────────────────────────────────────────────────────────────

def ask_groq_to_fix(file_content: str, dep_name: str, target_ver: str) -> str:
    """
    Sends the manifest to Groq with instructions to upgrade dep_name.

    I pull out the current version line and include it explicitly in the prompt
    because without it the model sometimes returns the file completely unchanged
    (it gets confused about what it's supposed to edit). Giving it the exact
    line to change cuts down on that significantly.
    """
    current_spec = _extract_dep_line(file_content, dep_name)
    context = (
        f"The current entry for '{dep_name}' is: {current_spec!r}."
        if current_spec
        else f"'{dep_name}' doesn't appear in this file yet."
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
                    f"Edit this file so that '{dep_name}' satisfies '{target_ver}'. "
                    f"Change only the '{dep_name}' line — leave everything else exactly as-is.\n\n"
                    f"File:\n\n{file_content}"
                ),
            },
        ],
        temperature=0.1,  # low temp = more deterministic, less creative = less likely to hallucinate
    )

    result = response.choices[0].message.content.strip()

    # the model sometimes wraps the output in backtick fences despite being told not to
    if result.startswith("```"):
        lines  = result.splitlines()
        end    = len(lines) - 1 if lines and lines[-1].strip() == "```" else len(lines)
        result = "\n".join(lines[1:end]).strip()

    return result


# ── GitHub workflow ───────────────────────────────────────────────────────────

def _find_open_pr_for_dep(repo, dep_name: str) -> Optional[str]:
    """
    Checks if there's already an open Auto-Patch PR for this package.

    GitHub sometimes retries webhook deliveries, which would cause us to open
    a second identical PR. This check prevents that. If the API call fails for
    any reason I let the pipeline continue — a missed duplicate is better than
    a missed real patch.
    """
    try:
        for pr in repo.get_pulls(state="open", base=repo.default_branch):
            if "[Auto-Patch]" in pr.title and dep_name.lower() in pr.title.lower():
                return pr.html_url
    except GithubException as exc:
        logger.warning("Couldn't check for existing PRs (will proceed anyway): %s", exc)
    return None


def _delete_branch(repo, branch_name: str) -> None:
    # best-effort cleanup — if this fails too I just log it and move on
    try:
        repo.get_git_ref(f"heads/{branch_name}").delete()
        logger.info("Cleaned up branch: %s", branch_name)
    except Exception as exc:
        logger.warning("Couldn't delete branch '%s': %s", branch_name, exc)


def open_pull_request(
    repo,
    manifest_path: str,
    fixed_content:  str,
    dep_name:       str,
    target_ver:     str,
) -> object:
    """
    Creates a branch, commits the patched file, opens the PR.

    One thing that tripped me up: you can't use the file SHA from when you read
    the manifest in find_manifest, because main might have been pushed to in the
    meantime. If that happens, GitHub rejects the update with a 409 SHA conflict.
    The fix is to re-fetch the file SHA from the newly created branch instead —
    since it was just branched from the current tip, it's guaranteed to be fresh.
    """
    default_branch = repo.default_branch
    base_sha       = repo.get_branch(default_branch).commit.sha

    # microseconds in the timestamp so two simultaneous alerts for the same
    # package can't possibly generate the same branch name
    safe_dep    = dep_name.replace("/", "-").replace(".", "-").lower()[:40]
    ts          = datetime.now().strftime("%Y%m%d%H%M%S%f")
    branch_name = f"fix/{safe_dep}-{ts}"

    repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=base_sha)
    logger.info("Created branch: %s", branch_name)

    # re-fetch SHA from our branch (not from main) to avoid the 409 issue above
    try:
        file_on_branch = repo.get_contents(manifest_path, ref=branch_name)
        if isinstance(file_on_branch, list):
            raise ValueError(f"'{manifest_path}' is a directory on {branch_name}")
        current_sha = file_on_branch.sha

    except (GithubException, ValueError) as exc:
        logger.error("Couldn't read '%s' from branch '%s': %s", manifest_path, branch_name, exc)
        _delete_branch(repo, branch_name)
        raise RuntimeError(f"Failed to read manifest from {branch_name}") from exc

    # if the commit fails, clean up the empty branch so it doesn't litter the repo
    try:
        repo.update_file(
            path=manifest_path,
            message=f"fix: upgrade {dep_name} to satisfy {target_ver}",
            content=fixed_content,
            sha=current_sha,
            branch=branch_name,
        )
    except GithubException as exc:
        logger.error("Commit failed on '%s': %s", branch_name, exc)
        _delete_branch(repo, branch_name)
        raise RuntimeError(f"Commit failed: {exc}") from exc

    logger.info("Committed '%s' → '%s'", manifest_path, branch_name)

    # if the PR itself fails (branch protections, PRs disabled, etc.) I don't
    # clean up the branch — the commit is still there and can be PRed manually
    try:
        pr = repo.create_pull(
            title=f"🔒 [Auto-Patch] Upgrade {dep_name} → {target_ver}",
            body=(
                f"### Automated Security Patch\n\n"
                f"| Field | Value |\n"
                f"|---|---|\n"
                f"| Package | `{dep_name}` |\n"
                f"| Target constraint | `{target_ver}` |\n\n"
                f"Generated by the GitHub Auto-Patcher. "
                f"**Please review the diff before merging.**"
            ),
            head=branch_name,
            base=default_branch,
        )
    except GithubException as exc:
        logger.error("PR creation failed ('%s' → '%s'): %s", branch_name, default_branch, exc)
        raise RuntimeError(f"PR failed: {exc}") from exc

    logger.info("PR opened: %s", pr.html_url)
    return pr


# ── pipeline ──────────────────────────────────────────────────────────────────

def run_patch_pipeline(
    repo_owner: str,
    repo_name:  str,
    dep_name:   str,
    target_ver: str,
) -> None:
    """
    Runs everything top to bottom. Each step bails out with a clear log message
    if something goes wrong — I'd rather have obvious failures than silent ones
    that leave the repo in an inconsistent state.

    This runs in a background thread via FastAPI's BackgroundTasks, so blocking
    API calls (GitHub, Groq) don't stall the event loop.
    """
    logger.info(
        "Patch pipeline started — package=%s  target=%s  repo=%s/%s",
        dep_name, target_ver, repo_owner, repo_name,
    )

    try:
        repo = github_client.get_repo(f"{repo_owner}/{repo_name}")
    except GithubException as exc:
        logger.error("Can't access %s/%s: %s", repo_owner, repo_name, exc)
        return

    # skip if there's already an open PR for this — avoids duplicate spam
    existing = _find_open_pr_for_dep(repo, dep_name)
    if existing:
        logger.info("Already have an open Auto-Patch PR for '%s': %s — skipping", dep_name, existing)
        return

    manifest_path, file_content, _ = find_manifest(repo)
    if not manifest_path:
        logger.error("No requirements.txt or package.json found in %s/%s", repo_owner, repo_name)
        return

    logger.info("Found manifest: %s", manifest_path)

    try:
        fixed_content = ask_groq_to_fix(file_content, dep_name, target_ver)
    except Exception as exc:
        logger.error("Groq call failed: %s", exc)
        return

    if not fixed_content:
        logger.error("Groq returned empty content — bailing out to avoid wiping the file")
        return

    if fixed_content.strip() == file_content.strip():
        # this usually means the package already satisfies the constraint, or
        # Groq misunderstood what to change. either way, a no-diff PR is useless.
        logger.warning(
            "Groq returned the same content for '%s' — package may already satisfy '%s'. "
            "To force a real patch, downgrade it to an old version in requirements.txt.",
            dep_name, target_ver,
        )
        return

    try:
        pr = open_pull_request(repo, manifest_path, fixed_content, dep_name, target_ver)
        logger.info("Done ✓  PR: %s", pr.html_url)
    except Exception as exc:
        logger.error("Failed to open PR: %s", exc)


# ── webhook event type handling ───────────────────────────────────────────────

# GitHub has two event types for the same thing:
#   repository_vulnerability_alert — the original one, action="create"
#   dependabot_alert               — the newer one, action="created", different payload schema
# Supporting both so this doesn't break when GitHub finishes migrating everyone
_VULN_EVENTS = frozenset({"repository_vulnerability_alert", "dependabot_alert"})


def _extract_target_version(payload: dict, event_type: str) -> Optional[str]:
    """
    The patched version lives in different places depending on which event type
    we're dealing with:

    repository_vulnerability_alert → alert.security_advisory.patched_versions
    dependabot_alert               → alert.security_vulnerability.first_patched_version.identifier

    Returns None if there's no patch available yet (some alerts fire before a
    fix exists). Callers handle None as "skip cleanly".
    """
    try:
        if event_type == "dependabot_alert":
            vuln  = (payload.get("alert") or {}).get("security_vulnerability") or {}
            patch = vuln.get("first_patched_version") or {}
            ver   = patch.get("identifier")
        else:
            ver = payload["alert"]["security_advisory"]["patched_versions"]
        return ver or None
    except (KeyError, TypeError):
        return None


# ── webhook endpoint ──────────────────────────────────────────────────────────

@app.post("/webhook")
async def webhook(request: Request, background_tasks: BackgroundTasks):
    """
    Entry point for GitHub webhook deliveries.

    Returns 200 immediately and runs the patch in the background — this is
    important because GitHub will mark the delivery as failed if we take more
    than 10 seconds to respond, and the LLM call alone can take 5-8 seconds.

    Check order matters here:
    1. Event type — reject non-vulnerability events fast, before touching anything else
    2. Parse payload — we need repo owner/name to look up the right secret
    3. Verify signature — do this AFTER parsing so we can use the per-repo secret
    4. Action gate — we only care about new alerts, not dismissals
    5. Extract fields — get dep name and target version
    6. Queue pipeline and return 200
    """
    payload_bytes = await request.body()
    delivery_id   = request.headers.get("X-GitHub-Delivery", "local-test")

    event_type = request.headers.get("X-GitHub-Event", "")
    if event_type == "ping":
        logger.info("GitHub ping [delivery=%s] — webhook is wired up correctly", delivery_id)
        return {"status": "pong"}
    if event_type not in _VULN_EVENTS:
        logger.info("Ignoring event '%s' [delivery=%s]", event_type, delivery_id)
        return {"status": "ignored", "reason": f"unsupported event '{event_type}'"}

    try:
        payload = json.loads(payload_bytes)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # using direct key access (not chained .get) so null values at any level
    # raise TypeError, which I can catch cleanly. chained .get() silently returns
    # None when an intermediate key is null, which then explodes somewhere downstream.
    try:
        repo_owner = payload["repository"]["owner"]["login"]
        repo_name  = payload["repository"]["name"]
    except (KeyError, TypeError):
        raise HTTPException(status_code=400, detail="Payload missing repository info")

    if not repo_owner or not repo_name:
        raise HTTPException(status_code=400, detail="Empty owner or repo name")

    secret    = _get_webhook_secret(repo_owner, repo_name)
    signature = request.headers.get("X-Hub-Signature-256", "")
    verify_signature(payload_bytes, signature, secret)

    action = payload.get("action", "")
    if action not in ("create", "created"):  # "create" = old format, "created" = new
        logger.info("Action '%s' [delivery=%s] — nothing to do", action, delivery_id)
        return {"status": "ignored", "reason": f"action='{action}'"}

    try:
        dep_name = payload["alert"]["dependency"]["package"]["name"]
    except (KeyError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=f"Missing dependency info: {exc}")

    if not dep_name:
        raise HTTPException(status_code=400, detail="Empty dependency name")

    target_ver = _extract_target_version(payload, event_type)
    if not target_ver:
        logger.info("No patched version for '%s' yet [delivery=%s] — skipping", dep_name, delivery_id)
        return {"status": "skipped", "reason": "no patched version available yet"}

    logger.info(
        "Alert [delivery=%s]: %s needs to satisfy %s in %s/%s",
        delivery_id, dep_name, target_ver, repo_owner, repo_name,
    )

    background_tasks.add_task(run_patch_pipeline, repo_owner, repo_name, dep_name, target_ver)
    return {"status": "patch pipeline queued"}


# ── health check ─────────────────────────────────────────────────────────────

@app.get("/")
def health():
    return {"status": "GitHub Auto-Patcher is running 🚀"}

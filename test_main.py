"""
test_main.py — Full test suite for GitHub Auto-Patcher.

Covers every code path: security, webhook routing, Groq output sanitization,
the full patch pipeline, duplicate-PR guard, and branch cleanup on failure.

No real API keys needed — everything external is mocked.

Run:
    pip install pytest httpx2
    pytest test_main.py -v
"""

import base64
import hashlib
import hmac
import json
import os
from unittest.mock import MagicMock, PropertyMock, patch

import pytest
from fastapi.testclient import TestClient

# ── Set fake env vars BEFORE importing main (clients are built at import time) ──
os.environ["GITHUB_TOKEN"]          = "fake_github_token"
os.environ["GROQ_API_KEY"]          = "fake_groq_key"
os.environ["GITHUB_WEBHOOK_SECRET"] = "test-global-secret"

from main import (  # noqa: E402
    app,
    _extract_dep_line,
    _find_open_pr_for_dep,
    _get_webhook_secret,
    ask_groq_to_fix,
    find_manifest,
    run_patch_pipeline,
    verify_signature,
)

# ── Constants ─────────────────────────────────────────────────────────────────

GLOBAL_SECRET = "test-global-secret"
OWNER         = "TestOwner"
REPO          = "test-repo"


# ── Shared helpers ────────────────────────────────────────────────────────────

def sign(payload_bytes: bytes, secret: str = GLOBAL_SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()


def make_webhook_payload(
    action:  str = "create",
    owner:   str = OWNER,
    repo:    str = REPO,
    dep:     str = "requests",
    version: str = ">= 2.31.0",
) -> bytes:
    return json.dumps(
        {
            "action": action,
            "alert": {
                "dependency": {"package": {"name": dep, "ecosystem": "pip"}},
                "security_advisory": {
                    "patched_versions": version,
                    "summary": "Test advisory",
                },
            },
            "repository": {"name": repo, "owner": {"login": owner}},
        },
        separators=(",", ":"),
    ).encode()


def make_mock_repo(dep_file_content: str = "requests==2.28.0\n") -> MagicMock:
    """Return a fully-configured mock PyGithub Repo object."""
    repo = MagicMock()
    type(repo).default_branch = PropertyMock(return_value="main")

    branch_mock            = MagicMock()
    branch_mock.commit.sha = "base-sha-abc123"
    repo.get_branch.return_value = branch_mock

    file_mock         = MagicMock()
    file_mock.sha     = "file-sha-xyz789"
    file_mock.content = base64.b64encode(dep_file_content.encode()).decode()
    repo.get_contents.return_value = file_mock

    repo.create_git_ref.return_value = MagicMock()
    repo.update_file.return_value    = MagicMock()

    pr_mock          = MagicMock()
    pr_mock.html_url = f"https://github.com/{OWNER}/{REPO}/pull/42"
    repo.create_pull.return_value = pr_mock

    repo.get_git_ref.return_value = MagicMock()

    # get_pulls — empty by default (no existing PRs)
    repo.get_pulls.return_value = iter([])

    return repo


def _mock_groq(content: str) -> MagicMock:
    m = MagicMock()
    m.choices[0].message.content = content
    return m


# ── Pytest fixtures ───────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


# ═════════════════════════════════════════════════════════════════════════════
# 1.  HEALTH ENDPOINT
# ═════════════════════════════════════════════════════════════════════════════

class TestHealth:
    def test_returns_200_with_running_message(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "running" in resp.json()["status"].lower()


# ═════════════════════════════════════════════════════════════════════════════
# 2.  SIGNATURE VERIFICATION
# ═════════════════════════════════════════════════════════════════════════════

class TestSignatureVerification:

    def test_valid_signature_passes(self):
        body = b'{"hello":"world"}'
        verify_signature(body, sign(body), GLOBAL_SECRET.encode())

    def test_empty_header_raises_401(self):
        with pytest.raises(Exception) as exc:
            verify_signature(b"body", "", GLOBAL_SECRET.encode())
        assert exc.value.status_code == 401

    def test_malformed_header_raises_401(self):
        with pytest.raises(Exception) as exc:
            verify_signature(b"body", "not-a-real-sig", GLOBAL_SECRET.encode())
        assert exc.value.status_code == 401

    def test_wrong_signature_raises_401(self):
        with pytest.raises(Exception) as exc:
            verify_signature(b"body", "sha256=" + "0" * 64, GLOBAL_SECRET.encode())
        assert exc.value.status_code == 401

    def test_wrong_secret_raises_401(self):
        body = b'{"data":"test"}'
        sig  = sign(body, secret="correct-secret")
        with pytest.raises(Exception) as exc:
            verify_signature(body, sig, b"wrong-secret")
        assert exc.value.status_code == 401

    def test_tampered_payload_raises_401(self):
        original = b'{"action":"create"}'
        tampered = b'{"action":"delete"}'
        with pytest.raises(Exception) as exc:
            verify_signature(tampered, sign(original), GLOBAL_SECRET.encode())
        assert exc.value.status_code == 401


# ═════════════════════════════════════════════════════════════════════════════
# 3.  PER-REPO SECRET LOOKUP
# ═════════════════════════════════════════════════════════════════════════════

class TestPerRepoSecretLookup:

    def test_per_repo_secret_takes_precedence(self):
        with patch.dict(os.environ, {
            "WEBHOOK_SECRET_ALICE_MY_REPO": "per-repo",
            "GITHUB_WEBHOOK_SECRET":        "global",
        }):
            assert _get_webhook_secret("alice", "my-repo") == b"per-repo"

    def test_falls_back_to_global_secret(self):
        clean = {k: v for k, v in os.environ.items() if "WEBHOOK_SECRET_GHOST" not in k}
        clean["GITHUB_WEBHOOK_SECRET"] = "global-fallback"
        with patch.dict(os.environ, clean, clear=True):
            assert _get_webhook_secret("ghost", "repo") == b"global-fallback"

    def test_no_secret_raises_500(self):
        clean = {k: v for k, v in os.environ.items()
                 if not k.startswith("WEBHOOK_SECRET_") and k != "GITHUB_WEBHOOK_SECRET"}
        with patch.dict(os.environ, clean, clear=True):
            with pytest.raises(Exception) as exc:
                _get_webhook_secret("nobody", "norepo")
            assert exc.value.status_code == 500

    def test_hyphens_normalised(self):
        with patch.dict(os.environ, {"WEBHOOK_SECRET_MY_ORG_MY_REPO": "secret"}):
            assert _get_webhook_secret("my-org", "my-repo") == b"secret"

    def test_dots_normalised(self):
        with patch.dict(os.environ, {"WEBHOOK_SECRET_ORG_REPO_V2": "secret"}):
            assert _get_webhook_secret("org", "repo.v2") == b"secret"

    def test_empty_per_repo_value_falls_back_to_global(self):
        with patch.dict(os.environ, {
            "WEBHOOK_SECRET_ALICE_EMPTY": "",
            "GITHUB_WEBHOOK_SECRET":      "global-ok",
        }):
            assert _get_webhook_secret("alice", "empty") == b"global-ok"


# ═════════════════════════════════════════════════════════════════════════════
# 4.  WEBHOOK ENDPOINT
# ═════════════════════════════════════════════════════════════════════════════

VLN_ALERT = "repository_vulnerability_alert"


class TestWebhookEndpoint:

    def test_ping_returns_pong(self, client):
        body = b"{}"
        resp = client.post("/webhook", content=body,
                           headers={"X-GitHub-Event": "ping",
                                    "X-Hub-Signature-256": sign(body)})
        assert resp.status_code == 200
        assert resp.json()["status"] == "pong"

    def test_unsupported_event_ignored(self, client):
        body = b"{}"
        resp = client.post("/webhook", content=body,
                           headers={"X-GitHub-Event": "push",
                                    "X-Hub-Signature-256": sign(body)})
        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"

    def test_missing_signature_returns_401(self, client):
        body = make_webhook_payload()
        resp = client.post("/webhook", content=body,
                           headers={"X-GitHub-Event": VLN_ALERT})
        assert resp.status_code == 401

    def test_wrong_signature_returns_401(self, client):
        body = make_webhook_payload()
        resp = client.post("/webhook", content=body,
                           headers={"X-GitHub-Event": VLN_ALERT,
                                    "X-Hub-Signature-256": "sha256=" + "0" * 64})
        assert resp.status_code == 401

    def test_wrong_secret_returns_401(self, client):
        body = make_webhook_payload()
        resp = client.post("/webhook", content=body,
                           headers={"X-GitHub-Event": VLN_ALERT,
                                    "X-Hub-Signature-256": sign(body, "wrong-secret")})
        assert resp.status_code == 401

    def test_invalid_json_returns_400(self, client):
        body = b"not-valid-json"
        resp = client.post("/webhook", content=body,
                           headers={"X-GitHub-Event": VLN_ALERT,
                                    "X-Hub-Signature-256": sign(body)})
        assert resp.status_code == 400

    def test_missing_repo_info_returns_400(self, client):
        body = json.dumps({"action": "create"}, separators=(",", ":")).encode()
        resp = client.post("/webhook", content=body,
                           headers={"X-GitHub-Event": VLN_ALERT,
                                    "X-Hub-Signature-256": sign(body)})
        assert resp.status_code == 400

    def test_missing_alert_field_returns_400(self, client):
        payload = {"action": "create",
                   "repository": {"name": "r", "owner": {"login": "o"}}}
        body = json.dumps(payload, separators=(",", ":")).encode()
        resp = client.post("/webhook", content=body,
                           headers={"X-GitHub-Event": VLN_ALERT,
                                    "X-Hub-Signature-256": sign(body)})
        assert resp.status_code == 400
        assert "missing" in resp.json()["detail"].lower()

    def test_dismiss_action_ignored(self, client):
        body = make_webhook_payload(action="dismiss")
        resp = client.post("/webhook", content=body,
                           headers={"X-GitHub-Event": VLN_ALERT,
                                    "X-Hub-Signature-256": sign(body)})
        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"

    def test_auto_dismiss_ignored(self, client):
        body = make_webhook_payload(action="auto_dismiss")
        resp = client.post("/webhook", content=body,
                           headers={"X-GitHub-Event": VLN_ALERT,
                                    "X-Hub-Signature-256": sign(body)})
        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"

    def test_valid_alert_queues_pipeline_and_returns_200(self, client):
        body = make_webhook_payload()
        with patch("main.run_patch_pipeline") as mock_pipeline:
            resp = client.post(
                "/webhook", content=body,
                headers={"X-GitHub-Event": VLN_ALERT,
                         "X-Hub-Signature-256": sign(body)},
            )
        assert resp.status_code == 200
        assert "queued" in resp.json()["status"]
        mock_pipeline.assert_called_once_with(
            OWNER, REPO, "requests", ">= 2.31.0"
        )

    def test_delivery_id_accepted_in_header(self, client):
        body = make_webhook_payload()
        with patch("main.run_patch_pipeline"):
            resp = client.post(
                "/webhook", content=body,
                headers={"X-GitHub-Event": VLN_ALERT,
                         "X-Hub-Signature-256": sign(body),
                         "X-GitHub-Delivery": "abc-123-delivery-id"},
            )
        assert resp.status_code == 200

    def test_per_repo_secret_used_when_set(self, client):
        per_repo_secret = "per-repo-xyz"
        env_key = f"WEBHOOK_SECRET_{OWNER}_{REPO}".upper().replace("-", "_")
        body = make_webhook_payload()
        with patch.dict(os.environ, {env_key: per_repo_secret}):
            with patch("main.run_patch_pipeline"):
                resp = client.post(
                    "/webhook", content=body,
                    headers={"X-GitHub-Event": VLN_ALERT,
                             "X-Hub-Signature-256": sign(body, per_repo_secret)},
                )
        assert resp.status_code == 200


# ═════════════════════════════════════════════════════════════════════════════
# 5.  DEPENDENCY LINE EXTRACTION
# ═════════════════════════════════════════════════════════════════════════════

class TestExtractDepLine:

    def test_finds_pinned_version(self):
        content = "fastapi>=0.100.0\nrequests==2.28.0\nuvicorn>=0.23.0\n"
        assert _extract_dep_line(content, "requests") == "requests==2.28.0"

    def test_finds_range_spec(self):
        content = "requests>=2.31.0\n"
        assert _extract_dep_line(content, "requests") == "requests>=2.31.0"

    def test_returns_none_when_not_found(self):
        content = "fastapi>=0.100.0\nuvicorn>=0.23.0\n"
        assert _extract_dep_line(content, "requests") is None

    def test_ignores_comment_lines(self):
        content = "# requests==1.0.0 — old version\nrequests>=2.31.0\n"
        assert _extract_dep_line(content, "requests") == "requests>=2.31.0"

    def test_case_insensitive_dep_match(self):
        content = "Requests==2.28.0\n"
        assert _extract_dep_line(content, "requests") == "Requests==2.28.0"

    def test_underscore_dep_name_matches_hyphen_line(self):
        """
        PEP 508: 'python_dotenv' and 'python-dotenv' are the same distribution.
        GitHub sends 'python-dotenv'; requirements.txt may use either form.
        Before this fix, _extract_dep_line returned None for such cases.
        """
        content = "python-dotenv==1.0.0\nrequests==2.28.0\n"
        assert _extract_dep_line(content, "python_dotenv") == "python-dotenv==1.0.0"

    def test_hyphen_dep_name_matches_underscore_line(self):
        """Reverse: dep name with hyphens, line uses underscores."""
        content = "python_dotenv==1.0.0\n"
        assert _extract_dep_line(content, "python-dotenv") == "python_dotenv==1.0.0"

    def test_mixed_case_underscore_dep_matches(self):
        content = "Pillow==9.0.0\nPython_DateUtil==2.9.0\n"
        assert _extract_dep_line(content, "python-dateutil") == "Python_DateUtil==2.9.0"


# ═════════════════════════════════════════════════════════════════════════════
# 6.  GROQ OUTPUT SANITIZATION
# ═════════════════════════════════════════════════════════════════════════════

class TestGroqOutputSanitization:

    def test_clean_output_unchanged(self):
        with patch("main.groq_client") as g:
            g.chat.completions.create.return_value = _mock_groq(
                "requests>=2.31.0\nfastapi>=0.100.0"
            )
            result = ask_groq_to_fix("requests==2.28.0\n", "requests", ">= 2.31.0")
        assert result == "requests>=2.31.0\nfastapi>=0.100.0"

    def test_bare_fences_stripped(self):
        with patch("main.groq_client") as g:
            g.chat.completions.create.return_value = _mock_groq("```\nrequests>=2.31.0\n```")
            result = ask_groq_to_fix("requests==2.28.0\n", "requests", ">= 2.31.0")
        assert result == "requests>=2.31.0"

    def test_language_tagged_fences_stripped(self):
        with patch("main.groq_client") as g:
            g.chat.completions.create.return_value = _mock_groq(
                "```python\nrequests>=2.31.0\nfastapi>=0.100.0\n```"
            )
            result = ask_groq_to_fix("requests==2.28.0\n", "requests", ">= 2.31.0")
        assert result == "requests>=2.31.0\nfastapi>=0.100.0"

    def test_text_fences_stripped(self):
        with patch("main.groq_client") as g:
            g.chat.completions.create.return_value = _mock_groq("```text\nrequests>=2.31.0\n```")
            result = ask_groq_to_fix("requests==2.28.0\n", "requests", ">= 2.31.0")
        assert result == "requests>=2.31.0"

    def test_unclosed_fence_still_strips_opening(self):
        with patch("main.groq_client") as g:
            g.chat.completions.create.return_value = _mock_groq("```\nrequests>=2.31.0")
            result = ask_groq_to_fix("requests==2.28.0\n", "requests", ">= 2.31.0")
        assert "```" not in result


# ═════════════════════════════════════════════════════════════════════════════
# 7.  find_manifest
# ═════════════════════════════════════════════════════════════════════════════

class TestFindManifest:

    def test_returns_requirements_txt(self):
        repo = make_mock_repo("requests==2.28.0\n")
        path, content, sha = find_manifest(repo)
        assert path == "requirements.txt"
        assert "requests" in content
        assert sha == "file-sha-xyz789"

    def test_returns_none_on_404(self):
        from github import GithubException
        repo = MagicMock()
        repo.get_contents.side_effect = GithubException(404, {"message": "Not Found"}, None)
        path, _, _ = find_manifest(repo)
        assert path is None

    def test_non_404_error_skipped_gracefully(self):
        from github import GithubException
        repo = MagicMock()
        repo.get_contents.side_effect = GithubException(403, {"message": "Forbidden"}, None)
        path, _, _ = find_manifest(repo)
        assert path is None

    def test_directory_listing_skipped(self):
        repo = MagicMock()
        repo.get_contents.return_value = [MagicMock(), MagicMock()]
        path, _, _ = find_manifest(repo)
        assert path is None

    def test_non_utf8_content_skipped(self):
        repo      = MagicMock()
        file_mock = MagicMock()
        file_mock.sha     = "sha"
        file_mock.content = base64.b64encode(b"\xff\xfe invalid utf8").decode()
        repo.get_contents.return_value = file_mock
        path, _, _ = find_manifest(repo)
        assert path is None


# ═════════════════════════════════════════════════════════════════════════════
# 8.  DUPLICATE PR GUARD
# ═════════════════════════════════════════════════════════════════════════════

class TestDuplicatePRGuard:

    def test_returns_none_when_no_open_prs(self):
        repo = make_mock_repo()
        repo.get_pulls.return_value = iter([])
        result = _find_open_pr_for_dep(repo, "requests")
        assert result is None

    def test_returns_url_when_matching_pr_exists(self):
        repo    = make_mock_repo()
        mock_pr = MagicMock()
        mock_pr.title    = "🔒 [Auto-Patch] Upgrade requests → >= 2.31.0"
        mock_pr.html_url = "https://github.com/owner/repo/pull/5"
        repo.get_pulls.return_value = iter([mock_pr])

        result = _find_open_pr_for_dep(repo, "requests")
        assert result == "https://github.com/owner/repo/pull/5"

    def test_ignores_pr_for_different_package(self):
        repo    = make_mock_repo()
        mock_pr = MagicMock()
        mock_pr.title    = "🔒 [Auto-Patch] Upgrade flask → >= 2.0.0"
        mock_pr.html_url = "https://github.com/owner/repo/pull/3"
        repo.get_pulls.return_value = iter([mock_pr])

        result = _find_open_pr_for_dep(repo, "requests")
        assert result is None

    def test_returns_none_on_github_api_error(self):
        from github import GithubException
        repo = make_mock_repo()
        repo.get_pulls.side_effect = GithubException(403, {"message": "Forbidden"}, None)
        # Should not raise — logs warning and returns None
        result = _find_open_pr_for_dep(repo, "requests")
        assert result is None


# ═════════════════════════════════════════════════════════════════════════════
# 9.  FULL PIPELINE
# ═════════════════════════════════════════════════════════════════════════════

class TestRunPatchPipeline:

    def test_happy_path_creates_branch_commits_and_opens_pr(self):
        repo = make_mock_repo("requests==2.28.0\n")
        with patch("main.github_client") as gh, patch("main.groq_client") as groq:
            gh.get_repo.return_value = repo
            groq.chat.completions.create.return_value = _mock_groq("requests>=2.31.0\n")
            run_patch_pipeline(OWNER, REPO, "requests", ">= 2.31.0")

        repo.create_git_ref.assert_called_once()
        repo.update_file.assert_called_once()
        repo.create_pull.assert_called_once()

    def test_duplicate_pr_guard_skips_pipeline(self):
        """If an open PR already exists for this dep, no new PR should be created."""
        repo    = make_mock_repo("requests==2.28.0\n")
        mock_pr = MagicMock()
        mock_pr.title    = "🔒 [Auto-Patch] Upgrade requests → >= 2.31.0"
        mock_pr.html_url = "https://github.com/owner/repo/pull/5"
        repo.get_pulls.return_value = iter([mock_pr])

        with patch("main.github_client") as gh, patch("main.groq_client") as groq:
            gh.get_repo.return_value = repo
            run_patch_pipeline(OWNER, REPO, "requests", ">= 2.31.0")

        # Groq should never have been called — we bailed out at the duplicate check
        groq.chat.completions.create.assert_not_called()
        repo.create_pull.assert_not_called()

    def test_groq_empty_response_aborts(self):
        repo = make_mock_repo()
        with patch("main.github_client") as gh, patch("main.groq_client") as groq:
            gh.get_repo.return_value = repo
            groq.chat.completions.create.return_value = _mock_groq("")
            run_patch_pipeline(OWNER, REPO, "requests", ">= 2.31.0")
        repo.create_pull.assert_not_called()

    def test_groq_unchanged_output_aborts(self):
        original = "requests==2.28.0\n"
        repo     = make_mock_repo(original)
        with patch("main.github_client") as gh, patch("main.groq_client") as groq:
            gh.get_repo.return_value = repo
            groq.chat.completions.create.return_value = _mock_groq(original)
            run_patch_pipeline(OWNER, REPO, "requests", ">= 2.31.0")
        repo.create_pull.assert_not_called()

    def test_groq_api_error_aborts_cleanly(self):
        repo = make_mock_repo()
        with patch("main.github_client") as gh, patch("main.groq_client") as groq:
            gh.get_repo.return_value = repo
            groq.chat.completions.create.side_effect = RuntimeError("503")
            run_patch_pipeline(OWNER, REPO, "requests", ">= 2.31.0")
        repo.create_pull.assert_not_called()

    def test_repo_access_failure_aborts_cleanly(self):
        from github import GithubException
        with patch("main.github_client") as gh:
            gh.get_repo.side_effect = GithubException(403, {"message": "Forbidden"}, None)
            run_patch_pipeline(OWNER, REPO, "requests", ">= 2.31.0")

    def test_missing_manifest_aborts_cleanly(self):
        from github import GithubException
        repo = MagicMock()
        type(repo).default_branch = PropertyMock(return_value="main")
        repo.get_contents.side_effect = GithubException(404, {"message": "Not Found"}, None)
        repo.get_pulls.return_value = iter([])
        with patch("main.github_client") as gh:
            gh.get_repo.return_value = repo
            run_patch_pipeline(OWNER, REPO, "requests", ">= 2.31.0")
        repo.create_pull.assert_not_called()

    def test_branch_name_contains_dep_name(self):
        repo  = make_mock_repo("requests==2.28.0\n")
        calls = []

        def capture(ref, sha):
            calls.append(ref)
            return MagicMock()

        repo.create_git_ref.side_effect = capture
        with patch("main.github_client") as gh, patch("main.groq_client") as groq:
            gh.get_repo.return_value = repo
            groq.chat.completions.create.return_value = _mock_groq("requests>=2.31.0\n")
            run_patch_pipeline(OWNER, REPO, "requests", ">= 2.31.0")

        assert calls
        assert "fix/" in calls[0] and "requests" in calls[0]

    def test_long_dep_name_truncated_in_branch(self):
        long_dep = "a-very-long-package-name-that-exceeds-forty-characters-by-far"
        repo     = make_mock_repo(f"{long_dep}==1.0.0\n")
        calls    = []

        def capture(ref, sha):
            calls.append(ref)
            return MagicMock()

        repo.create_git_ref.side_effect = capture
        with patch("main.github_client") as gh, patch("main.groq_client") as groq:
            gh.get_repo.return_value = repo
            groq.chat.completions.create.return_value = _mock_groq(f"{long_dep}>=2.0.0\n")
            run_patch_pipeline(OWNER, REPO, long_dep, ">= 2.0.0")

        if calls:
            branch_name = calls[0].replace("refs/heads/", "")
            dep_part    = branch_name[len("fix/"):branch_name.rfind("-")]
            assert len(dep_part) <= 40

    def test_non_main_default_branch_used(self):
        repo = make_mock_repo("requests==2.28.0\n")
        type(repo).default_branch = PropertyMock(return_value="master")
        with patch("main.github_client") as gh, patch("main.groq_client") as groq:
            gh.get_repo.return_value = repo
            groq.chat.completions.create.return_value = _mock_groq("requests>=2.31.0\n")
            run_patch_pipeline(OWNER, REPO, "requests", ">= 2.31.0")
        assert "master" in str(repo.create_pull.call_args)


# ═════════════════════════════════════════════════════════════════════════════
# 10.  BRANCH CLEANUP ON FAILURE
# ═════════════════════════════════════════════════════════════════════════════

class TestBranchCleanupOnFailure:

    def test_branch_deleted_when_commit_fails(self):
        from github import GithubException
        repo = make_mock_repo()
        repo.update_file.side_effect = GithubException(409, {"message": "Conflict"}, None)

        with patch("main.github_client") as gh, patch("main.groq_client") as groq:
            gh.get_repo.return_value = repo
            groq.chat.completions.create.return_value = _mock_groq("requests>=2.31.0\n")
            run_patch_pipeline(OWNER, REPO, "requests", ">= 2.31.0")

        repo.get_git_ref.assert_called_once()
        repo.get_git_ref.return_value.delete.assert_called_once()
        repo.create_pull.assert_not_called()

    def test_branch_deleted_when_branch_file_read_fails(self):
        from github import GithubException
        repo = make_mock_repo()

        def side_effect(path, ref=None):
            if ref is not None:
                raise GithubException(404, {"message": "Not Found"}, None)
            return repo.get_contents.return_value

        repo.get_contents.side_effect = side_effect
        with patch("main.github_client") as gh, patch("main.groq_client") as groq:
            gh.get_repo.return_value = repo
            groq.chat.completions.create.return_value = _mock_groq("requests>=2.31.0\n")
            run_patch_pipeline(OWNER, REPO, "requests", ">= 2.31.0")

        repo.get_git_ref.assert_called_once()
        repo.create_pull.assert_not_called()

    def test_server_stable_when_both_commit_and_cleanup_fail(self):
        from github import GithubException
        repo = make_mock_repo()
        repo.update_file.side_effect = GithubException(409, {"message": "Conflict"}, None)
        repo.get_git_ref.side_effect = GithubException(404, {"message": "Not Found"}, None)

        with patch("main.github_client") as gh, patch("main.groq_client") as groq:
            gh.get_repo.return_value = repo
            groq.chat.completions.create.return_value = _mock_groq("requests>=2.31.0\n")
            run_patch_pipeline(OWNER, REPO, "requests", ">= 2.31.0")

        repo.create_pull.assert_not_called()


# ═════════════════════════════════════════════════════════════════════════════
# 9.  DEPENDABOT_ALERT EVENT TYPE  (new GitHub format)
# ═════════════════════════════════════════════════════════════════════════════

def make_dependabot_alert_payload(
    action:  str = "created",
    owner:   str = OWNER,
    repo:    str = REPO,
    dep:     str = "requests",
    version: str = "2.31.0",       # note: identifier, not a constraint string
) -> bytes:
    """Build a payload matching GitHub's newer dependabot_alert event schema."""
    return json.dumps(
        {
            "action": action,
            "alert": {
                "number": 1,
                "state": "open",
                "dependency": {
                    "package": {"ecosystem": "pip", "name": dep},
                    "manifest_path": "requirements.txt",
                    "scope": "runtime",
                },
                "security_advisory": {
                    "ghsa_id": "GHSA-test-1234-5678",
                    "cve_id": "CVE-2023-12345",
                    "summary": "Test advisory summary",
                    "severity": "high",
                },
                "security_vulnerability": {
                    "package": {"ecosystem": "pip", "name": dep},
                    "severity": "high",
                    "vulnerable_version_range": f"< {version}",
                    "first_patched_version": {"identifier": version},
                },
                "auto_dismissed_at": None,
            },
            "repository": {"name": repo, "owner": {"login": owner}},
        },
        separators=(",", ":"),
    ).encode()


class TestDependabotAlertEventType:

    def test_dependabot_alert_accepted_and_queues_pipeline(self, client):
        body = make_dependabot_alert_payload()
        with patch("main.run_patch_pipeline") as mock_pipeline:
            resp = client.post(
                "/webhook", content=body,
                headers={"X-GitHub-Event": "dependabot_alert",
                         "X-Hub-Signature-256": sign(body)},
            )
        assert resp.status_code == 200
        assert "queued" in resp.json()["status"]
        # target_ver should be the identifier from first_patched_version
        mock_pipeline.assert_called_once_with(OWNER, REPO, "requests", "2.31.0")

    def test_dependabot_alert_created_action_accepted(self, client):
        """action='created' (new format) must be treated same as 'create'."""
        body = make_dependabot_alert_payload(action="created")
        with patch("main.run_patch_pipeline") as mock_pipeline:
            resp = client.post(
                "/webhook", content=body,
                headers={"X-GitHub-Event": "dependabot_alert",
                         "X-Hub-Signature-256": sign(body)},
            )
        assert resp.status_code == 200
        mock_pipeline.assert_called_once()

    def test_dependabot_alert_dismiss_action_ignored(self, client):
        body = make_dependabot_alert_payload(action="dismissed")
        resp = client.post(
            "/webhook", content=body,
            headers={"X-GitHub-Event": "dependabot_alert",
                     "X-Hub-Signature-256": sign(body)},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"

    def test_dependabot_alert_with_no_patch_returns_skipped(self, client):
        """An alert with no fix available must return 200 skipped, never 400."""
        payload = json.loads(make_dependabot_alert_payload())
        # Remove the first_patched_version to simulate "no fix yet"
        del payload["alert"]["security_vulnerability"]["first_patched_version"]
        body = json.dumps(payload, separators=(",", ":")).encode()
        resp = client.post(
            "/webhook", content=body,
            headers={"X-GitHub-Event": "dependabot_alert",
                     "X-Hub-Signature-256": sign(body)},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "skipped"


# ═════════════════════════════════════════════════════════════════════════════
# 10.  NULL / MISSING PATCHED VERSIONS  (graceful skip, not 400)
# ═════════════════════════════════════════════════════════════════════════════

class TestNullPatchedVersions:

    def test_null_patched_versions_returns_skipped_not_400(self, client):
        """GitHub sometimes sends alerts before a fix exists (patched_versions=null)."""
        payload = json.loads(make_webhook_payload())
        payload["alert"]["security_advisory"]["patched_versions"] = None
        body = json.dumps(payload, separators=(",", ":")).encode()
        resp = client.post(
            "/webhook", content=body,
            headers={"X-GitHub-Event": "repository_vulnerability_alert",
                     "X-Hub-Signature-256": sign(body)},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "skipped"

    def test_missing_patched_versions_key_returns_skipped_not_400(self, client):
        """patched_versions key entirely absent must also skip gracefully."""
        payload = json.loads(make_webhook_payload())
        del payload["alert"]["security_advisory"]["patched_versions"]
        body = json.dumps(payload, separators=(",", ":")).encode()
        resp = client.post(
            "/webhook", content=body,
            headers={"X-GitHub-Event": "repository_vulnerability_alert",
                     "X-Hub-Signature-256": sign(body)},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "skipped"

    def test_empty_string_patched_versions_returns_skipped(self, client):
        payload = json.loads(make_webhook_payload())
        payload["alert"]["security_advisory"]["patched_versions"] = ""
        body = json.dumps(payload, separators=(",", ":")).encode()
        resp = client.post(
            "/webhook", content=body,
            headers={"X-GitHub-Event": "repository_vulnerability_alert",
                     "X-Hub-Signature-256": sign(body)},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "skipped"


# ═════════════════════════════════════════════════════════════════════════════
# 11.  NULL OWNER / NAME IN REPOSITORY FIELD  (TypeError path)
# ═════════════════════════════════════════════════════════════════════════════

class TestNullRepositoryFields:

    def test_null_owner_returns_400_not_500(self, client):
        """
        If payload has "owner": null, chained .get() previously raised
        AttributeError → 500.  Direct key access now raises TypeError → 400.
        """
        payload = json.loads(make_webhook_payload())
        payload["repository"]["owner"] = None
        body = json.dumps(payload, separators=(",", ":")).encode()
        resp = client.post(
            "/webhook", content=body,
            headers={"X-GitHub-Event": "repository_vulnerability_alert",
                     "X-Hub-Signature-256": sign(body)},
        )
        assert resp.status_code == 400

    def test_null_repository_returns_400(self, client):
        payload = json.loads(make_webhook_payload())
        payload["repository"] = None
        body = json.dumps(payload, separators=(",", ":")).encode()
        resp = client.post(
            "/webhook", content=body,
            headers={"X-GitHub-Event": "repository_vulnerability_alert",
                     "X-Hub-Signature-256": sign(body)},
        )
        assert resp.status_code == 400


# ═════════════════════════════════════════════════════════════════════════════
# 12.  _extract_target_version  (unit tests)
# ═════════════════════════════════════════════════════════════════════════════

from main import _extract_target_version  # noqa: E402


class TestExtractTargetVersion:

    def test_legacy_event_extracts_patched_versions(self):
        payload = {
            "alert": {"security_advisory": {"patched_versions": ">= 2.31.0"}}
        }
        assert _extract_target_version(payload, "repository_vulnerability_alert") == ">= 2.31.0"

    def test_dependabot_event_extracts_identifier(self):
        payload = {
            "alert": {
                "security_vulnerability": {
                    "first_patched_version": {"identifier": "2.31.0"}
                }
            }
        }
        assert _extract_target_version(payload, "dependabot_alert") == "2.31.0"

    def test_null_patched_versions_returns_none(self):
        payload = {
            "alert": {"security_advisory": {"patched_versions": None}}
        }
        assert _extract_target_version(payload, "repository_vulnerability_alert") is None

    def test_missing_security_vulnerability_returns_none(self):
        payload = {"alert": {}}
        assert _extract_target_version(payload, "dependabot_alert") is None

    def test_null_first_patched_version_returns_none(self):
        payload = {
            "alert": {
                "security_vulnerability": {"first_patched_version": None}
            }
        }
        assert _extract_target_version(payload, "dependabot_alert") is None

    def test_entirely_missing_alert_returns_none(self):
        assert _extract_target_version({}, "repository_vulnerability_alert") is None

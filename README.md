# GitHub Auto-Patcher

A FastAPI service that listens for GitHub Dependabot vulnerability alerts, asks an LLM to generate the exact dependency fix, and automatically opens a Pull Request — all within seconds of the alert firing, no developer intervention needed.

Built with Python, FastAPI, Groq (Llama 3.3-70b), and the GitHub API.

---

## What it does

Security scanners like Dependabot are great at finding vulnerable dependencies. The problem is they just tell you *what's* broken — you still have to open the file, change the version, commit, and create a PR yourself. For a team managing dozens of repos, that's a lot of manual work that often gets pushed to "later."

This tool closes that loop. When Dependabot detects a vulnerability, it fires a webhook to this service. The service reads the manifest file from your repo, sends it to Groq's Llama 3 model with instructions to upgrade the vulnerable package, and then commits the fix and opens a PR — all automatically.

The time between "Dependabot fires" and "PR is open on GitHub" is about 5–10 seconds.

---

## How it works

```
GitHub Dependabot
      │
      │  fires repository_vulnerability_alert webhook
      ▼
FastAPI /webhook endpoint
      │
      ├─ verifies HMAC-SHA256 signature
      ├─ checks for duplicate open PRs (idempotency)
      │
      ▼
Groq API (Llama 3.3-70b)
      │
      │  returns patched requirements.txt / package.json
      ▼
GitHub API
      │
      ├─ creates a new fix branch
      ├─ commits the patched file
      └─ opens a Pull Request
```

The webhook endpoint responds to GitHub immediately (before the pipeline runs) so it never hits GitHub's 10-second delivery timeout. The actual patching runs in a background thread.

---

## Tech stack

| Layer | Technology |
|---|---|
| Web framework | FastAPI |
| ASGI server | Uvicorn |
| LLM | Groq API — Llama 3.3-70b-versatile |
| GitHub integration | PyGithub |
| Local tunnel (dev) | ngrok |
| Test suite | pytest (76 tests) |

---

## Project structure

```
test-auto-patcher/
├── main.py            # The entire service — webhook, pipeline, GitHub API calls
├── test_main.py       # 76 pytest tests, no real API keys needed
├── test_webhook.py    # Fire a fake Dependabot alert at your local server
├── requirements.txt   # Dependencies (requests==2.28.0 is intentionally old)
├── .env.example       # Template — copy to .env and fill in real values
└── .gitignore         # Keeps .env and venv out of version control
```

---

## Setup

### 1. Clone and install

```bash
git clone https://github.com/Sarvjais12/test-auto-patcher.git
cd test-auto-patcher

python -m venv venv

# Windows
venv\Scripts\activate

# Mac / Linux
source venv/bin/activate

pip install -r requirements.txt
pip install pytest httpx2
```

### 2. Get your credentials

**Groq API key** — free at [console.groq.com](https://console.groq.com). Sign in → API Keys → Create.

**GitHub fine-grained PAT** — go to [github.com/settings/personal-access-tokens/new](https://github.com/settings/personal-access-tokens/new):
- Repository access → Only select repositories → pick this repo
- Permissions → **Contents: Read and write**, **Pull requests: Read and write**
- Nothing else needed — don't give it more than this

### 3. Create your .env file

```bash
# Windows
copy .env.example .env

# Mac / Linux
cp .env.example .env
```

Open `.env` and fill in your real values:

```env
GITHUB_TOKEN=github_pat_your_real_token_here
GROQ_API_KEY=gsk_your_real_groq_key_here
WEBHOOK_SECRET_SARVJAIS12_TEST_AUTO_PATCHER=pick_any_strong_random_string
GITHUB_WEBHOOK_SECRET=pick_any_strong_random_string
```

The webhook secret can be anything — just make sure it matches exactly what you put in your GitHub webhook settings later.

---

## Running it

### Start the server

```bash
uvicorn main:app --port 3000 --reload
```

You should see `Application startup complete.` with no warnings. If you see "Missing environment variables", your `.env` file isn't filled in correctly.

Check it's alive:
```bash
curl http://localhost:3000/
# {"status":"GitHub Auto-Patcher is running 🚀"}
```

### Run the test suite

```bash
pytest test_main.py -v
```

All 76 tests run against mocked APIs — no real tokens are used, no network calls made. Should pass in under 2 seconds.

### Fire a fake webhook (tests the full pipeline)

With the server running in one terminal, open a second terminal and run:

```bash
python test_webhook.py
```

This simulates exactly what GitHub sends for a Dependabot alert. You'll see the server receive it, call Groq, create a branch, and open a PR — all logged in real time.

---

## Connecting to real Dependabot

For the full end-to-end experience where real GitHub vulnerability alerts trigger the patcher automatically:

### 1. Expose your local server

```bash
ngrok http 3000
```

Copy the HTTPS URL it gives you (looks like `https://xxxx.ngrok-free.app`).

### 2. Configure GitHub webhook

Go to your repo → **Settings** → **Webhooks** → **Add webhook** (or edit the existing one):

- **Payload URL**: `https://xxxx.ngrok-free.app/webhook`
- **Content type**: `application/json`
- **Secret**: the same string you put in `.env` for `WEBHOOK_SECRET_SARVJAIS12_TEST_AUTO_PATCHER`
- **Events**: select "Let me select individual events" → check **Repository vulnerability alerts** only

Save. Your server terminal will immediately log:
```
INFO  GitHub ping received — webhook wiring confirmed
```

### 3. Trigger a real alert

The `requirements.txt` in this repo intentionally includes `requests==2.28.0`, which has known vulnerabilities. Once Dependabot scans the repo and detects it, it fires the webhook automatically. A PR will appear on GitHub within seconds.

You can also force a scan: repo → **Security** tab → **Dependabot alerts** → **Check for updates**.

---

## Security design decisions

A few things were deliberately built this way:

**Per-repo webhook secrets** — instead of one shared secret for all repos, each repo gets its own secret (e.g. `WEBHOOK_SECRET_ALICE_MY_REPO`). If one repo's secret leaks, an attacker can't forge webhooks for any other repo this service handles.

**Fine-grained PAT** — the GitHub token is scoped to only the repos this service manages, with only the two permissions it actually needs. A classic token with full `repo` scope would give write access to every private repo you own, which is unnecessary and dangerous.

**Constant-time signature comparison** — the HMAC check uses `hmac.compare_digest` instead of `==`. This prevents timing attacks where an attacker could gradually learn the correct signature by measuring how long comparison takes.

**BackgroundTasks** — the webhook endpoint returns 200 to GitHub immediately, then runs the patching pipeline in a background thread. This means the server never hits GitHub's 10-second webhook delivery timeout, even if Groq is slow.

**Idempotency guard** — before running, the pipeline checks if an open Auto-Patch PR already exists for that package. If it does, it skips. This prevents duplicate PRs when GitHub retries a webhook delivery.

**Branch cleanup on failure** — if the LLM patch gets committed to a branch but the PR creation fails, the pipeline doesn't leave orphaned branches in your repo. The branch is deleted automatically.

---

## What it handles gracefully

- **No patched version yet** — some vulnerability alerts fire before a fix exists. The service detects this and returns a clean `200 skipped` instead of crashing.
- **Both Dependabot event formats** — GitHub has a legacy `repository_vulnerability_alert` format and a newer `dependabot_alert` format. Both are supported.
- **Groq returns unchanged content** — if the LLM fails to make any change (because the package was already at the right version, or it misunderstood), the pipeline logs a warning and skips opening a PR rather than creating a no-diff PR that would just be noise.
- **Commit fails mid-pipeline** — if writing the patch to GitHub fails (SHA conflict, network error, permissions), the orphaned branch is cleaned up before the error is raised.
- **Null values in webhook payloads** — direct key access with `TypeError` catching instead of chained `.get()` calls, so a null owner field doesn't silently produce `None` and crash somewhere unexpected downstream.

---

## Running tests in detail

The test suite is organized into 10 groups:

| Test class | What it covers |
|---|---|
| `TestHealth` | Health endpoint returns 200 |
| `TestSignatureVerification` | Valid sig, missing header, wrong sig, tampered payload |
| `TestPerRepoSecretLookup` | Per-repo priority, global fallback, no secret → 500 |
| `TestWebhookEndpoint` | All routing: ping, wrong event, bad JSON, wrong sig, good path |
| `TestExtractDepLine` | PEP 508 underscore/hyphen normalisation |
| `TestGroqOutputSanitization` | Markdown fence stripping |
| `TestFindManifest` | 404 handling, directory listing, bad encoding |
| `TestDuplicatePRGuard` | Skips when matching PR already open |
| `TestRunPatchPipeline` | Full happy path + 6 failure modes |
| `TestBranchCleanupOnFailure` | Orphaned branch deleted when commit fails |

---

## Environment variables reference

| Variable | Required | Description |
|---|---|---|
| `GITHUB_TOKEN` | Yes | Fine-grained PAT with Contents + Pull requests permissions |
| `GROQ_API_KEY` | Yes | Groq API key from console.groq.com |
| `WEBHOOK_SECRET_{OWNER}_{REPO}` | Recommended | Per-repo webhook secret (lowercase hyphens → uppercase underscores) |
| `GITHUB_WEBHOOK_SECRET` | Fallback | Global secret used if no per-repo secret matches |

---

## Limitations and future improvements

This is an MVP — it works well for the core use case but has some known constraints:

- Only supports `requirements.txt` (Python) and `package.json` (Node) at the repo root. Monorepos with nested manifests aren't supported yet.
- No retry logic for transient API failures (Groq or GitHub returning 503). A failed pipeline just logs an error and stops.
- The LLM occasionally returns a version constraint that's technically valid but not ideal (e.g. `==2.31.0` instead of `>=2.31.0`). The PR should always be reviewed before merging.
- ngrok's free tier gives a new URL every restart, so the GitHub webhook URL needs updating each session. A paid ngrok account or a deployed server would fix this.


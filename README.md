# GitHub Auto-Patcher

I built this because Dependabot is great at finding vulnerable dependencies but it doesn't actually fix anything — it just opens an issue and waits for a developer to deal with it. For a team managing a lot of repos, that backlog grows fast and "fix the vulnerable dep" always ends up below "ship the feature" on the priority list.

So this service closes that loop. When Dependabot fires an alert, the patcher wakes up, reads your manifest, asks an LLM to bump the broken package to a safe version, and opens a PR — all automatically, usually within 10 seconds of the alert firing.

---

## How it actually works

```
GitHub Dependabot detects requests==2.28.0 (vulnerable)
          │
          │  fires a webhook
          ▼
  POST /webhook  (this service)
          │
          ├── verifies the HMAC signature so we know it's really from GitHub
          ├── checks if there's already an open patch PR (avoids duplicates)
          │
          ▼
  Groq API  →  Llama 3.3-70b reads requirements.txt, upgrades the package
          │
          ▼
  GitHub API
          ├── creates a new branch  (fix/requests-20260613...)
          ├── commits the updated requirements.txt
          └── opens a Pull Request  🎉
```

The webhook endpoint returns 200 to GitHub immediately. The actual patching runs in a background thread so we never hit GitHub's 10-second delivery timeout.

---

## Stack

| What | Tech |
|---|---|
| Web server | FastAPI + Uvicorn |
| LLM | Groq — Llama 3.3-70b-versatile |
| GitHub integration | PyGithub |
| Local tunnel | ngrok (for dev) |
| Tests | pytest — 76 tests, fully mocked |

---

## Getting started

### Clone and set up

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

### Grab your credentials

**Groq API key** — free at [console.groq.com](https://console.groq.com). Sign in → API Keys → Create API Key. Starts with `gsk_`.

**GitHub fine-grained PAT** — go to [github.com/settings/personal-access-tokens/new](https://github.com/settings/personal-access-tokens/new):

- Repository access → Only select repositories → pick this repo
- Permissions: **Contents** (Read and write), **Pull requests** (Read and write)
- That's it. Don't give it anything else.

### Set up your .env

```bash
# Windows
copy .env.example .env

# Mac/Linux
cp .env.example .env
```

Fill in the real values:

```
GITHUB_TOKEN=github_pat_your_real_token
GROQ_API_KEY=gsk_your_real_groq_key
WEBHOOK_SECRET_SARVJAIS12_TEST_AUTO_PATCHER=any_random_string_you_pick
GITHUB_WEBHOOK_SECRET=same_or_different_random_string
```

The webhook secret can literally be anything — just make sure it matches what you set in the GitHub webhook settings later.

---

## Running it

### Start the server

```bash
uvicorn main:app --port 3000 --reload
```

You should see `Application startup complete.` with no warnings. If you see warnings about missing env vars, your `.env` isn't filled in correctly.

Quick sanity check:
```bash
curl http://localhost:3000/
# {"status":"GitHub Auto-Patcher is running 🚀"}
```

### Run the tests

```bash
pytest test_main.py -v
```

76 tests, all mocked — no network calls, no API keys needed. Runs in about 1-2 seconds. If all 76 pass, everything is wired up correctly.

### Simulate a Dependabot alert

With the server running in one terminal, open a second one and run:

```bash
python test_webhook.py
```

This fires exactly the same payload GitHub would send for a real alert. Watch the server terminal — you'll see it receive the alert, call Groq, create a branch, and open a PR in real time.

---

## Connecting real Dependabot

For the full live demo where GitHub fires the webhook automatically:

**Step 1 — Expose your local server:**
```bash
ngrok http 3000
```
Copy the HTTPS URL (looks like `https://xxxx.ngrok-free.app`).

**Step 2 — Set up the GitHub webhook:**

Go to your repo → Settings → Webhooks → Add webhook (or edit the existing one):

- Payload URL: `https://xxxx.ngrok-free.app/webhook`
- Content type: `application/json`
- Secret: the string you put in `.env` for `WEBHOOK_SECRET_SARVJAIS12_TEST_AUTO_PATCHER`
- Events: "Let me select individual events" → check **Repository vulnerability alerts** only

Save it. Your server will immediately log:
```
INFO  GitHub ping received — webhook is wired up correctly
```

**Step 3 — Trigger the alert:**

The `requirements.txt` in this repo has `requests==2.28.0` on purpose — it's a known vulnerable version that Dependabot will flag. Once it scans the repo and detects it, the webhook fires automatically and a PR appears on GitHub.

To force a scan immediately: repo → Security tab → Dependabot alerts → Check for updates.

---

## A few design decisions worth explaining

**Per-repo webhook secrets** — I'm using separate secrets per repo (`WEBHOOK_SECRET_OWNER_REPO`) instead of one global secret. If you use a single shared secret and it leaks, an attacker can forge valid webhook payloads for every repo your service watches. With per-repo secrets, a leak only affects one repo.

**Fine-grained PAT** — the GitHub token is scoped to only this repo and only the two permissions it needs (Contents and Pull requests). A classic token with the full `repo` scope would give write access to every private repo on the account, which is way more than necessary.

**Constant-time HMAC comparison** — the signature check uses `hmac.compare_digest` instead of `==`. Regular string comparison short-circuits as soon as it finds a mismatch, which means response time varies slightly depending on how many bytes are correct. An attacker could theoretically measure those timing differences to figure out the correct signature one byte at a time. `compare_digest` always takes the same time regardless of where the mismatch is.

**Idempotency guard** — before running, the pipeline checks whether an open Auto-Patch PR already exists for that package. GitHub sometimes retries webhook deliveries when it doesn't get a response fast enough, which would otherwise cause two identical PRs.

**Fresh SHA on commit** — I re-fetch the file's SHA from the newly created branch instead of reusing the one from `find_manifest`. If anyone pushes to main between the manifest read and the commit, the original SHA becomes stale and GitHub rejects the commit with a 409. Fetching it from the branch after creation guarantees it's current.

---

## What it handles gracefully

- **No fix available yet** — some alerts fire before a patch exists. Returns `200 skipped` instead of erroring.
- **Both Dependabot event formats** — GitHub has a legacy format (`repository_vulnerability_alert`) and a newer one (`dependabot_alert`) with a different payload structure. Both work.
- **Duplicate alerts** — if the same vulnerability fires twice, the second run finds the existing PR and skips without creating a duplicate.
- **Commit fails mid-pipeline** — the empty branch gets cleaned up automatically instead of left dangling in the repo.
- **Groq returns unchanged content** — detected and skipped with a warning log instead of opening a pointless no-diff PR.

---

## Files

```
main.py          — the whole service: webhook, pipeline, GitHub API calls
test_main.py     — 76 pytest tests (run these first to verify everything works)
test_webhook.py  — fire a fake Dependabot alert at your local server
requirements.txt — requests==2.28.0 is intentionally old to trigger Dependabot
.env.example     — copy to .env and fill in your real credentials
.gitignore       — keeps .env and venv/ out of version control
```

---

## Known limitations

- Only looks for `requirements.txt` and `package.json` at the repo root. Monorepos or nested manifests aren't supported.
- No retry logic for transient API failures. If Groq or GitHub returns a 503, the pipeline logs an error and stops — the next real alert will try again.
- The LLM occasionally produces a constraint that's valid but not ideal (e.g. `==2.31.0` instead of `>=2.31.0`). Always review the PR diff before merging.
- ngrok free tier generates a new URL each restart, so you have to update the GitHub webhook URL every session. A paid ngrok account or deploying to a server fixes this.

# 🔒 GitHub Auto-Patcher

A lightweight backend tool that listens for GitHub vulnerability alerts and automatically opens a Pull Request with an AI-generated fix — no manual triage needed.

---

## What it does

When GitHub Dependabot detects a vulnerable dependency in your repo, this tool:

1. Catches the webhook alert instantly
2. Reads your `requirements.txt` or `package.json` from the repo
3. Sends it to Groq (Llama 3) and asks it to patch the vulnerable package
4. Creates a new branch, commits the fix, and opens a Pull Request — all within seconds

---

## Tech Stack

- **Python + FastAPI** — webhook server
- **Groq API (Llama 3)** — generates the dependency fix
- **PyGithub** — interacts with the GitHub API
- **Ngrok** — tunnels GitHub webhooks to your local machine during development

---

## Setup

### 1. Clone and install

```bash
git clone https://github.com/YOUR_USERNAME/github-auto-patcher
cd github-auto-patcher
pip install -r requirements.txt
```

### 2. Create your `.env` file

```bash
cp .env.example .env
```

Fill in the three values:

| Variable | Where to get it |
|---|---|
| `GITHUB_TOKEN` | GitHub → Settings → Developer Settings → Personal Access Tokens (give it `repo` scope) |
| `GROQ_API_KEY` | console.groq.com → free signup, no card needed |
| `GITHUB_WEBHOOK_SECRET` | Make up any random string, e.g. `my-super-secret-123` |

### 3. Run the server

```bash
uvicorn main:app --port 3000
```

### 4. Expose it with Ngrok

In a second terminal:

```bash
ngrok http 3000
```

Copy the `https://xxxx.ngrok.io` URL.

### 5. Configure your GitHub repo webhook

- Go to your repo → **Settings** → **Webhooks** → **Add webhook**
- Payload URL: `https://xxxx.ngrok.io/webhook`
- Content type: `application/json`
- Secret: same value as `GITHUB_WEBHOOK_SECRET` in `.env`
- Events: select **"Repository vulnerability alerts"**

---

## Demo

Commit a vulnerable package to trigger it:

```
# requirements.txt
requests==2.6.0
```

Push to main → Dependabot fires → webhook hits your server → PR appears automatically.

---

## Project Structure

```
github-auto-patcher/
├── main.py           # all the logic lives here
├── .env.example      # template for secrets
├── requirements.txt  # Python dependencies
└── README.md
```

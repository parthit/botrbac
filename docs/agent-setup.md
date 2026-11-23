# Set it up with a coding agent

Copy one of the prompts below into Claude Code, Cursor, Codex, or any coding agent that can run commands on
your computer. The agent does the terminal work. It will stop and tell you exactly what to click in Google
Cloud and Vercel, because those steps need you signed in to your own accounts.

You need a GitHub fork of this repo (for deploying), a Google account, and a Vercel account.

## Deploy your own copy on Vercel

```text
Set up my own self-hosted copy of Bot RBAC (https://github.com/parthit/botrbac) on Vercel.

Follow docs/agent-setup.md in that repo, section "Instructions for the agent", step by step.
My fork is: <https://github.com/YOUR-USERNAME/botrbac, or "please fork it for me">
My Google address (OWNER_EMAIL): <you@example.com>
Other people allowed to sign in (ALLOWED_EMAILS, optional): <none>
```

## Just run it on my computer

```text
Run Bot RBAC (https://github.com/parthit/botrbac) locally on my computer.

Follow docs/agent-setup.md in that repo, section "Instructions for the agent", but only steps
A, B, C and F (local run). Skip Vercel.
My Google address (OWNER_EMAIL): <you@example.com>
```

---

## Instructions for the agent

You are setting up Bot RBAC for the person you are working with. It is a Python (3.12) MCP server plus a web
dashboard, deployed as one Vercel function, using `uv`. The full human guide is
[docs/self-hosting.md](self-hosting.md); read it if anything below is unclear.

Rules:

- **Never print, log, commit or paste secrets** (client secret, `SESSION_SECRET`, `ENCRYPTION_KEY`, tokens)
  into chat or files that are tracked by git. `.env` is git-ignored; keep secrets there or pipe them
  directly into `vercel env add`.
- When a step needs the human to click something in a web console, stop, tell them exactly what to click
  and what to paste back, and wait. Ask for the Google client secret to be pasted into `.env` by the human
  or typed into a hidden prompt, not into chat, if your environment allows.
- Do not change application code to make setup work. If something fails, check the Troubleshooting table
  in docs/self-hosting.md and report.

### A. Get the code and check it works

1. Check `uv` is installed (`uv --version`). If not, install it:
   `curl -LsSf https://astral.sh/uv/install.sh | sh` (macOS/Linux) and reopen the shell or use the full path.
2. Clone the person's fork (or `https://github.com/parthit/botrbac` for a local-only run) and `cd` into it.
3. `uv sync`
4. `uv run pytest -q` should pass with no network and no Google account. If it fails, stop and report.

### B. Secrets and .env

1. `cp .env.example .env`
2. Run `uv run python scripts/make_secrets.py` and write the two values into `.env` as `SESSION_SECRET`
   and `ENCRYPTION_KEY` without echoing them into chat.
3. Set `OWNER_EMAIL` (and `ALLOWED_EMAILS` if given) in `.env`.

### C. Google Cloud (the human does this; you guide)

Tell the person to do the following at <https://console.cloud.google.com/> and wait until they confirm.
If the `gcloud` CLI is installed and signed in, you may do 1 and 2 yourself
(`gcloud projects create`, `gcloud services enable drive.googleapis.com --project <id>`); the consent
screen and Web OAuth client must be done in the console.

1. Create a project (e.g. `botrbac`).
2. Enable **Google Drive API** (APIs & Services → Library).
3. OAuth consent screen / Google Auth Platform: External; app name; their email; add themselves (and every
   `ALLOWED_EMAILS` address) as **Test users**; add scopes `openid`, `email`,
   `https://www.googleapis.com/auth/drive`.
4. Credentials → Create OAuth client ID → **Web application**. Authorized redirect URIs:
   - `http://localhost:8000/auth/callback`
   - `https://<vercel-domain>/auth/callback` (add after step D gives the domain)
5. Put the Client ID and Client secret into `.env` as `GOOGLE_OAUTH_CLIENT_ID` and
   `GOOGLE_OAUTH_CLIENT_SECRET`.

Mention: while the Google app is in Testing, Drive access expires every 7 days. For personal use they can
click **Publish app** on the Audience page to stop that (the "unverified app" warning stays).

### D. Vercel project and storage

1. Check for the Vercel CLI (`vercel --version`); if missing, `npm i -g vercel`. Run `vercel login` if
   needed (the human completes it in the browser).
2. In the repo: `vercel link` (create a new project; framework "Other"; keep defaults). `vercel.json`
   already routes everything to `api/index.py`.
3. `vercel deploy --prod`. Note the production domain. The first deploy shows a "storage missing" page;
   that is expected.
4. Storage: try `vercel integration add upstash`. If the CLI does not support it, tell the human: Vercel
   dashboard → this project → **Storage** → **Upstash for Redis** (free) → connect to the project
   (all environments). Wait until they confirm. Run `vercel env ls` and check that `KV_REST_API_URL` and
   `KV_REST_API_TOKEN` (or `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN`) exist.
5. Remind the human to add `https://<domain>/auth/callback` to the Google OAuth client (step C.4).

### E. Environment variables and deploy

1. For each of `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET`, `OWNER_EMAIL`, `SESSION_SECRET`,
   `ENCRYPTION_KEY`, and `ALLOWED_EMAILS` if set, pipe the value from `.env` into
   `vercel env add <NAME> production` (e.g. `printf '%s' "$VALUE" | vercel env add NAME production`)
   so it is not shown on screen. Use the **same** `SESSION_SECRET` / `ENCRYPTION_KEY` as `.env` or new
   ones, either is fine, but never rotate `ENCRYPTION_KEY` later without warning the human.
2. Add `APP_BASE_URL` = `https://<domain>` (no trailing slash).
3. `vercel deploy --prod`.
4. `curl -s https://<domain>/health` must return `{"status":"ok"}`. If it returns 503, read
   `vercel logs <domain>` for the setting name and fix it.

### F. Local run (only if asked, or to try before deploying)

1. In `.env`, `APP_BASE_URL=http://localhost:8000` and leave the Redis variables empty.
2. `uv run --env-file .env uvicorn api.index:app --reload --port 8000` (run in the background).
3. `curl -s http://localhost:8000/health` → `{"status":"ok"}`.
4. Tell the human to open <http://localhost:8000/>, sign in, click **Connect Google Drive**, then **Browse →
   Allow** on a test folder. Data is in memory and is lost on restart.
5. To call the MCP tools locally: `uv run python scripts/make_token.py local admin`, add the printed
   `API_TOKENS=` entry to `.env`, restart the server, and give the human the token for MCP Inspector
   (`npx @modelcontextprotocol/inspector`, Streamable HTTP, `http://localhost:8000/mcp`,
   header `Authorization: Bearer <token>`). Hosted assistants can't reach localhost; for that, see the
   tunnel option in docs/self-hosting.md.

### G. Hand over

Tell the human, in this order:

1. Open `https://<domain>/` → **Sign in with Google** → **Connect Google Drive**.
2. **Browse** → **Allow** on a test folder.
3. Add `https://<domain>/mcp` as a custom connector in their assistant (Claude: Settings → Connectors →
   Add custom connector; ChatGPT: developer mode → Settings → Apps → Create, OAuth; Grok Bot: say "Add this
   MCP server: https://<domain>/mcp"). Leave client id/secret empty.
4. Disconnect the assistant's built-in Google Drive connector if it has one.
5. Test: ask for a file in the allowed folder (works), then one outside it (should return an approval link).

Finish with a short summary: the domain, which variables were set (names only), and anything left for the
human to do.

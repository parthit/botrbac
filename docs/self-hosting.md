# Self-hosting Bot RBAC

Run your own copy so the Google Drive token lives in your own Vercel project and your own database,
not on botrbac.com. It is one Python function on Vercel (the free Hobby plan is enough) plus Upstash Redis
or Postgres for storage. Allow about 30 minutes the first time.

> **Have a coding agent?** Claude Code, Cursor, Codex and similar agents can do most of this for you.
> Paste the prompt in [agent-setup.md](agent-setup.md). The agent runs the commands and stops to tell you
> exactly which buttons to click in Google Cloud and Vercel.

- [What you need](#what-you-need)
- [1. Google Cloud: OAuth client and file picker](#1-google-cloud-oauth-client-and-file-picker)
- [2. Vercel: project and storage](#2-vercel-project-and-storage)
- [3. Environment variables](#3-environment-variables)
- [4. Deploy and check](#4-deploy-and-check)
- [5. Sign in and allow a test folder](#5-sign-in-and-allow-a-test-folder)
- [6. Connect an assistant](#6-connect-an-assistant)
- [7. Test it](#7-test-it)
- [Run it on your computer](#run-it-on-your-computer)
- [Troubleshooting](#troubleshooting)
- [Reference: all environment variables](#reference-all-environment-variables)

## What you need

- A Google account (the one whose Drive you want to use).
- A GitHub account, to fork this repo.
- A [Vercel](https://vercel.com) account (Hobby is fine).
- For generating secrets and running locally: [uv](https://docs.astral.sh/uv/)
  (`curl -LsSf https://astral.sh/uv/install.sh | sh`). It installs the right Python (3.12) for you.

```bash
git clone https://github.com/<you>/botrbac && cd botrbac   # your fork
uv sync
```

## 1. Google Cloud: OAuth client and file picker

Signed in to <https://console.cloud.google.com/> with your own account:

1. **Project:** project picker → **New project** → name it (e.g. `botrbac`) → **Create**.
2. **APIs:** **APIs & Services → Library** → enable **Google Drive API** and **Google Picker API**.
3. **Consent screen** (**APIs & Services → OAuth consent screen**, called **Google Auth Platform** in newer
   consoles):
   - App name (e.g. `Bot RBAC`), your email as support and developer contact.
   - **Audience:** **External**.
   - **Test users:** add your own address, and the address of anyone else who will sign in.
   - **Data access / Scopes:** add `openid`, `email` and `https://www.googleapis.com/auth/drive.file`
     ("only the specific files you use with this app"). Do **not** add `…/auth/drive`: Bot RBAC refuses
     a connection that carries it.
4. **OAuth client:** **APIs & Services → Credentials → Create credentials → OAuth client ID** (or
   **Clients → Create client**). Type: **Web application**. **Authorized redirect URIs:**
   - `https://<your-domain>/auth/callback`, e.g. `https://botrbac-yourname.vercel.app/auth/callback`
     (you can come back and fix this after step 2 when you know the domain)
   - `http://localhost:8000/auth/callback` (only for running on your computer)

   Copy the **Client ID** and **Client secret**.
5. **Picker key:** **Credentials → Create credentials → API key**, then open the key:
   - **Application restrictions:** Websites → `https://<your-domain>/*` (and `http://localhost:8000/*`
     if you run it on your computer).
   - **API restrictions:** Restrict key → **Google Picker API**.

   Save and copy the key (`GOOGLE_PICKER_API_KEY`). It is visible in the page; the restrictions are what
   protect it.
6. **Project number:** console home → **Project info** → **Project number** (the long number, not the
   project ID). This is `GOOGLE_CLOUD_PROJECT_NUMBER`.

Bot RBAC only ever gets the files people pick in Google's file picker (the `drive.file` permission).
Google enforces that, so the rest of each Drive stays closed to your server.

While the app is in **Testing**, Google shows an "unverified app" warning (click **Advanced → Go to …**) and
expires sign-ins after 7 days, so you will need to reconnect Drive weekly. For personal use you can instead
click **Publish app** on the Audience page: the warning stays, but tokens stop expiring. Opening it to the
public needs brand verification (`drive.file` is not a restricted scope, so no security assessment); see
[google-verification.md](google-verification.md).

## 2. Vercel: project and storage

1. Fork this repo on GitHub. In Vercel: **Add New → Project** → import your fork → **Deploy**. The first
   deploy will show a "storage missing" page. That's expected.
2. Note the production domain (**Settings → Domains**), e.g. `https://botrbac-yourname.vercel.app`. This is
   your `APP_BASE_URL`. Make sure `<APP_BASE_URL>/auth/callback` is in the Google client's redirect URIs.
3. **Storage:** in the project, **Storage → Create / Connect** → **Upstash for Redis** (free plan) → connect
   it to this project. Vercel adds `KV_REST_API_URL` and `KV_REST_API_TOKEN` (or the `UPSTASH_REDIS_REST_*`
   pair) for you. Neon Postgres works too: it adds `DATABASE_URL`.

Prefer the CLI? `npm i -g vercel`, then `vercel link` and `vercel env add NAME production` for each
variable below. Storage still has to be connected once in the dashboard (or with
`vercel integration add upstash` on recent CLI versions).

## 3. Environment variables

Generate the two secrets on your computer:

```bash
uv run python scripts/make_secrets.py
# SESSION_SECRET=...
# ENCRYPTION_KEY=...
```

In Vercel, **Settings → Environment Variables** (Production), add:

| Name | Value |
| --- | --- |
| `GOOGLE_OAUTH_CLIENT_ID` | from step 1.4 |
| `GOOGLE_OAUTH_CLIENT_SECRET` | from step 1.4 |
| `OWNER_EMAIL` | your Google address. The admin, and the only account that can open `/admin` |
| `APP_BASE_URL` | e.g. `https://botrbac-yourname.vercel.app`, no trailing `/` |
| `SESSION_SECRET` | from `make_secrets.py` |
| `ENCRYPTION_KEY` | from `make_secrets.py`. Keep it safe: changing it makes stored Drive tokens unreadable |
| `GOOGLE_PICKER_API_KEY` | from step 1.5 |
| `GOOGLE_CLOUD_PROJECT_NUMBER` | from step 1.6 |

Strongly recommended for a personal copy:

| Name | Value |
| --- | --- |
| `ALLOWED_EMAILS` | comma-separated addresses allowed to sign in. Unset means any Google account that is a test user (or anyone, once the Google app is published) can sign in and connect their own Drive. `OWNER_EMAIL` is always allowed |

Everything else is optional; see the [reference](#reference-all-environment-variables).

## 4. Deploy and check

Redeploy (**Deployments → ⋯ → Redeploy**, or push to `main`). Then:

```bash
curl https://<your-domain>/health
# {"status":"ok"}
```

`{"status":"unavailable"}` with HTTP 503 means a setting is malformed. The reason is in the Vercel function
logs (names only, never values). After you sign in, the overview page also lists missing settings.

Preview deployments are usually behind Vercel's login, so use the production URL everywhere.

## 5. Sign in and allow a test folder

1. Open `https://<your-domain>/` → **Sign in with Google**. Google asks only for your email.
2. On **Connections**, click **Connect Google Drive** and allow it with the same account. That is a
   second Google screen, for Drive.
3. In Drive, make a folder `Bot RBAC test` with a doc inside ("Test plan"). Put another doc ("Private note")
   **outside** it.
4. In the dashboard, open **Files** → **Add from Google Drive**. Google's own window opens; pick
   `Bot RBAC test` and the doc inside it, then **Select**. They are now allowed.

Google opens a file to Bot RBAC only once it is picked. Picking a folder may not open the files already
inside it, so if an assistant can't read a file in an allowed folder, pick that file too.

## 6. Connect an assistant

Your MCP address is `https://<your-domain>/mcp`. Every assistant below uses OAuth: leave any client id and
secret fields empty, sign in when the browser opens, and choose what the app may do (**Read only**,
**Read and edit** or **Full**).

| Assistant | Where |
| --- | --- |
| **Claude** (web, desktop, mobile) | Settings → Connectors → Add custom connector |
| **ChatGPT** | turn on developer mode, then Settings → Apps → Create, choose OAuth |
| **Grok Bot** | say "Add this MCP server: https://&lt;your-domain&gt;/mcp" in the chat |
| **grok.com** | Connectors → New Connector → Custom |
| **Cursor** | add a remote MCP server with the URL |
| **Muse** | add a custom connector |

**Disconnect the assistant's own Google Drive connector** if it has one. Otherwise it can reach your whole
Drive without going through Bot RBAC. Also check <https://myaccount.google.com/permissions>.

Connected apps appear in **Settings → Assistants**, where you can change their role, rename or
disconnect them.

Other OAuth clients: the server only accepts the redirect URLs listed in `ALLOWED_REDIRECT_URIS` in
`src/scoped_drive_mcp/mcp_oauth.py`. Add your client's exact callback there if it isn't listed.

### Static bearer tokens (xAI API, scripts, MCP Inspector)

For clients that send a fixed `Authorization` header instead of OAuth:

```bash
uv run python scripts/make_token.py my-script viewer   # roles: viewer, editor, admin
```

It prints the token (give it to the client) and an `API_TOKENS` entry (`name:role:sha256`). Put the entry in
Vercel's `API_TOKENS` (comma-separate several) and redeploy. These tokens act as `OWNER_EMAIL`. Remove the
entry and redeploy to revoke one.

xAI Responses API example:

```bash
curl https://api.x.ai/v1/responses \
  -H "Authorization: Bearer $XAI_API_KEY" -H "Content-Type: application/json" \
  -d '{
    "model": "grok-4.7",
    "input": [{"role": "user", "content": "List my allowed Drive items and summarise Test plan."}],
    "tools": [{"type": "mcp", "server_url": "https://<your-domain>/mcp",
               "server_label": "drive", "authorization": "<token>"}]
  }'
```

## 7. Test it

1. **Allowed file works:** ask the assistant to read *Test plan*. It should quote it.
2. **Other files are refused:** ask it to read *Private note* (or give its ID, the part after `/d/` in the
   doc's URL). It should reply with an approval link like `https://<your-domain>/requests/…` instead of
   the content.
3. **Approve:** open the link, choose what to share, **Approve**. Ask again: it works.
4. **Revoke:** in **Access**, **Remove** the item. Within about 2 seconds the assistant is refused again.
5. **Activity** shows every call, grant, revoke and refusal (never file contents).

## Run it on your computer

Useful for development, or to try it before deploying. You still need the Google OAuth client from step 1
with `http://localhost:8000/auth/callback` as a redirect URI.

```bash
uv sync
cp .env.example .env
uv run python scripts/make_secrets.py           # prints SESSION_SECRET and ENCRYPTION_KEY
```

Edit `.env`: paste the two secrets, and set `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET`,
`GOOGLE_PICKER_API_KEY`, `GOOGLE_CLOUD_PROJECT_NUMBER`, `OWNER_EMAIL` and
`APP_BASE_URL=http://localhost:8000`. The picker key's website restriction must include
`http://localhost:8000/*`. Leave the Redis variables empty: locally the server
uses an in-memory store, which is wiped on every restart.

```bash
uv run --env-file .env uvicorn api.index:app --reload --port 8000
open http://localhost:8000/        # sign in, connect Drive, allow a folder
```

**Talking to it from an assistant.** Hosted assistants (Claude.ai, ChatGPT, Grok) can't reach `localhost`.
Two options:

- **MCP Inspector, locally.** Make a token with `uv run python scripts/make_token.py local admin`, put the
  `API_TOKENS=` line in `.env` and restart. Then run `npx @modelcontextprotocol/inspector`, choose
  **Streamable HTTP**, URL `http://localhost:8000/mcp`, header `Authorization: Bearer <token>`,
  **Connect → List Tools**, and call `list_folder` with no arguments.
- **A tunnel.** `cloudflared tunnel --url http://localhost:8000` (or ngrok) gives you an `https://` URL. Set
  `APP_BASE_URL` to it, add `<tunnel-url>/auth/callback` to the Google client, restart, and connect the
  assistant to `<tunnel-url>/mcp`.

Tests need no Google account or network:

```bash
uv run pytest
uv run ruff check . && uv run ruff format --check .
```

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Google says `redirect_uri_mismatch` | The redirect URI in the Google client must be exactly `<APP_BASE_URL>/auth/callback`. No trailing slash, same scheme and host |
| "Access blocked: app has not completed verification" | Add the address as a **Test user** on the consent screen |
| Site says storage is missing | Connect Upstash Redis or Neon Postgres to the Vercel project, then redeploy |
| `/health` returns 503 | A variable is malformed (e.g. `ENCRYPTION_KEY` is not a Fernet key, `APP_BASE_URL` is `http://` on a non-local host). Check the function logs |
| Drive stops working after a week | The Google app is in Testing. Reconnect Drive, or publish the app (step 1) |
| Assistant sees your whole Drive | Its built-in Google Drive connector is still connected. Disconnect it |
| No **Add from Google Drive** button | `GOOGLE_PICKER_API_KEY` or `GOOGLE_CLOUD_PROJECT_NUMBER` is missing |
| Picker opens, then errors | The API key's website restriction doesn't include this site, or the Picker API isn't enabled or allowed on the key |
| A file in an allowed folder is "not found" | Google hasn't opened it to the app. Pick that file too |
| "Google gave more access than Bot RBAC asks for" | An older full-Drive grant came back. Remove Bot RBAC at myaccount.google.com/permissions and connect again; remove `…/auth/drive` from the consent screen's scopes |
| Assistant's OAuth fails with a redirect error | Its callback URL isn't in `ALLOWED_REDIRECT_URIS` (see step 6) |
| Everyone got signed out | `SESSION_SECRET` changed. Expected |
| "Reconnect Google Drive" after changing `ENCRYPTION_KEY` | Stored tokens can't be decrypted with the new key. Reconnect Drive |

## Reference: all environment variables

| Name | Default | What it does |
| --- | --- | --- |
| `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET` | required | Web OAuth client from Google Cloud |
| `OWNER_EMAIL` | required | the admin's Google address; only this account can open `/admin` |
| `APP_BASE_URL` | required | public origin, no trailing `/`. `http://` only for `localhost` |
| `SESSION_SECRET` | required | signs dashboard cookies (32+ characters) |
| `ENCRYPTION_KEY` | required | Fernet key that encrypts stored Google tokens and signs records |
| `KV_REST_API_URL` / `KV_REST_API_TOKEN` (or `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN`) | required on Vercel, one store | Upstash Redis. Empty locally means in-memory |
| `DATABASE_URL` or `POSTGRES_URL` | one store | Postgres instead of Redis. If both are set, Redis data is copied to Postgres once and Postgres is used |
| `ALLOWED_EMAILS` | anyone | comma-separated addresses allowed to sign in (`OWNER_EMAIL` always is) |
| `API_TOKENS` | none | static bearer tokens for the admin (`name:role:sha256`, comma-separated). See step 6 |
| `ROOT_FOLDER_ID` | none | a Drive folder that is always allowed for the admin, on top of the ticks. It must also be picked, or Google won't open it |
| `GOOGLE_OAUTH_REFRESH_TOKEN` | none | overrides the admin's dashboard Drive connection (from `scripts/bootstrap_oauth.py`, which needs a Desktop client). Every access token it yields is limited to `drive.file` |
| `GOOGLE_PICKER_API_KEY`, `GOOGLE_CLOUD_PROJECT_NUMBER` | required | Google's file picker, which is how files are added. Restrict the key by HTTP referrer and to the Picker API; it is visible in the page |
| `MAX_BYTES` | 5242880 | bytes fetched per read |
| `MAX_CHARS` | 100000 | characters returned per read |
| `DROP_HOLD_HOURS` | 24 | hours a file a paired person sent is held for its recipient to save (24 to 168); then it is deleted |
| `DROP_MAX_MB` | 20 | largest file a person may send from the dashboard (1 to 100). It is sent in 4 MB pieces, under Vercel's 4.5 MB request limit. An assistant's `send_file` keeps the `MAX_BYTES` limit |
| `BLOB_READ_WRITE_TOKEN` (or `BLOB_STORE_ID`) | unset | set by Vercel when a Blob store is connected to the project. Held files then go to Blob instead of Redis or Postgres. Use a **private** store |
| `DROP_BLOB_MONTHLY_UPLOADS` | 1500 | Blob uploads a calendar month (each 4 MB piece is one). The free tier includes 2,000 and turns Blob off for 30 days past it |
| `DROP_BLOB_STORAGE_MB` | 800 | MB that held files may take in Blob (the free tier includes 1 GB). Sends are refused past either cap until it frees up |
| `EXTRACT_ISOLATION` | on | reads PDF and Office files in a separate process with hard memory and CPU limits. `0` reads them in the server process, only for hosts that cannot start a process |
| `EXTRACT_MEMORY_MB` | 768 | address-space limit of that process, in MB (256 to 8192). Up to two run at once (at most one per caller), so keep two of them plus the server under the function's memory |
| `SCOPE_CACHE_TTL` | 60 | seconds folder ancestry is cached |
| `ALLOWLIST_CACHE_TTL` | 2 | seconds the allowlist is cached; bounds how fast a revoke takes effect |
| `MAX_PENDING_REQUESTS` | 50 | access requests one app may have waiting |
| `LOGIN_RATE_LIMIT`, `LOGIN_RATE_WINDOW_SECONDS` | 30 / 600 | sign-in attempts per IP |
| `MCP_RATE_LIMIT`, `MCP_RATE_WINDOW_SECONDS` | 300 / 60 | `/mcp` calls per token |
| `REQUIRE_SIGNED_RECORDS` | off | `1` ignores unsigned allowlist, app and pairing records. Turn on after **Sign existing records** on `/admin`. See [security.md](security.md) |
| `TRUSTED_PROXY_HOPS` | unset | proxies in front of the server that add to `X-Forwarded-For`. Leave unset on Vercel |
| `NOTION_OAUTH_CLIENT_ID`, `NOTION_OAUTH_CLIENT_SECRET` | unset | optional Notion connection; both set turns it on ([notion.md](notion.md)) |
| `EDGE_CONFIG` | unset | Vercel Edge Config connection string; holds the `self_pairing` switch ([sharing.md](sharing.md)) |
| `WEBHOOKS_ENABLED`, `WEBHOOK_KEK`, `WEBHOOK_HOST_ALLOWLIST` | off | wake-up pings to paired assistants ([sharing.md](sharing.md)) |
| `VERCEL_OBSERVABILITY` | on | `off` removes Vercel Speed Insights and Web Analytics scripts |
| `OAUTH_TEST_CALLBACK` | off | `1` accepts this server's own `/oauth/done` as an OAuth redirect, for local testing only |
| `OAUTH_LOOPBACK_CALLBACK` | off | `1` accepts `http://localhost:8787/callback` and `http://127.0.0.1:8787/callback` as OAuth redirects, for a local MCP client you run yourself |

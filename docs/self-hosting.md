# Self-hosting Bot RBAC

Run your own copy on Vercel (the free Hobby plan is enough) with Upstash Redis or Postgres for storage.
The dashboard setup below is the normal route. The older [single-folder setup](#phase-1-setup-guide-single-folder-no-dashboard) still works.

## More than one person

Each person signs in with their own Google account and connects their own Drive. Ticking an item adds it
to **their** allowlist. Someone who signed in but has not connected Drive can see the dashboard; pages that
need Drive, and approving an assistant on `/oauth/authorize`, send them to `/connect` first.
Grok Bot connects with the MCP OAuth flow on `/oauth/authorize`; that grant is tied to the signed-in
user, and `/mcp` calls Drive with that user's sign-in. One Grok Bot does not see another person's files.

`OWNER_EMAIL` is the admin. That account keeps its own ticks and its own Grok Bot connection, and it
is the only account that can open `/admin` (a directory of emails and whether Grok Bot is connected —
not files). Pre-shared `API_TOKENS` from `scripts/make_token.py` stay a legacy bearer for the admin
only. New people do not get those tokens; they sign in and click Allow in Grok Bot.

`BOT_EMAIL`, if still set, is ignored.

Storage is still Upstash Redis when that is all that is configured, and tests use in-memory keys.
Set `DATABASE_URL` or `POSTGRES_URL` (Vercel Neon injects a pooled URL) to store the same data in
Postgres. If both Redis and Postgres are set, the admin's existing allowlist, tokens, requests and
activity are copied across once. `/health` reports `store` as `memory`, `redis` or `postgres` and
never prints the URL.

New here? Follow the [Phase 2 setup and test walkthrough](#phase-2-setup-and-test-walkthrough). The older
single-folder setup (phase 1) still works and is described further down. See [PLAN.md](PLAN.md) for
the design notes.

## Phase 2 setup and test walkthrough

This is the whole setup, written for someone who hasn't done it before. You'll need: your normal Google account,
a GitHub account with this repo, and a Vercel account. Allow about 30 minutes. Optional for step 6:
[uv](https://docs.astral.sh/uv/) on your computer.

### 1. Google Cloud: one OAuth client for the dashboard

Do this signed in to <https://console.cloud.google.com/> with **your own** account.

1. **Project:** click the project picker at the top → **New project** → name it (e.g. `grok-drive`) → **Create**.
2. **Drive API:** **APIs & Services → Library** → search **Google Drive API** → **Enable**.
3. **Consent screen** (**APIs & Services → OAuth consent screen**, called **Google Auth Platform** in newer
   consoles):
   - App name (e.g. `Grok Drive`), and your email as support and developer contact.
   - **Audience / User type:** **External**.
   - **Test users:** add your own address. Each other person who will sign in needs to be a test user too.
4. **Create the client:** **APIs & Services → Credentials → Create credentials → OAuth client ID** (or
   **Clients → Create client**). Application type: **Web application**. Under **Authorized redirect URIs** add:
   - `https://<project>.vercel.app/auth/callback` (use your real Vercel domain, see step 2)
   - `http://localhost:8000/auth/callback` (only needed if you run it on your computer)

   Click **Create** and copy the **Client ID** and **Client secret**. These become `GOOGLE_OAUTH_CLIENT_ID` and
   `GOOGLE_OAUTH_CLIENT_SECRET`.
   (If you set up phase 1 with a *Desktop* client, create this new *Web* client anyway; Desktop clients
   don't accept these redirect URIs.)
5. **Publish and verify:** the consent screen should list `openid`, `email`, and
   `https://www.googleapis.com/auth/drive`. Sign-in only requests the first two; the Drive scope is
   requested later, when someone chooses **Connect Google Drive**. That scope is restricted. The Google Picker is optional:
   enable the **Google Picker API**, create a browser API key, and set `GOOGLE_PICKER_API_KEY` plus
   `GOOGLE_CLOUD_PROJECT_NUMBER` only if you want the picker button. The remaining clicks in Google
   Cloud and Search Console (custom domain, a separate production project, brand verification,
   publishing **In production**) are listed in
   [google-verification.md](google-verification.md). While the app is in *Testing*, Google expires
   sign-ins after 7 days. A saved sign-in that only has `drive.file` must sign in again.

### 2. Vercel: project, Redis and environment variables

1. In Vercel, **Add New → Project**, import this GitHub repo, and deploy once (it will report missing settings;
   that's fine). Note the production domain, e.g. `https://<project>.vercel.app`. That's your
   `APP_BASE_URL`. If it differs from what you entered in step 1.4, fix the redirect URI there.
2. **Redis:** in the project, open **Storage** (or **Integrations → Marketplace**), add **Upstash → Redis**
   (free plan) and connect it to this project. Vercel then adds `UPSTASH_REDIS_REST_URL` /
   `UPSTASH_REDIS_REST_TOKEN` (or `KV_REST_API_URL` / `KV_REST_API_TOKEN`) for you; either pair works.
3. **Secrets:** on your computer run `uv run python scripts/make_secrets.py` (or
   `python3 -c "import secrets; print(secrets.token_urlsafe(48))"` for the session secret and
   `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` for the key).
4. **Settings → Environment Variables:** add these names and type the values in yourself:

| Name | Required | Where the value comes from |
| --- | --- | --- |
| `API_TOKENS` | yes | step 6 (`scripts/make_token.py`) |
| `GOOGLE_OAUTH_CLIENT_ID` | yes | step 1.4 |
| `GOOGLE_OAUTH_CLIENT_SECRET` | yes | step 1.4 |
| `OWNER_EMAIL` | yes | the admin's Google address (the only account that can open `/admin`; other people can sign in too) |
| `ALLOWED_EMAILS` | no | comma-separated Google addresses allowed to sign in. Leave unset and any verified Google account can sign in. `OWNER_EMAIL` is always allowed |
| `APP_BASE_URL` | yes | the public origin users open, with no trailing `/`. A custom domain replaces the Vercel host here and in the OAuth redirect URI (`APP_BASE_URL/auth/callback`) |
| `SESSION_SECRET` | yes | step 2.3 |
| `ENCRYPTION_KEY` | yes | step 2.3 |
| `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN` | one store | added by the Upstash integration (or `KV_REST_API_URL` / `KV_REST_API_TOKEN`). On Vercel the app needs Redis **or** Postgres |
| `DATABASE_URL` or `POSTGRES_URL` | one store | optional Neon Postgres URL. If both Redis and Postgres are set, Redis is copied once and Postgres is then used |
| `GOOGLE_OAUTH_REFRESH_TOKEN` | no | optional. If set, it overrides the admin's dashboard sign-in for Drive calls. It must be that person's own token; an old bot token makes Grok see an empty Drive |
| `ROOT_FOLDER_ID` | no | a folder that is always allowed in addition to your ticks |
| `MAX_BYTES`, `MAX_CHARS`, `SCOPE_CACHE_TTL`, `ALLOWLIST_CACHE_TTL` | no | limits; defaults 5 MB, 100000, 60 s, 2 s |
| `AUTH_MODE` | no | `oauth_bot` (default and only mode) |
| `GOOGLE_PICKER_API_KEY` | no | browser API key for the Google Picker. Restrict it by HTTP referrer. Public in the signed-in page |
| `GOOGLE_CLOUD_PROJECT_NUMBER` | no | numeric Cloud project number. The Picker needs it so a chosen file is granted to this app |
| `LOGIN_RATE_LIMIT`, `LOGIN_RATE_WINDOW_SECONDS` | no | sign-in attempts per IP. Defaults 30 per 600 seconds |
| `EDGE_CONFIG` | no | added when you connect a Vercel Edge Config. Holds the `self_pairing` switch (see Bot Bridge). Without it, pairing your own assistants is on |
| `MCP_RATE_LIMIT`, `MCP_RATE_WINDOW_SECONDS` | no | `/mcp` calls per bearer token. Defaults 300 per 60 seconds |
| `VERCEL_OBSERVABILITY` | no | `off` removes the Vercel Speed Insights and Web Analytics scripts. On by default on Vercel. Turn both on under the project's **Speed Insights** and **Analytics** tabs. Addresses are sent without ids or query strings |
| `REQUIRE_SIGNED_RECORDS` | no | `1` ignores an allowlist, app or pairing record that is not signed. Turn on after **Sign existing records** on `/admin`. See [security.md](security.md) |
| `MAX_PENDING_REQUESTS` | no | access requests one connected app may have waiting at once. Default 50 |
| `TRUSTED_PROXY_HOPS` | no | how many proxies in front of the server add to `X-Forwarded-For`. Leave unset on Vercel. Behind your own reverse proxy set `1`; without it, rate limits use the socket address |
| `OAUTH_TEST_CALLBACK` | no | `1` accepts this server's own `/oauth/done` as an OAuth redirect, for local testing. Leave unset in production |

### 3. Deploy

Redeploy (**Deployments → … → Redeploy**, or push to `main`). Then open `https://<project>.vercel.app/health`.
The public body is only `{"status":"ok"}` or, on HTTP 503, `{"status":"unavailable"}`. It does not list
settings, the store, or whether an account is connected. A bad `ENCRYPTION_KEY` or a missing store is in
the host logs. If Redis or Postgres is missing on Vercel, the site itself explains that and refuses to
serve the dashboard (each instance has its own memory, so grants and sign-ins would silently disappear).
Connect Upstash (step 2.2) and redeploy. The signed-in admin overview still names missing settings.

Preview deployments are usually behind Vercel's login, so use the production URL for everything below.

### 4. Sign in, then connect Google Drive

1. Open `https://<project>.vercel.app/` and click **Sign in with Google**. Choose **your own** account and
   accept the unverified-app warning. Google asks only for your email address.
2. You land on **Connections** (step 2 of 2). Click **Allow Bot RBAC to access Google Drive**. Google shows a
   second screen for Drive access; allow it with the same account. The overview should now show Google Drive
   as connected. Grok's tools use this connection. **Disconnect** on the same page deletes the stored token
   and asks Google to revoke it. Other people sign in with their own Google accounts and tick their own
   files. Only `OWNER_EMAIL` can open `/admin`. If `ALLOWED_EMAILS` is set, any address not on that list
   is rejected.

The refresh token is stored encrypted with `ENCRYPTION_KEY`. (Prefer the old way? Running
`scripts/bootstrap_oauth.py` and setting `GOOGLE_OAUTH_REFRESH_TOKEN` still works; it needs a Desktop client,
and you must sign in as yourself, not as a second account.)

### 5. Tick a test folder

1. In your own Google Drive, make a folder `Grok test` with a Google Doc inside (e.g. "Test plan" with a sentence
   in it). Put a second doc **outside** it, e.g. "Private note" in My Drive.
2. In the dashboard, click **Browse**, find `Grok test` and click **Allow**. It now shows **allowed**, and
   **Access** lists it. Nothing is shared with another Google account; the folder is only added to the allowlist.

### 6. Create an API token and connect Grok

```bash
uv run python scripts/make_token.py grok-viewer viewer
```

Put the printed `API_TOKENS` entry into Vercel (step 2.4) and redeploy. Give that token to the xAI API or the
Grok Build CLI. Grok Bot cannot use it; connect the bot with [Connect Grok Bot](#connect-grok-bot) instead.

**xAI Responses API:**

```bash
curl https://api.x.ai/v1/responses \
  -H "Authorization: Bearer $XAI_API_KEY" -H "Content-Type: application/json" \
  -d '{
    "model": "grok-4.7",
    "input": [{"role": "user", "content": "List my shared Drive items and summarise Test plan."}],
    "tools": [{
      "type": "mcp",
      "server_url": "https://<project>.vercel.app/mcp",
      "server_label": "drive",
      "authorization": "<token from make_token.py>"
    }]
  }'
```

**grok.com:** **Connectors → New Connector → Custom** may only offer OAuth. Use [Connect Grok Bot](#connect-grok-bot)
for that. A static bearer, when the form still has a token field, is the `make_token.py` secret from this step.
Also disconnect Grok's built-in Google Drive connector so it can't bypass this server (see (g) below).

### Connect Grok Bot

Grok Bot attaches a remote MCP server by URL and authenticates only with OAuth. It cannot use a static bearer.
The secret from `make_token.py` stays on the xAI API and the Grok Build CLI.

1. Sign in, connect Google Drive, and tick at least one folder.
2. In the Grok Bot chat, say: Add this MCP server: https://botrbac.com/mcp
3. When the browser opens, sign in as the owner and click Allow.
4. Do not paste the make_token.py secret into the Grok Bot chat. That token is only for the xAI API and the Grok Build CLI.
5. Ask the bot to list allowed files. An unticked file should still return an approval link.

On the Allow page you choose what the app may do with your ticked items: **Read only** (the default: the
`viewer` tools), **Read and edit** (`editor`) or **Full** (`admin`, which adds `trash_file`). Settings lists the
connection under **Assistants**, where you can change that choice (it applies on the app's next call) or
**Disconnect** it, which stops it immediately. Apps connected before this choice existed keep Full until you
change them. The dashboard sign-in cookie is not
a token for `/mcp`.

### Connect Muse

Muse (muse.ai) also connects with OAuth and registers itself. Leave any client id and secret empty.

1. Sign in, connect Google Drive, and tick at least one folder.
2. In Muse, add a custom connector for `https://<project>.vercel.app/mcp`.
3. When the browser opens, sign in and click Allow.

The same **Connected apps** list shows the Muse connection, and **Disconnect** stops it.

### Connect Claude, ChatGPT or Dots

All of these use the same `https://<project>.vercel.app/mcp` address and OAuth. Leave any client id and secret empty.

- **Claude** (claude.ai, desktop, mobile): **Settings → Connectors → Add custom connector**.
- **ChatGPT**: turn on developer mode, then **Settings → Apps → Create** and choose OAuth.
- **Dots** (OpenAI dots): add the connector in ChatGPT first. Dots use the apps installed in your ChatGPT
  account, so there is no separate setup.

The server advertises `authorization_response_iss_parameter_supported`, so ChatGPT uses its stable
`https://chatgpt.com/connector_platform_oauth_redirect` callback, which is on the allow list.

### 7. Test it

1. **Ticked file works:** ask Grok "Read the doc *Test plan* in my Drive". It should quote it.
2. **Unticked file gets a link:** ask "Read the doc with ID `<id of Private note>`" (the ID is in the doc's URL
   after `/d/`). Grok should reply with a link like `https://<project>.vercel.app/requests/…`.
3. **Approve:** open the link (you're signed in as the owner). It shows what was asked, by which token and
   tool, and the reason. Choose **Share just this item** (or its parent folder) and click **Approve**.
4. **Retry:** ask Grok again. It works now.
5. **Remove:** in **Access**, click **Remove** next to `Private note`. Ask again: Grok gets a new approval link
   instead of the content (the server stops within ~2 seconds). If the item still has a share from an older
   bot account, Remove deletes that share too.
   `get_metadata` and `list_folder` only ever list parent folder ids that are themselves shared, so the ids of
   your other folders never reach Grok.
6. **Activity** shows every call, grant, revoke and decision (no file contents).

Grok can also ask for something it can't find with `request_access`; the approval page then lets you browse
and pick the item to share.


## Phase 1 setup guide (single folder, no dashboard)

Everything below still works. With phase 2 configured you only need parts of it: (d) tokens, (f) connecting
Grok, (g) disconnecting the built-in connector and (h) MCP Inspector.

You'll need: a Google account that owns the folder (your normal account), a Vercel account, and
[uv](https://docs.astral.sh/uv/) on your computer (`curl -LsSf https://astral.sh/uv/install.sh | sh`).

```bash
git clone https://github.com/parthit/scoped-drive-mcp && cd scoped-drive-mcp
uv sync
```

### (a) Pick the folder

1. In your own Google Drive, open the folder Grok should use.
2. Copy the ID from the address bar:
   `https://drive.google.com/drive/folders/`**`1AbCdEfGh...`** ← this is your `ROOT_FOLDER_ID`.
   The allowlist is what keeps Grok to this folder. The refresh token below can see the rest of this Drive.

### (b) Google Cloud project, Drive API and OAuth client

Do these steps while signed in to the Google Cloud console with **any** account (your own is fine).

1. Go to <https://console.cloud.google.com/>, click the project picker at the top, then **New project**. Name it
   (e.g. `grok-drive`) and create it.
2. **Enable the Drive API:** open **APIs & Services → Library**, search for **Google Drive API**, click **Enable**.
3. **OAuth consent screen:** open **APIs & Services → OAuth consent screen** (called **Google Auth Platform** in
   newer consoles).
   - Fill in an app name (e.g. `Grok Drive Bot`) and your email addresses.
   - **Audience / User type:** choose **External**.
   - Under **Test users**, add your own Gmail address.
4. **Publish the app:** on the same page (**Audience**), click **Publish app** and confirm, so the status
   becomes **In production**.
   **This matters:** while an app is in *Testing*, Google expires its refresh tokens after **7 days** and the
   server would stop working every week.
   You do **not** need to submit the app for verification. For personal use, Google will show a
   **"Google hasn't verified this app"** warning when you sign in. That's expected: click **Advanced** and then
   **Go to … (unsafe)**. You're the developer and the only user.
5. **Create the OAuth client:** open **APIs & Services → Credentials → Create credentials → OAuth client ID**
   (or **Clients → Create client**), choose application type **Desktop app**, and create it. Copy the
   **Client ID** and **Client secret**, or download the JSON file. Keep the JSON **outside** this repo (or delete it
   when done). The `.gitignore` also blocks `client_secret*.json`.

### (c) Get your refresh token

Run this on your own computer. A browser window opens. **Sign in as yourself.** An old bot account's token
makes Grok see that account's Drive, which does not contain your files.

```bash
export GOOGLE_OAUTH_CLIENT_ID="...apps.googleusercontent.com"
export GOOGLE_OAUTH_CLIENT_SECRET="..."
uv run python scripts/bootstrap_oauth.py
# or: uv run python scripts/bootstrap_oauth.py --client-secrets ~/Downloads/client_secret_XXXX.json
```

Accept the unverified-app warning and the Drive permission. The script prints a **refresh token**. That's your
`GOOGLE_OAUTH_REFRESH_TOKEN`. Treat it like a password.

> If it says no refresh token was returned, remove the app at <https://myaccount.google.com/permissions>
> (signed in as yourself) and run the script again.

### (d) Create API tokens for Grok

Each token has a name and a role. The server stores only the SHA-256 **hash**. You give the token itself to Grok.

```bash
uv run python scripts/make_token.py grok-viewer viewer
# Token (give this to Grok; ...):
#   q3J...random...
# API_TOKENS entry (put this in Vercel):
#   grok-viewer:viewer:5f2b...64 hex chars...
```

Combine several entries with commas:
`API_TOKENS=grok-viewer:viewer:<hash>,grok-editor:editor:<hash>,me-admin:admin:<hash>`

Already have a token? Get its hash with `uv run python scripts/make_token.py --hash-only "<token>"`, or:

```bash
printf '%s' "<token>" | shasum -a 256      # macOS
printf '%s' "<token>" | sha256sum          # Linux
```

To revoke a token, remove its entry from `API_TOKENS` and redeploy.

### (e) Configure Vercel

In the Vercel dashboard, open your project → **Settings → Environment Variables** and add these. **You type the
values in yourself.** They are never stored in this repo.

| Name | Required | Value |
| --- | --- | --- |
| `ROOT_FOLDER_ID` | yes (phase 1) | folder ID from step (a); optional with the dashboard |
| `GOOGLE_OAUTH_CLIENT_ID` | yes | from step (b) |
| `GOOGLE_OAUTH_CLIENT_SECRET` | yes | from step (b) |
| `GOOGLE_OAUTH_REFRESH_TOKEN` | yes (phase 1) | from step (c); your own account. Optional once the dashboard sign-in is stored, and it overrides that sign-in if set |
| `API_TOKENS` | yes | from step (d) |
| `AUTH_MODE` | no | `oauth_bot` (the default and only mode) |
| `MAX_BYTES` | no | max bytes fetched per read (default `5242880`, 5 MB). `download_file` also caps the returned bytes at 1 MiB |
| `MAX_CHARS` | no | max characters returned per read (default `100000`) |
| `SCOPE_CACHE_TTL` | no | seconds to cache folder lookups (default `60`) |

Then redeploy (push to `main` or click **Redeploy**). Check `https://<project>.vercel.app/health`:

- `{"status":"ok"}` means the configuration loaded. This endpoint doesn't contact Google.
- HTTP 503 with `"misconfigured"` lists which settings are missing or invalid (names only, never values).

Notes:

- The repo includes `vercel.json` (routes `/mcp` and `/health` to `api/index.py`, `maxDuration` 60 s, well within
  Hobby's 300 s limit) and `requirements.txt` for the Python runtime.
- **Preview deployments** are usually behind Vercel's *Deployment Protection* login, so Grok can't reach them.
  Use the production URL (`https://<project>.vercel.app/mcp`).

### (f) Connect Grok

#### xAI API (Responses API)

Add the server as a remote MCP tool in `POST https://api.x.ai/v1/responses`:

```json
{
  "model": "grok-4.7",
  "input": [{"role": "user", "content": "List the files in my Drive folder."}],
  "tools": [
    {
      "type": "mcp",
      "server_url": "https://<project>.vercel.app/mcp",
      "server_label": "drive",
      "authorization": "<token from step d>",
      "allowed_tools": ["search_files", "list_folder", "get_metadata", "read_file", "download_file"]
    }
  ]
}
```

`authorization` is sent to the server in the `Authorization` header. The server accepts both
`Bearer <token>` and the bare token. `allowed_tools` is optional. The server already hides tools the token's role
can't use, but it's a good extra limit.

With the Python `xai_sdk`:

```python
import os
from xai_sdk import Client
from xai_sdk.chat import user
from xai_sdk.tools import mcp

client = Client(api_key=os.environ["XAI_API_KEY"])
chat = client.chat.create(
    model="grok-4.7",
    tools=[
        mcp(
            server_url="https://<project>.vercel.app/mcp",
            server_label="drive",
            authorization=os.environ["DRIVE_MCP_TOKEN"],
            allowed_tool_names=[
                "search_files",
                "list_folder",
                "get_metadata",
                "read_file",
                "download_file",
            ],
        )
    ],
)
chat.append(user("Summarise the newest document in my Drive folder."))
print(chat.sample().content)
```

#### Grok Bot

Grok Bot cannot use a static bearer. See [Connect Grok Bot](#connect-grok-bot).

#### grok.com

Open **Connectors → New Connector → Custom**, and enter `https://<project>.vercel.app/mcp`. If the form only
offers OAuth, finish [Connect Grok Bot](#connect-grok-bot) (sign in as the owner and click Allow). If it still
has a bearer field, that value is the token from step (d), not an OAuth access token.

### (g) Disconnect Grok's built-in Google Drive connector

If Grok has its own Google Drive connector connected to **your** account, it can bypass this server and see your
whole Drive. On grok.com, open **Settings → Connectors**, find **Google Drive**, and disconnect it. Then, signed
in to your own Google account, open <https://myaccount.google.com/permissions> and remove any Grok/xAI access
listed there.

### (h) Test with MCP Inspector

```bash
npx @modelcontextprotocol/inspector
```

In the Inspector UI choose transport **Streamable HTTP**, URL `https://<project>.vercel.app/mcp` (or
`http://127.0.0.1:8000/mcp` locally), and add the header `Authorization: Bearer <token>` (in the
authentication/headers section). Click **Connect**, then **List Tools**. Try:

- `list_folder` with no arguments: shows the items you shared (and `ROOT_FOLDER_ID`, if set).
- `read_file` with the ID of a file that isn't shared: returns an `access_required` error with an approval link
  (or `Forbidden` if `APP_BASE_URL` isn't set).
- With a viewer token, `create_folder` doesn't appear at all, and calling it anyway returns `Permission denied`.

### Run locally

```bash
cp .env.example .env        # fill in values; .env is git-ignored
# for the dashboard locally: APP_BASE_URL=http://localhost:8000 (and that redirect URI in Google Cloud);
# without the Redis variables an in-memory store is used (lost on restart; refused on Vercel)
uv run --env-file .env uvicorn api.index:app --reload
curl http://127.0.0.1:8000/health
open http://localhost:8000/   # the dashboard
```

### Run the tests

```bash
uv run pytest            # no network needed (uses an in-memory fake Drive)
uv run ruff check .
```

After changing dependencies, regenerate Vercel's requirements file:
`uv export --no-dev --no-hashes --no-emit-project -o requirements.txt`.

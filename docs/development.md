# Development notes

Local setup, tests and pull requests are in [CONTRIBUTING.md](../CONTRIBUTING.md).
How the pieces fit, the data model and the trade-offs are in [architecture.md](architecture.md).

## Project layout

```
api/index.py                  Vercel entry point (app = build_app())
api/blob-sign.mjs             Node.js function that signs Vercel Blob URLs for held files (drops)
package.json                  its one dependency, @vercel/blob (pinned; `npm ci`, `npm test`)
vercel.json                   routes everything else to api/index.py, maxDuration, bundles templates,
                              and the daily clean-up cron
requirements.txt              runtime deps for Vercel (exported from uv.lock)
scripts/bootstrap_oauth.py    optional: one-time sign-in → refresh token (legacy GOOGLE_OAUTH_REFRESH_TOKEN)
scripts/make_token.py         generate API tokens + hashes
scripts/make_secrets.py       generate SESSION_SECRET and ENCRYPTION_KEY
scripts/terminal_agent_setup.py  writes docs/terminal-agent-setup.md from templates/terminal_setup.md
src/scoped_drive_mcp/
  server.py                   build_app(), the one place everything is wired together; ScopedFastMCP
  tools/                      MCP tool registration, one module per group (drive, uploads, access,
                              mailbox, shared, drops, notion, onedrive) + instructions
  config.py                   env-var settings (pydantic-settings), missing-settings report
  ops.py                      /health/ready and the scheduled clean-up route (/internal/sweep)
  errors.py                   report_exception: one place unexpected errors go

  Who is calling
  auth.py                     bearer-token ASGI middleware for /mcp (API tokens and OAuth access tokens)
  mcp_oauth.py                MCP OAuth 2.1 authorization server (dynamic client registration, PKCE)
  oauth.py                    Google web OAuth (authorization code) for the dashboard
  ratelimit.py                fixed-window limits on the store's atomic counter
  policy.py                   role → tool map and @require (role check, audit row, error mapping)
  audit.py                    JSON-lines audit log (+ the store's activity list)

  Google Drive
  drive_client.py             credentials + thin Drive v3 wrappers
  scope.py                    the allowlist scope guard and search query builder
  service.py                  Drive tool implementations
  uploads.py                  chunked uploads: pieces in the store, checked and created in one step
  extract.py                  text from PDF, Word, PowerPoint, Excel, RTF and .doc bytes, under a work budget
  extract_worker.py           runs extract.py in a child process with memory, CPU and time limits

  Other connections (optional, each behind its own allowlist)
  connections.py              the services a person can connect, one consent step each
  notion.py / notion_client.py        Notion: tools / OAuth and API calls
  onedrive.py / onedrive_client.py    OneDrive: tools / OAuth and Microsoft Graph calls

  People and their assistants
  access.py                   access requests (storage, dedupe, request tools)
  agent_roles.py              named roles: /mcp/role/<slug> narrows a call to part of the allowlist
  peer_requests.py            requests between paired people, for people only (no MCP tool reads them)
  peer_request_pages.py       their dashboard routes
  grants.py                   owner-side grant/revoke and approve/deny
  bridge/                     pairings and the mailbox between one person's own assistants
    pairing.py / mail.py / webhooks.py   the three parts of Mailbox (mailbox.py puts them together)
    common.py                   errors, limits, key names and helpers they share
  wake.py                     the HTTPS ping that wakes a paired assistant (host allowlist, pinned address)
  external.py                 what a paired person's assistants may read or edit (the Sharing list)
  untrusted.py                markers around other people's text that the text cannot forge
  shared_sources.py           "Shared with me" as a browsable tree for the dashboard
  drops.py / drop_storage.py  sending a file to a paired person / where its bytes wait (store or Vercel Blob)

  Storage
  store/                      everything kept in Redis or Postgres
    backends.py                 the KeyValueStore interface; Memory, Redis and Postgres
    wrappers.py                 key prefix, signed records, per-person keys
    records.py                  allowlist, encrypted tokens, activity log
    tenancy.py                  who has an account; sessions
    __init__.py                 build_store, the one-time Redis → Postgres copy, re-exports

  Dashboard
  dashboard.py                session, CSRF and error wrappers, security headers, static assets,
                              and the route table
  pages/                      the pages themselves, one module per group (signin, connections, files,
                              sharing, drops, requests, admin, consent, settings); kit.py is what
                              dashboard.py hands them, common.py what they share
  humanize.py                 plain-language timestamps, names and activity rows; reads nothing
  templates/                  dashboard HTML (Jinja2), app.css, ui.js, fonts

  terminal/                   Bot RBAC Terminal (docs/terminal.md), server side; `term:` keys only
    feature.py                  dashboard pages, /api/terminal/*, /terminal/setup.md and install.sh
    roles.py                    per-person roles (tool patterns), built-ins, tools seen
    device.py                   device-code login, terminal tokens, terminal records
    ingest.py                   audit rows from terminals, sessions, revocation
src/botrbac_cli/              the `botrbac` CLI. The server imports patterns.py, signing.py and
                              api.DEFAULT_SERVER from it, so both sides share one definition
  patterns.py                 tool patterns and the session chain check (pure Python)
  signing.py                  the signed policy: the server signs, the CLI verifies
  sealing.py                  seals recorded commands to the site's key, so only the website reads them
  main.py                     commands
  api.py                      the website's /api/terminal endpoints, with token refresh
  state.py                    the files the CLI keeps on the computer ($BOTRBAC_HOME)
  gateway.py                  stdio MCP gateway in front of upstream MCP servers
  policy.py                   cached policy, offline grace, enforcement
  protect.py                  files an agent may not change whatever its role
  queue.py / sync.py          SQLite audit queue and sending it
  session.py / shell.py       `botrbac run --role`, `shell-init`
  coverage.py / check.py / hooks.py   wrap, add-gateway, doctor, hook adapter, Claude Code hook install
  shellcmd.py                 programs in a shell command, for cmd/<program> patterns
tests/                        pytest suite with a fake Drive (owner and bot views) and in-memory store
tests/node/                   node --test suite for api/blob-sign.mjs (Blob SDK faked)
```

### Implementation notes

- Uses the official MCP Python SDK's `FastMCP` (`mcp>=1.30,<2`). In `mcp` 2.x `FastMCP` was renamed to `MCPServer`,
  so the 1.x line is pinned.
- The dashboard is a separate Starlette app mounted next to `/mcp` and `/health`; `/mcp` is wrapped in the
  bearer middleware on its own, so the dashboard cookie and the MCP bearer are not interchangeable. `/mcp`
  accepts either a pre-shared `API_TOKENS` bearer or an OAuth access token from `/oauth/token`. Discovery
  documents under `/.well-known/` are public.
- The server runs in stateless JSON mode. Instead of relying on the ASGI lifespan to start FastMCP's
  session manager (serverless runtimes may skip lifespan, or send the first request before startup finishes),
  `/mcp` starts a short-lived stateless session manager **inside each request**. This works the same under
  uvicorn, Vercel and test clients without lifespan.

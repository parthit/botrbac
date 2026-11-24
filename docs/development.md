# Development notes

Local setup, tests and pull requests are in [CONTRIBUTING.md](../CONTRIBUTING.md).

## Project layout

```
api/index.py                  Vercel entry point (app = build_app())
api/blob-sign.mjs             Node.js function that signs Vercel Blob URLs for held files (drops)
package.json                  its one dependency, @vercel/blob (pinned; `npm ci`, `npm test`)
vercel.json                   routes everything else to api/index.py, maxDuration, bundles templates
requirements.txt              runtime deps for Vercel (exported from uv.lock)
scripts/bootstrap_oauth.py    optional: one-time sign-in → refresh token (legacy GOOGLE_OAUTH_REFRESH_TOKEN)
scripts/make_token.py         generate API tokens + hashes
scripts/make_secrets.py       generate SESSION_SECRET and ENCRYPTION_KEY
src/scoped_drive_mcp/
  config.py                   env-var settings (pydantic-settings), missing-settings report
  drive_client.py             credentials + thin Drive v3 wrappers (bot, owner, lazy bot)
  scope.py                    the allowlist scope guard and search query builder
  policy.py                   role → tool map and @require decorator (access_required errors)
  access.py                   access requests (storage, dedupe, request tools)
  bridge.py                   pairings; mailbox between one person's own assistants
  grants.py                   owner-side grant/revoke and approve/deny
  store.py                    Redis / in-memory store, allowlist, encrypted tokens, activity log
  oauth.py                    Google web OAuth (authorization code) for the dashboard
  mcp_oauth.py                MCP OAuth 2.1 authorization server (dynamic client registration, PKCE)
  dashboard.py                owner dashboard routes (Starlette)
  templates/                  dashboard HTML (Jinja2)
  auth.py                     bearer-token ASGI middleware for /mcp (API tokens and OAuth access tokens)
  audit.py                    JSON-lines audit log (+ Redis activity sink)
  extract.py                  text from PDF, Word, PowerPoint, Excel, RTF and .doc bytes, under a work budget
  extract_worker.py           runs extract.py in a child process with memory, CPU and time limits
  service.py                  tool implementations
  server.py                   FastMCP tools + build_app()
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

# Notes for coding agents

Bot RBAC is an MCP server and web dashboard that limits AI assistants to the Google Drive files a person
allows. Python 3.12, managed with `uv`, deployed as one Vercel function (`api/index.py`), plus a small
Node.js function (`api/blob-sign.mjs`) that only signs Vercel Blob URLs for the Python app.

- **Setting it up for someone?** Follow [docs/agent-setup.md](docs/agent-setup.md), section
  "Instructions for the agent".
- **Install:** `uv sync`
- **Test:** `uv run pytest -q` (no network; uses a fake Drive and an in-memory store)
- **Lint/format:** `uv run ruff check .` and `uv run ruff format --check .` (use the locked ruff via `uv run`)
- **Node signer** (`api/blob-sign.mjs`, signs Vercel Blob URLs): `npm ci --ignore-scripts`, then `npm test`
  and `node --check api/blob-sign.mjs`. Keep `@vercel/blob` pinned to an exact version in `package.json`.
- **Run locally:** `cp .env.example .env`, fill it in, then
  `uv run --env-file .env uvicorn api.index:app --reload --port 8000`
- **After changing dependencies:** `uv export --no-dev --no-hashes --no-emit-project -o requirements.txt`
  (Vercel installs from `requirements.txt`; CI fails if it drifts from `uv.lock`).
- **Terminal CLI** (`src/botrbac_cli/`, the `botrbac` command; [docs/terminal.md](docs/terminal.md)): its
  tests run in the same `uv run pytest -q`. Try it with `uv run botrbac --help`. **Setting up Terminal on
  someone's computer?** Follow [docs/terminal-agent-setup.md](docs/terminal-agent-setup.md) (generated from
  `templates/terminal_setup.md` by `scripts/terminal_agent_setup.py`).
- Code lives in `src/scoped_drive_mcp/` (the package keeps its original name). Layout:
  [docs/development.md](docs/development.md).
- Never commit `.env`, tokens, or Google client JSON. Keep the allowlist check, role checks and security
  behaviour intact unless the task is explicitly about them ([docs/security.md](docs/security.md)).

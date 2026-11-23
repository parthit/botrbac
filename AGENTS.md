# Notes for coding agents

Bot RBAC is an MCP server and web dashboard that limits AI assistants to the Google Drive files a person
allows. Python 3.12, managed with `uv`, deployed as one Vercel function (`api/index.py`).

- **Setting it up for someone?** Follow [docs/agent-setup.md](docs/agent-setup.md), section
  "Instructions for the agent".
- **Install:** `uv sync`
- **Test:** `uv run pytest -q` (no network; uses a fake Drive and an in-memory store)
- **Lint/format:** `uv run ruff check .` and `uv run ruff format --check .` (use the locked ruff via `uv run`)
- **Run locally:** `cp .env.example .env`, fill it in, then
  `uv run --env-file .env uvicorn api.index:app --reload --port 8000`
- **After changing dependencies:** `uv export --no-dev --no-hashes --no-emit-project -o requirements.txt`
  (Vercel installs from `requirements.txt`; CI fails if it drifts from `uv.lock`).
- Code lives in `src/scoped_drive_mcp/` (the package keeps its original name). Layout:
  [docs/development.md](docs/development.md).
- Never commit `.env`, tokens, or Google client JSON. Keep the allowlist check, role checks and security
  behaviour intact unless the task is explicitly about them ([docs/security.md](docs/security.md)).

# Contributing

Bot RBAC is an MCP server that sits between AI assistants and Google Drive. A person signs in, ticks the
files and folders an assistant may use, and everything else stays out of reach.

## Set up locally

You need [uv](https://docs.astral.sh/uv/). It installs Python 3.12 for you.

```bash
uv sync
uv run pytest -q          # no network or Google account needed
```

To run the server with the dashboard you also need a Google OAuth client. See
[Run it on your computer](docs/self-hosting.md#run-it-on-your-computer).

Fill in `.env` on your own machine. It is git-ignored. Do not commit secrets, tokens, client JSON, or `.env`.

## Checks

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

`tests/test_store_backends.py` also checks the Postgres and Redis stores against real servers when
`TEST_DATABASE_URL` (e.g. `postgresql://postgres@127.0.0.1:5432/postgres`) and `TEST_REDIS_URL`
(e.g. `redis://127.0.0.1:6379`) are set; without them those cases are skipped. CI sets both. Use
throwaway servers: each test writes under its own random key prefix and nothing is cleaned up.

CI runs these on every pull request and on `main` (`.github/workflows/ci.yml`). Run ruff through `uv run`,
not a globally installed copy: CI uses the version locked in `uv.lock`.

After you change dependencies, regenerate the Vercel requirements file and commit it with the change:

```bash
uv export --no-dev --no-hashes --no-emit-project -o requirements.txt
```

## Pull requests

Branch from `main`. Describe what changed and why. Add a test for behaviour changes.

Keep the existing allowlist checks, roles and security behaviour intact unless the pull request is
explicitly about that.

## Security

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## License

By contributing you agree your contribution is licensed under the [MIT License](LICENSE).

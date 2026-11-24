# Bot RBAC Terminal

Roles defined on the website, enforced on your own computers by the `botrbac` CLI, for any agent that
speaks MCP: Claude Code, Codex, Cursor, Gemini CLI and others. It sits next to the hosted Drive server and
does not change `/mcp`, the existing dashboard pages or existing connections.

```
agent (Claude Code, Codex, …)
  │  MCP over stdio
  ▼
botrbac gateway ── role check ── audit row (SQLite) ──► website when online
  │  forwards allowed calls
  ▼
your MCP servers (GitHub, filesystem, …)
```

## Set up

1. **Install:** `uv tool install git+https://github.com/parthit/botrbac` (puts `botrbac` on your PATH).
2. **Log in:** `botrbac login --server https://<your Bot RBAC site>`. Open the link it prints, check the
   code matches, pick a role and approve. The computer appears on the **Terminal** page.
3. **Put your agent's MCP servers behind Bot RBAC:**
   - `botrbac wrap claude-code` (the project's `.mcp.json`), `botrbac wrap cursor`, `botrbac wrap gemini`,
     `botrbac wrap codex`, or `botrbac wrap other --file path/to/config.json`. The original file is kept as
     `<name>.botrbac-backup-<time>`. Add `--dry-run` to see what would change.
   - Or add servers yourself, `botrbac servers add github -- npx -y @modelcontextprotocol/server-github`
     or `botrbac servers add notes --url https://…/mcp`, and add `botrbac gateway` to your agent as an
     MCP server.
4. **Check:** `botrbac doctor` lists anything that still bypasses Bot RBAC.

Tools appear to the agent as `<server>__<tool>`. Tools the role does not allow are not listed, and calling
one anyway returns an error that names the role.

## Roles

**Terminal → Roles** on the website. A role is a list of tool patterns:

| Pattern | Means |
| --- | --- |
| `github/create_issue` | one tool |
| `github/*` | every tool on one server |
| `github/get_*` | tools on a server whose names start with `get_` |
| `*/read*` | tools on any server whose names start with `read` |
| `*` | everything |

Tools are named `<server>/<tool>`. Server names are the names in `botrbac servers list`. An agent's own
tools (see [hooks](#an-agents-own-tools-hooks)) use the agent's name: `claude-code/Bash`, `codex/shell`.
Once a terminal syncs, the tools it saw are offered as tick boxes on the role page.

Built-in roles: **Read-only** (the default for a new terminal, and what a terminal falls back to if its role
is deleted), **Full access** and **No tools**. Each role also sets an **offline grace** (1–30 days, below).

## Narrower roles for one run: `--role`

```
botrbac run --role reviewer -- claude
```

starts the agent in a **session** whose tools are the intersection of the terminal's role and `reviewer`.
To type it the way you start the agent anyway, add this to your shell's startup file:

```
eval "$(botrbac shell-init)"          # bash or zsh
botrbac shell-init --shell fish | source
```

Then `claude --botrbac --role reviewer`, `codex --botrbac --role reviewer` and so on run through
`botrbac run`. Without `--botrbac` the agent starts exactly as before. `--agents a,b` picks which commands
to wrap.

- The session id travels in `BOTRBAC_SESSION`, which every process the agent starts inherits: subagents,
  `codex exec`, scripts and gateways. A session started inside another one gets the intersection again, so
  it can only **narrow**; asking for a wider role changes nothing.
- Subagents running inside the agent's own process share its connection and so its role.
- **Terminal → Activity** links each call to its session. The session page shows the tree of sessions
  started under it and lets you **revoke** it, which blocks it and everything under it the next time the
  terminal checks in (about a minute while online).

## An agent's own tools: hooks

The gateway sees MCP tools. An agent's built-in tools (shell, file edits, web fetch) never go through MCP,
so they are checked by the agent's pre-tool hook calling `botrbac check`:

```
botrbac hooks install claude-code          # this project's .claude/settings.json
botrbac hooks install claude-code --user   # every project
```

This adds a `PreToolUse` hook that runs `botrbac check --agent claude-code --block-unguarded` before every
tool call. The call is checked as `claude-code/<Tool>`, so give roles the tools you want, such as
`claude-code/Read`, `claude-code/Edit` or `claude-code/*`. With `--block-unguarded`, MCP tools that do not
come through `botrbac gateway` are blocked; pass `--allow-unguarded` to check them as `<server>/<tool>`
instead.

For another agent with pre-tool hooks, make the hook run `botrbac check --agent <name>` with the tool call
as JSON on stdin (it reads `tool_name`, `toolName`, `tool` or `name`). Exit code 0 allows and 2 blocks, with
the reason on stderr. `--format json` prints `{"decision": "allow"|"deny", "reason": …}` instead, and
`--tool NAME` skips stdin.

## Offline

The policy (role, roles you may narrow to, revoked sessions) is cached on the computer with the time it was
fetched. Without internet the cached policy is used for the role's offline grace, then **every tool is
blocked** until the terminal checks in again. A computer with no cached policy blocks everything.

Every decision is written to `~/.config/botrbac/audit.db` and sent when the site can be reached: every
minute from a running gateway, when a gateway or `botrbac run` ends, and on `botrbac sync`. Rows have an id,
so a batch sent twice is stored once. **Terminal → Activity** marks rows that were recorded offline and
sent later.

## What it can and cannot guarantee

Bot RBAC Terminal sees only tool calls that go through `botrbac gateway` or a hook that calls
`botrbac check`. It stops an **agent** from going around your rules. It cannot stop the **person who owns
the computer**: they can edit the agent's config, remove the hook or delete the cached policy. Where an
agent supports settings an administrator controls (for example Claude Code's managed settings), put the
gateway and hook there so they cannot be removed from the computer itself.

Audit rows hold identifiers and decisions only: the tool name, agent, role, session, and allow or block.
Never tool arguments, results or file contents. A session start records the program's name, never its
arguments.

## Commands

| Command | |
| --- | --- |
| `botrbac login --server URL` | Connect this computer (device code approved on the website) |
| `botrbac status` | Account, role, policy age, rows waiting, current session |
| `botrbac servers add/remove/list` | The MCP servers the gateway sits in front of |
| `botrbac gateway [--agent NAME]` | The MCP server your agent starts |
| `botrbac wrap <agent> [--file F] [--dry-run]` | Move an agent's MCP servers behind the gateway |
| `botrbac doctor` | Login, policy age, servers that bypass Bot RBAC |
| `botrbac run --role R -- cmd …` | Run a command in a narrower session |
| `botrbac shell-init` | Shell functions for `<agent> --botrbac --role R` |
| `botrbac hooks install claude-code` | Check Claude Code's own tools too |
| `botrbac check --agent A` | The hook adapter (reads the tool call on stdin) |
| `botrbac sync` / `botrbac log` | Send waiting rows now / show recent rows |
| `botrbac logout` | Forget this computer's login (disconnect it on the website too) |

Files live in `$BOTRBAC_HOME`, by default `~/.config/botrbac`: `credentials.json` (mode 0600),
`policy.json`, `config.json`, `audit.db`, `sessions/` and `state.json`.

## Server side

| Endpoint | Auth | |
| --- | --- | --- |
| `POST /api/terminal/device` | none, rate-limited per address | Start a device login (RFC 8628) |
| `POST /api/terminal/token` | device code or refresh token | Tokens: `brt_at_…` (1 hour), `brt_rt_…` (90 days, rotated) |
| `GET /api/terminal/policy` | terminal access token | Role, roles, revoked sessions, version |
| `POST /api/terminal/audit` | terminal access token | Up to 500 rows; tools seen; unguarded servers |

Terminal tokens work only on `/api/terminal/*`, and `/mcp` refuses them. Every key this feature writes
starts with `term:`; roles, terminals, tokens and revocations are signed like OAuth records. Each person
keeps their last 2000 terminal activity rows.

# Bot RBAC Terminal

Roles defined on the website, enforced on your own computers by the `botrbac` CLI, for any agent that
speaks MCP: Claude Code, Codex, Cursor, Gemini CLI and others. Coding agents setting it up: follow
[terminal-agent-setup.md](terminal-agent-setup.md). It sits next to the hosted Drive server and
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

## In one minute

- **Terminal**: a computer running `botrbac`, connected to your account. Agents on it call their tools
  through botrbac, which checks each call against the computer's role.
- **Role**: a list of allowed tools (`claude-code/Edit`, `github/get_*`, `cmd/git`). Anything else is
  blocked. Each computer has one, set on **Terminal → Terminals** in the Role column (pick, then
  **Change**). That is the only place a role is tied to a computer.
- **Built-in roles**: Read-only (new computers start here), Full access (nothing blocked), No tools
  (pause). **Terminal → Roles → New role** has templates (*Reviewer*, *Coding*, *Coding, limited shell*).
- **Activity**: every call, allowed or blocked, with the exact tool name to add when something you want
  is blocked.
- **Unguarded server**: an MCP server the agent reaches directly, so no role covers it. `botrbac doctor`
  prints the fix, usually `botrbac wrap claude-code --user`.
- **`--role`**: narrows one session below the computer's role; it can never widen it.

The goal: every computer on a role that fits the work done there, and no unguarded servers.

## Set up

The **Terminal** page on the website offers three ways. Each ends with you approving one code in the
browser.

- **Paste into your terminal:**
  `curl -fsSL https://botrbac.com/terminal/install.sh | sh -s -- --agent claude-code` (or `cursor`, `codex`,
  `gemini`). The script installs botrbac with uv or pipx (installing uv first only when neither is there),
  runs `botrbac login`, adds the gateway to that agent and runs `botrbac doctor`. For Claude Code it also adds
  the hook (`botrbac hooks install claude-code --user --allow-unguarded`), so Claude's own shell and file
  edits follow the role as well; `--no-hook` leaves it out and `botrbac hooks remove claude-code --user`
  undoes it. A new computer starts as Read-only, so with the hook Claude can read but not edit or run
  commands until you give it a wider role. It never uses sudo and can be run again. Read it first at the
  same address: `https://botrbac.com/terminal/install.sh`.
- **Paste into your agent:** `Set up Bot RBAC Terminal for me by following https://botrbac.com/terminal/setup.md`.
  The agent follows [terminal-agent-setup.md](terminal-agent-setup.md) (the same text the site serves).
- **Step by step:**
  1. `uv tool install git+https://github.com/parthit/botrbac` (or `pipx install git+…`).
  2. `botrbac login`. Open the link it prints, check the code matches, pick a role and approve. It connects
     to `https://botrbac.com` unless you give `--server URL` or set `BOTRBAC_SERVER`; the page shows the
     right command for the site you are on.
  3. `claude mcp add botrbac -- botrbac gateway` for Claude Code, or `botrbac add-gateway --agent cursor`
     (also `codex`, `gemini`), which adds the gateway to that agent's file in your home directory, keeps the
     other servers and a backup, and does nothing when it is already there.

Then put MCP servers behind the gateway so their tools follow the role:

- `botrbac servers add github -- npx -y @modelcontextprotocol/server-github` or
  `botrbac servers add notes --url https://…/mcp`, one server at a time; or
- `botrbac wrap claude-code` (the project's `.mcp.json`; add `--user` for `~/.claude.json`, including
  servers set for one project), `botrbac wrap cursor`, `botrbac wrap gemini`, `botrbac wrap codex`, or
  `botrbac wrap other --file path/to/config.json`, which moves every server in the file. The original is kept
  as `<name>.botrbac-backup-<time>`. Add `--dry-run` to see what would change.

`botrbac doctor` lists anything that still bypasses Bot RBAC.

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
| `cmd/gh` | the `gh` program in an agent's shell (`cmd/git*`, `cmd/*` work the same way) |

Tools are named `<server>/<tool>`. Server names are the names in `botrbac servers list`. An agent's own
tools (see [hooks](#an-agents-own-tools-hooks)) use the agent's name: `claude-code/Bash`, `codex/shell`.
Once a terminal syncs, the tools it saw are offered as tick boxes on the role page. A bare word such as
`gh` is refused with a hint: to allow the gh command, use `cmd/gh`.

Built-in roles: **Read-only**, **Full access** and **No tools**. A terminal whose role is deleted gets **No
tools** until you give it another role. Each role also sets an **offline grace** (1–30 days, below).

Patterns go by tool **names**. Read-only allows tools whose names start with read, get, list or search,
which is not a promise about what a server's tool really does, so check them. It also allows Claude Code's
Read, Grep, Glob and LS, which can read any file the computer's user can, including `~/.config/botrbac`.
Roles limit which tools run, not which files those tools touch.

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
- This relies on the agent keeping `BOTRBAC_SESSION`. An agent that can run shell commands could start
  `botrbac gateway` without it and get the terminal's own role (never more). If that matters, make the
  terminal's role itself narrow, or block the agent's shell tool with the hook below.
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

### Shell commands: `cmd/<program>`

An agent runs `gh pr list` through its shell tool, which the hook sees as one call to `claude-code/Bash`:
all of the shell or none of it. To allow some programs only, add `cmd/` patterns to the role:

```
claude-code/Bash
cmd/git
cmd/gh
```

When any role in force has a `cmd/` pattern, a shell call is allowed only if the shell tool itself is
allowed **and** every program in the command is allowed as `cmd/<program>`. The shell tools are Claude
Code's `Bash`, Codex's `shell` and Gemini CLI's `run_shell_command` (`SHELL_TOOLS` in
`src/botrbac_cli/shellcmd.py`). A role with no `cmd/` patterns works exactly as before. `*` and `*/read*`
never count as `cmd/` patterns.

The command is read conservatively. It is split on `;`, `&&`, `||`, `|`, `&` and new lines; each part's
program is its first word after `VAR=value` assignments, and `/usr/bin/gh` counts as `gh`. A wrapper
(`sudo`, `env`, `time`, `nohup`, `xargs`, `command`, `exec`) must be allowed itself **and** so must the
program it runs: `sudo gh` needs `cmd/sudo` and `cmd/gh`. The call is **blocked** when the command uses
`$(…)`, backticks, `<(…)`, `>(…)`, `eval`, `bash -c`/`sh -c`, a `( … )` subshell, shell control flow
(`if`, `for`, `while`, `case`, `!` …), a variable as the program, or anything else it cannot read; the
reason says why. Heredocs are read as commands too, so a role with `cmd/`
patterns blocks most of them. The row's reason names programs only; the command itself is recorded
only with [Record commands](#record-commands) on, and then sealed.

This protects against the agent, not the computer's owner, and goes by name: a program that starts others
(`make`, `npm run`, `find -exec`, `timeout`, `nice`, git aliases, scripts) runs whatever it runs, so
allowing `cmd/timeout` allows anything `timeout` can start.

For another agent with pre-tool hooks, make the hook run `botrbac check --agent <name>` with the tool call
as JSON on stdin (it reads `tool_name`, `toolName`, `tool` or `name`). Exit code 0 allows and 2 blocks, with
the reason on stderr; any error inside the check also exits 2. `--format json` prints
`{"decision": "allow"|"deny", "reason": …}` and always exits 0, so a caller using it must read
`decision`. `--tool NAME` skips stdin.

The hook command uses botrbac's full path. If that file is removed, the agent cannot run the hook, and most
agents (Claude Code included) then let the call go ahead: run `botrbac doctor` after moving or reinstalling
botrbac. MCP tools named `mcp__botrbac__…` are left to the gateway, which checks them itself; this trusts
that the server called `botrbac` in the agent's config is the gateway (`botrbac wrap` sets it up that way).

## Offline

The policy (role, roles you may narrow to, revoked sessions) is cached on the computer with the time it was
fetched, signed by the site (see [below](#what-it-can-and-cannot-guarantee)). Without internet the cached policy is used for the role's offline grace, then **every tool is
blocked** until the terminal checks in again. A computer with no cached policy blocks everything.

Every decision is written to `~/.config/botrbac/audit.db` and sent when the site can be reached: every
minute from a running gateway, when a gateway or `botrbac run` ends, and on `botrbac sync`. Rows have an id,
so a batch sent twice is stored once. **Terminal → Activity** marks rows that were recorded offline and
sent later.

## What it can and cannot guarantee

Bot RBAC Terminal sees only tool calls that go through `botrbac gateway` or a hook that calls
`botrbac check`. It stops an **agent** from going around your rules. It cannot stop the **person who owns
the computer**: they can edit the agent's config, remove the hook or delete the cached policy.

An agent could try to switch Bot RBAC off from inside, by editing the files it depends on. These layers
cover that, from strongest to weakest:

- **Signed role.** The site signs every policy it sends, and botrbac remembers the site's key from login.
  If the cached role on the computer is edited, every tool is blocked until `botrbac sync` fetches a fresh
  one. The offline grace counts from when the site issued the policy, so editing the saved fetch time does
  not stretch it. (Needs `ENCRYPTION_KEY` on the server; computers logged in before this pick up the key at
  their next token refresh.)
- **Protected files.** Whatever the role, a tool call that would change Claude Code's settings
  (`.claude/settings.json`, `.claude/settings.local.json`), `~/.claude.json` or botrbac's own folder is
  refused, as is one that mentions `disableAllHooks` or `botrbac hooks remove`. Paths are followed through
  symlinks and `..`. Reading those files is allowed, except botrbac's login file, which holds its tokens.
  This reads the call's text, so it is a speed bump: a path built at run time (variables, a script written
  elsewhere) gets past it.
- **Noticing.** `botrbac doctor` says when the hook is missing or switched off by `disableAllHooks`, and each
  sync tells the site, which marks the computer "hook off" on the Terminal page.

Extras for stricter setups, outside botrbac: put the hook and gateway in Claude Code's **managed settings**
(an administrator's file the user and agent cannot override, including `disableAllHooks`); add
`permissions.deny` rules for `Edit(~/.claude/**)` and `Edit(~/.config/botrbac/**)`; and run the agent in
Claude Code's sandbox, which keeps its shell from writing its own settings.

Audit rows hold identifiers and decisions: the tool name, agent, role, session, and allow or block. Tool
results and the contents of files read are never recorded. Unless you turn on Record commands, neither is
what was sent to a tool, and a session start records only the program's name.

### Record commands

Turn it on under **Terminal → Activity** to see the exact command each agent ran, secrets included: a
shell tool's command line, another tool's input (for Write, the file it wrote), the MCP arguments the
gateway passed on, and the whole `botrbac run` command line. Blocked calls are recorded too. Each one is
cut at 8,000 characters. It is off until you turn it on, and applies to all your terminals.

You can read it; the agents can't. The site's public key travels in the signed policy. The CLI seals each
command to it (X25519, AES-GCM, bound to the row) before the row is written to `audit.db`, so the queue
on the computer, `botrbac log` and anything else running as you see only ciphertext. Editing the key in
the cached policy breaks its signature, which blocks every tool. The site stores the sealed text and opens
it only to show it to you on the Activity page and in exports. The private key is derived from the
site's `ENCRYPTION_KEY`; change that and earlier commands can no longer be opened.

What this does not do: hide a command from the agent that ran it (it wrote it), or from whoever runs the
site, which can open what it stores. Nor is it proof of what ran: sealing needs only the public key, so an
agent that can run its own code on the computer can write rows with any command it likes, as it could
already write any row. The recorded command is what the computer reported.

Turning it off stops new commands at once on the site (a computer stops sealing them at its next
check-in). Commands already recorded stay, and keep showing to you, until their rows age out of the log
(the newest 2,000 rows are kept).

### Who did it: signing and delegation

`botrbac login` makes an Ed25519 key pair for this terminal. The private half stays in
`terminal_key.json` (mode 0600); the public half goes to the site with the token exchange, and the site
keeps it on the terminal. A computer that logged in before keys existed makes one and registers it at its
next token refresh (within an hour while online). A key is registered once and never replaced; to get a new
one, run `botrbac login` again.

Each audit batch is signed: `X-Botrbac-Signature: ed25519=<base64>`, `X-Botrbac-Key-Id`,
`X-Botrbac-Timestamp` and `X-Botrbac-Nonce`. The signature covers the method, the path, the sha256 of the
body, the timestamp, the nonce and the key id (a simplified HTTP Message Signatures, RFC 9421). The site
accepts it for 5 minutes either side of its clock and each nonce once. A terminal with a key must sign: a
missing, wrong, stale or replayed signature gets 401 and the rows stay waiting on the computer. If
`terminal_key.json` is lost, uploads keep failing until you run `botrbac login` again. A terminal without
a key (an older botrbac) is still accepted, and its rows are marked unsigned.

The site sets these on every row it stores, whatever the computer sent:

- `signed`: whether the batch carried a good signature from the terminal's key.
- `subject`: you, the account's email.
- `actor`: who acted for you, shaped like RFC 8693's `act` claim:
  `{"sub": "terminal:t_…", "act": {"sub": "agent:claude-code/<agent id>"}}`.
- `grant`: the role (and `policy_version`) the computer says it decided under.

The Activity page shows the chain on each row, for example "you → terminal vm → claude-code (subagent
…1a2b3c4d)", with a signed or unsigned mark. The exports carry the same fields as JSON.

### Export and webhook

**Terminal → Activity** exports CSV, JSON lines, or OpenTelemetry logs
(`/terminal/activity/export?format=otlp`): OTLP/JSON with one `resourceLogs` → `scopeLogs` → `logRecords`
entry per row, ready for an OTLP collector's file or HTTP receiver. Attributes follow OpenTelemetry semantic
conventions 1.37.0 where one fits: `gen_ai.tool.name`, `gen_ai.tool.call.id` (from `tool_use_id`),
`gen_ai.conversation.id` (from `agent_session_id`), `gen_ai.agent.id`, `gen_ai.agent.name`,
`gen_ai.operation.name` and `user.email`. The GenAI attributes have Development status in that version, so
their names may still change. Everything else is under `botrbac.*` (`botrbac.decision`, `botrbac.role`,
`botrbac.session_id`, `botrbac.event_id`, `botrbac.chain`, `botrbac.actor`, …). Blocked rows are
`WARN`, errors `ERROR`, the rest `INFO`. Like the other exports, recorded commands appear as text, for
you only.

The **audit webhook** posts each upload's new rows to an https address you set on the same page. Saving it
shows a secret once. Each POST is JSON (`{"v": 1, "type": "botrbac.terminal.audit", "rows": [...]}`) with
`X-Botrbac-Timestamp` and `X-Botrbac-Signature: sha256=<hex>`, the HMAC-SHA256 of `<timestamp>.<body>`
with the secret. Check it, and refuse timestamps more than a few minutes old. Recorded commands are left
out unless you tick "Include recorded commands"; then they are sent as text. Delivery is one try with a
3-second timeout; a failure never fails the upload, is not retried, and shows on the page as the last
delivery. The address must be https on port 443, with no user, query or fragment, and a name that resolves
only to public addresses (checked again at every delivery). It needs `ENCRYPTION_KEY` on the server.

### Commit trailer

`botrbac trailer install [--repo PATH]` adds a git `prepare-commit-msg` hook to one repository. A commit
made inside `botrbac run` (with `BOTRBAC_SESSION` set) then gets

    Botrbac-Session: https://botrbac.com/terminal/sessions/<id>

so a reviewer can open the session that made it. Nothing is installed unless you run it. Running it twice
changes nothing, and an amend does not add a second trailer. An existing hook is moved to
`prepare-commit-msg.botrbac-orig` and still runs first, with its exit status kept; botrbac's own part never
fails a commit. `botrbac trailer remove` takes the hook out and puts the old one back. The link opens only
for you; anyone who reads the commit sees the site's address and the session id.

## Commands

| Command | |
| --- | --- |
| `botrbac login [--server URL]` | Connect this computer (device code approved on the website; default `https://botrbac.com`) |
| `botrbac add-gateway --agent A` | Add the gateway to Cursor's, Codex's or Gemini CLI's config (others kept, backed up) |
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
| `botrbac trailer install [--repo P]` / `remove` | Opt-in git hook: `Botrbac-Session:` trailer on commits made in a session |
| `botrbac logout` | Forget this computer's login and key (disconnect it on the website too) |

Files live in `$BOTRBAC_HOME`, by default `~/.config/botrbac`: `credentials.json` (mode 0600),
`terminal_key.json` (the terminal's signing key, mode 0600), `policy.json`, `config.json`, `audit.db`, `sessions/` and `state.json`.

## Server side

| Endpoint | Auth | |
| --- | --- | --- |
| `GET /terminal/setup.md` | none | Setup steps for a coding agent, with this site's address |
| `GET /terminal/install.sh` | none | The install script, with this site's address |
| `POST /api/terminal/device` | none, rate-limited per address | Start a device login (RFC 8628) |
| `POST /api/terminal/token` | device code or refresh token | Tokens: `brt_at_…` (1 hour), `brt_rt_…` (90 days, rotated); optional `public_key` registers the terminal's signing key once |
| `GET /api/terminal/policy` | terminal access token | Role, roles, revoked sessions, version |
| `POST /api/terminal/audit` | terminal access token, plus a signature once the terminal has a key | Up to 500 rows; tools seen; unguarded servers |
| `GET /terminal/activity/export?format=csv\|jsonl\|otlp` | signed-in owner | Activity as CSV, JSON lines or OTLP/JSON logs |
| `POST /terminal/activity/webhook` | signed-in owner, CSRF | Set or remove the audit webhook (`url`, `include_commands`, `rotate`, `action=remove`) |

Terminal tokens work only on `/api/terminal/*`, and `/mcp` refuses them. Every key this feature writes
starts with `term:`; roles, terminals, tokens and revocations are signed like OAuth records. Each person
keeps their last 2000 terminal activity rows.

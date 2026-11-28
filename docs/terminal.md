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
sent later. Rows are chained as they are written (below), so rows deleted or changed on the computer while
it was offline show up as missing or altered once it syncs.

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

### Record integrity and retention

Each row in `audit.db` carries `seq` (1, 2, 3… per computer), `prev_hash` (the previous row's hash, 64
zeros for the first) and `row_hash`: SHA-256 over the row's canonical JSON (sorted keys, no whitespace,
UTF-8, like RFC 8785) without `row_hash`. The hash is taken last, after the sealed command and every other
field are in the row (`src/botrbac_cli/chain.py`). A queue from before this starts at row 1; its older rows
are sent as they were.

The site works each hash out again over exactly what the computer sent, and checks it against the last
row it accepted from that terminal. On **Terminal → Activity** a row that is not `ok` gets a badge:

- **rows missing before**: its seq jumps (`gap`). Rows were deleted on the computer, or have not been sent
  yet; a row that turns up later and links on both sides fills the gap.
- **altered record**: its seq was already used by another row, it does not link to the row before it, or
  its hash does not match its contents (`fork`).
- **unchained**: sent by an older botrbac.

The Terminals page says "record intact", or how many rows are missing or altered. A row sent twice is a
duplicate, not an alarm. Exports include `seq`, `chain` and `row_hash`. A computer that logs in again is a
new terminal on the site, and its chain carries on, so the Terminals page says which row it starts from.

After each batch the site answers with a **checkpoint** for that terminal, `{terminal_id, seq, row_hash,
ts}`, signed with the same key as the policy. The CLI keeps the newest in `state.json`. `botrbac verify`
walks the chain in `audit.db`, fetches the latest checkpoint (or uses the kept one with `--offline`),
checks its signature against the key pinned at login, and says whether the row the site signed is still
here, unchanged. It exits 1 if anything is wrong. **Terminal → Activity → Checkpoints** downloads every
terminal's checkpoint, with the site's public key, as JSON.

What this shows and what it doesn't. Deleting, reordering or editing rows on the computer breaks the
chain, and the site or `botrbac verify` notices. But code running as the computer's user can still write
new rows that never happened, with a valid chain, as long as it does so before they are sent: the chain
makes removal and changes detectable, not false rows. Once the site has a row, it is out of reach of the
computer. Rows deleted from the end of the queue before they were ever sent are noticed only by the next
row's gap (or not at all, if nothing follows). Anchoring checkpoints in a public transparency log such as
Sigstore Rekor, so that the site itself could not rewrite history unnoticed, is future work.

The site keeps rows for `TERMINAL_ACTIVITY_DAYS` (default 180) and at most `TERMINAL_ACTIVITY_MAX_ROWS`
per person (default 20,000), whichever comes first. Old rows are trimmed by when they arrived. The Activity
page shows the newest 2,000; exports stream everything kept.

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
(see [retention](#record-integrity-and-retention)).

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
| `botrbac verify [--offline]` | Check `audit.db`'s hash chain and the site's signed checkpoint |
| `botrbac logout` | Forget this computer's login (disconnect it on the website too) |

Files live in `$BOTRBAC_HOME`, by default `~/.config/botrbac`: `credentials.json` (mode 0600),
`policy.json`, `config.json`, `audit.db`, `sessions/` and `state.json`.

## Server side

| Endpoint | Auth | |
| --- | --- | --- |
| `GET /terminal/setup.md` | none | Setup steps for a coding agent, with this site's address |
| `GET /terminal/install.sh` | none | The install script, with this site's address |
| `POST /api/terminal/device` | none, rate-limited per address | Start a device login (RFC 8628) |
| `POST /api/terminal/token` | device code or refresh token | Tokens: `brt_at_…` (1 hour), `brt_rt_…` (90 days, rotated) |
| `GET /api/terminal/policy` | terminal access token | Role, roles, revoked sessions, version |
| `POST /api/terminal/audit` | terminal access token | Up to 500 rows; tools seen; unguarded servers. Answers with the terminal's signed `checkpoint` |
| `GET /api/terminal/checkpoint` | terminal access token | The terminal's latest signed checkpoint, or `null` |
| `GET /terminal/activity/checkpoints` | signed-in owner | Every terminal's checkpoint and chain state, as JSON |

Terminal tokens work only on `/api/terminal/*`, and `/mcp` refuses them. Every key this feature writes
starts with `term:`; roles, terminals, tokens and revocations are signed like OAuth records. Each person's
terminal activity is kept for `TERMINAL_ACTIVITY_DAYS` (180), at most `TERMINAL_ACTIVITY_MAX_ROWS` (20,000)
rows.

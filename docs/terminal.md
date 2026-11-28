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
  runs `botrbac login`, adds the gateway to that agent and runs `botrbac doctor`. It also adds that agent's
  hook (`botrbac hooks install <agent> --user --allow-unguarded`), so the agent's own shell and file edits
  follow the role as well; `--no-hook` leaves it out and `botrbac hooks remove <agent> --user` undoes it.
  A new computer starts as Read-only, so with the hook the agent can read but not edit or run commands
  until you give it a wider role. Before installing anything it prints what and from where. If this computer is already logged in to a
  different site, it logs in again to this one. It never uses sudo and can be run again. Read it first at the
  same address: `https://botrbac.com/terminal/install.sh`.
- **Paste into your agent:** `Set up Bot RBAC Terminal for me by following https://botrbac.com/terminal/setup.md`.
  The agent follows [terminal-agent-setup.md](terminal-agent-setup.md) (the same text the site serves).
- **Step by step:**
  1. `uv tool install git+https://github.com/parthit/botrbac` (or `pipx install git+…`).
  2. `botrbac login`. Open the link it prints, check the code matches, pick a role and approve. It connects
     to `https://botrbac.com` unless you give `--server URL` or set `BOTRBAC_SERVER`; the page shows the
     right command for the site you are on.
  3. `claude mcp add --scope user botrbac -- botrbac gateway` for Claude Code, or `botrbac add-gateway --agent cursor`
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
tools (see [hooks](#an-agents-own-tools-hooks)) use the agent's name: `claude-code/Bash`, `codex/Bash`, `cursor/Shell`.
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
- `--task "fix the flaky login test"` says what the session is for. It is recorded only sealed, with
  [Record commands](#record-commands) on, and shown on the session page.
- **Terminal → Activity** links each call to its session. The session page shows the tree of sessions
  started under it and lets you **revoke** it, which blocks it and everything under it the next time the
  terminal checks in (about a minute while online).

## An agent's own tools: hooks

The gateway sees MCP tools. An agent's built-in tools (shell, file edits, web fetch) never go through MCP,
so they are checked by the agent's pre-tool hook calling `botrbac check`:

```
botrbac hooks install claude-code          # this project's .claude/settings.json
botrbac hooks install claude-code --user   # every project
botrbac hooks install codex --user         # also gemini, cursor
```

This adds a `PreToolUse` hook that runs `botrbac check --agent claude-code --block-unguarded` before every
tool call. The call is checked as `claude-code/<Tool>`, so give roles the tools you want, such as
`claude-code/Read`, `claude-code/Edit` or `claude-code/*`. With `--block-unguarded`, MCP tools that do not
come through `botrbac gateway` are blocked; pass `--allow-unguarded` to check them as `<server>/<tool>`
instead.

Claude Code also gets `UserPromptSubmit`, `PostToolUse` and `PostToolUseFailure` hooks running the same command.
`botrbac check` reads `hook_event_name` from the payload: `PreToolUse` (or no event) is the check above;
the other three only record a row, always exit 0 and print nothing, so they never block or add text to
the conversation.

- **UserPromptSubmit** writes a `prompt` row: no tool, the prompt's id, and the prompt itself sealed
  (only with [Record commands](#record-commands) on).
- **PostToolUse** and **PostToolUseFailure** write a `result` row: the tool, the call's `tool_use_id`,
  `outcome` (`ok` or `error`), and the exit code, duration and result size in bytes when the agent sends
  them. Never the result itself.

Every hook row also keeps the agent's own ids, so the Activity page can tie a prompt to the calls it led
to and each call to its result (a row's prompt and agent-session links show only those rows, and exports
carry the ids): `agent_session_id` (the agent's session; Bot RBAC's own `session_id` is the
`botrbac run` session), `prompt_id`, `tool_use_id`, `agent_id`, `agent_type` and `parent_agent_id` (for
subagents), plus `permission_mode` and `cwd`. Codex's `turn_id` and Cursor's `conversation_id` and
`generation_id` are read too. At `PreToolUse` the row also gets the git checkout in `cwd`: `repo` (the
`origin` remote as `host/owner/name`, with any user name, token and scheme taken out), `branch` and `head`
(the commit). git gets about a second, the answer is cached for a few seconds in `git-cache.json`, and a
failure just leaves them out; it never changes the decision. `botrbac hooks remove` takes all four out.

Each install keeps the rest of the file, backs it up first (`<file>.botrbac-backup-<time>`), changes
nothing when run again, and refuses to touch a file it cannot parse. `botrbac hooks remove <agent>` takes
out only botrbac's entry. Without `--user` the file is the project's (`.codex/`, `.gemini/`, `.cursor/`).

| Agent | File (`--user`) | Event | Tools are checked as | Answer |
| --- | --- | --- | --- | --- |
| Claude Code | `~/.claude/settings.json` | `PreToolUse` | `claude-code/Bash`, `claude-code/Edit`, … | exit 2 blocks |
| Codex CLI | `~/.codex/hooks.json` | `PreToolUse` | `codex/Bash`, `codex/apply_patch`, … | exit 2 blocks |
| Gemini CLI | `~/.gemini/settings.json` | `BeforeTool` | `gemini/run_shell_command`, `gemini/write_file`, … | exit 2 blocks |
| Cursor | `~/.cursor/hooks.json` | `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile` | `cursor/Shell`, `cursor/Read`, MCP tools | JSON `permission` |

What each agent sends and needs, and how sure we are (formats checked November 2026; the comment at the
top of `src/botrbac_cli/agents.py` has the details):

- **Codex CLI** ([hooks docs](https://developers.openai.com/codex/hooks), and the hook engine in
  `openai/codex` under `codex-rs/hooks`). Same shape as Claude Code: `{"hooks": {"PreToolUse": [{"matcher":
  ".*", "hooks": [{"type": "command", "command": …}]}]}}`, the payload has `tool_name` (`Bash`,
  `apply_patch`, `mcp__<server>__<tool>`) and `tool_input`, and exit 2 with the reason on stderr blocks.
  **Codex skips a new or changed hook until you trust it**: run `/hooks` in Codex after installing.
  `[features] hooks = false` in `config.toml` switches hooks off; doctor reports that. Confident: read
  from Codex's source.
- **Gemini CLI** ([hooks reference](https://geminicli.com/docs/hooks/reference/)). A `BeforeTool` entry in
  `settings.json` with `matcher` `.*`, `name` `botrbac` and a 60 s `timeout`. MCP tools arrive as
  `mcp_<server>_<tool>` and are checked as `<server>/<tool>` (the name is split at the first `_` after
  `mcp_`, as Gemini does, so keep `_` out of server names). A call is left to the gateway only when the
  payload's `mcp_context` names the server exactly `botrbac`; without `mcp_context` such a call is blocked. Exit 2 blocks; **any other non-zero exit only
  warns and lets the tool run**, which is why every error in `botrbac check` exits 2. `hooksConfig.enabled:
  false`, or `botrbac` in `hooksConfig.disabled`, switches it off; doctor reports that. Confident: from
  Gemini's own docs.
- **Cursor** ([hooks docs](https://cursor.com/docs/hooks)). Cursor is closed source and its docs could not
  be fetched while this was written, so this follows its docs as quoted by third-party guides. Less sure.
  `{"version": 1, "hooks": {"beforeShellExecution": [{"command": …, "failClosed": true}], …}}`. The shell
  event sends `command` at the top level, checked as `cursor/Shell` (and `cmd/<program>`); the read event
  sends `file_path`, checked as `cursor/Read` (the file's content in the payload is never read or kept);
  the MCP event sends `tool_name`, `tool_input` as a JSON string, and the server's `url` or `command` but
  not its name, so the server is named after the url's host or the command's program (`npx -y
  @modelcontextprotocol/server-github` is `server-github`), and only a server whose command is the gateway's own
  (`botrbac gateway`) is treated as the gateway; one merely called `botrbac` is checked as
  `botrbac-upstream/<tool>`. Cursor reads the answer from stdout, `{"permission": "allow"}` or `{"permission": "deny",
  "user_message": …, "agent_message": …}`, so `botrbac check --agent cursor` always prints JSON and exits
  0. Cursor lets an action go ahead when a hook crashes unless the entry has `failClosed`, which the
  installer sets. If your Cursor version ignores `failClosed`, a missing botrbac lets calls through.

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
Code's `Bash`, Codex's `Bash` (and `shell`), Gemini CLI's `run_shell_command` and Cursor's `Shell`
(`SHELL_TOOLS` in `src/botrbac_cli/shellcmd.py`). A role with no `cmd/` patterns works exactly as before. `*` and `*/read*`
never count as `cmd/` patterns.

The command is read conservatively. It is split on `;`, `&&`, `||`, `|`, `&` and new lines; each part's
program is its first word after `VAR=value` assignments, and `/usr/bin/gh` counts as `gh`. A wrapper
(`sudo`, `env`, `time`, `nohup`, `xargs`, `command`, `exec`) must be allowed itself **and** so must the
program it runs: `sudo gh` needs `cmd/sudo` and `cmd/gh`. The call is **blocked** when the command uses
`$(…)`, backticks, `<(…)`, `>(…)`, `eval`, `bash -c`/`sh -c`, a `( … )` subshell, shell control flow
(`if`, `for`, `while`, `case`, `!` …), a variable as the program, or anything else it cannot read; the
reason says why. Also blocked: heredocs (`<<`, `<<-`; `<<<` is fine), ANSI-C and locale quoting (`$'…'`,
`$"…"`) and quotes inside `${…}`. A `#` at the start of a word starts a comment to the end of the line,
as in bash, and the lines after it are still checked. A number is a file descriptor only when it touches
the redirect (`2>f`); in `2 >f`, `2` is the program. An MCP server named `cmd` is checked as
`cmd-upstream/<tool>`, so it can never match `cmd/` patterns. The row's reason names programs only; the command itself is recorded
only with [Record commands](#record-commands) on, and then sealed.

This protects against the agent, not the computer's owner, and goes by name: a program that starts others
(`make`, `npm run`, `find -exec`, `timeout`, `nice`, git aliases, scripts) runs whatever it runs, so
allowing `cmd/timeout` allows anything `timeout` can start. Environment variables an allowed program
reads can make it run something else too (`GIT_PAGER=…`, `GIT_SSH_COMMAND=…`, `LD_PRELOAD=…`), so
`cmd/git` is a limit on names, not a sandbox.

For an agent botrbac does not set up, make its pre-tool hook run `botrbac check --agent <name>` with the
tool call as JSON on stdin (it reads `tool_name`, `toolName`, `tool` or `name`). Exit code 0 allows and 2 blocks, with
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
  (`.claude/settings.json`, `.claude/settings.local.json`), `~/.claude.json`, the other agents' hook and MCP
  files (`.codex/hooks.json`, `.codex/config.toml`, `.gemini/settings.json`, `.cursor/hooks.json`,
  `.cursor/mcp.json`) or botrbac's own folder is refused, as is one that mentions `disableAllHooks` or `botrbac hooks remove`. Paths are followed through
  symlinks and `..`. Reading those files is allowed, except botrbac's login file, which holds its tokens.
  Removing, moving or changing the folders that hold these files (`~/.claude`, `~/.codex`, `~/.gemini`,
  `~/.cursor`, the project's own, botrbac's folder) is refused too, as is `rm` or `mv` of your home or
  project folder. Globs, split quotes, `cd DIR && …` and `sh -c` are followed; looking (`ls`, `find`,
  `grep`) and `mkdir` stay allowed. This reads the call's text, so it is a speed bump: a path built at run
  time (variables, a script written elsewhere) gets past it.
- **Noticing.** `botrbac doctor` says when the hook is missing or switched off by `disableAllHooks` (or
  Codex's `[features] hooks = false`, Gemini's `hooksConfig`), and each sync tells the site, which marks the
  computer "hook off" on the Terminal page.
- **Coverage.** `botrbac doctor` also lists every agent it finds on the computer (its folder in your home,
  such as `~/.codex`, or its program on PATH) with whether its hook and gateway are in place, and the fix
  for each. Each sync sends a summary, `coverage`: `{"agents_detected": [...], "agents_hooked": [...],
  "hook_off": [...], "unguarded_servers": N}`. The Terminal page shows it per computer, for example
  "Coverage 2/3 agents hooked, 0 unguarded servers", and names the command that hooks the rest. It is
  what the computer says about itself: a hint for you, never used to allow anything.

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

Audit rows hold identifiers and decisions: the tool name, agent, role, session, and allow or block. Hook
rows add the agent's own ids (session, prompt, tool call, subagent), the permission mode, the working
folder and its git remote, branch and commit, and for a finished call its outcome, exit code, duration and
result size. These are stored in the clear, like the computer's name. Tool results and the contents of
files read are never recorded. Unless you turn on Record commands, neither is what was sent to a tool, nor
the prompt, nor a `--task`, and a session start records only the program's name.

Why an agent ran something comes only from what you gave it: the prompt it was answering (every call
carries that prompt's id) and the session's `--task`. What the model says about its own command, such as
the one-line `description` Claude Code's Bash tool carries, is never kept. A model can write anything
there, so it would read like evidence without being any.

### Record commands

Turn it on under **Terminal → Activity** to see the exact command each agent ran, secrets included: a
shell tool's command line, another tool's input (for Write, the file it wrote), the MCP arguments the
gateway passed on, and the whole `botrbac run` command line. Blocked calls are recorded too. Each one is
cut at 8,000 characters. It is off until you turn it on, and applies to all your terminals.

With it on, rows also carry:

- the **prompt** you typed, on the `prompt` row (UserPromptSubmit);
- the **task** given with `botrbac run --task "…"`, on the session's start row and its session page;
- `input_digest` (`sha256:<hex>`) and `input_size` (bytes) of the whole command or tool input, taken
  before the 8,000-character cut, so a long input can be matched against a copy you have.

The prompt and the task are sealed like the command and bound to their row, so neither can be moved
onto another row. The prompt travels in its `prompt` row's command field (that row has no other
command); the task is also bound to its field name. Without Record commands none of
them is sent.

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
a key (an older botrbac) is still accepted, and its rows are marked unsigned: until it has a key, anyone
holding its token can send rows as it. The key is registered once, so whoever offers one first wins. A
key added at a token refresh rather than at login is marked "key added at refresh" on the Terminals page
and written to the site's audit log; if that computer was not updated around then, a stolen refresh token
may have added it, so disconnect the terminal and connect it again.

The site sets these on every row it stores, whatever the computer sent:

- `signed`: whether the batch carried a good signature from the terminal's key.
- `subject`: you, the account's email.
- `actor`: who acted for you, shaped like RFC 8693's `act` claim:
  `{"sub": "terminal:t_…", "act": {"sub": "agent:claude-code/<agent id>"}}`.
- `grant`: the role the site has assigned to the terminal and its current policy version when the batch
  arrived (`role`, `policy_version`), plus what the computer says it decided under (`reported_role`,
  `reported_policy_version`). The reported ones are the computer's claim: a session narrowed with `--role`,
  or a policy cached while offline, legitimately differs; a computer that lies can write anything there.

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
2-second timeout, inside the upload; a failure never fails the upload and shows on the page as the last
delivery. **A row that is not delivered is never sent again**, so treat the webhook as a live feed and the
exports as the record. After 5 failures in a row, delivery pauses for 15 minutes (rows in that time are not
sent), so a dead receiver does not slow every upload; saving the webhook again ends the pause. The address must be https on port 443, with no user, query or fragment, and a name that resolves
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
| `botrbac servers add/remove/list [--url U]` | The MCP servers the gateway sits in front of |
| `botrbac gateway [--agent NAME]` | The MCP server your agent starts |
| `botrbac wrap <agent> [--user] [--file F] [--dry-run]` | Move an agent's MCP servers behind the gateway |
| `botrbac doctor` | Login, policy age, each agent's hook and gateway, servers that bypass Bot RBAC |
| `botrbac run --role R [--task T] [--agent A] -- cmd …` | Run a command in a narrower session |
| `botrbac shell-init` | Shell functions for `<agent> --botrbac --role R` |
| `botrbac hooks install A [--user] [--allow-unguarded]` | Check the agent's own tools too: `claude-code`, `codex`, `gemini`, `cursor` |
| `botrbac hooks remove A [--user]` | Take botrbac's hook out of that agent's file (others kept, backed up) |
| `botrbac check --agent A [--tool T] [--format json] [--block-unguarded]` | The hook adapter (reads the tool call on stdin) |
| `botrbac sync [--retry-rejected]` / `botrbac log [-n N]` | Send waiting rows now (`--retry-rejected` also resends rows the site refused) / show the last N rows (20) |
| `botrbac verify [--offline]` | Check `audit.db`'s hash chain and the site's signed checkpoint |
| `botrbac trailer install [--repo P] [--site URL]` / `remove` | Opt-in git hook: `Botrbac-Session:` trailer on commits made in a session |
| `botrbac logout` | Forget this computer's login and key (disconnect it on the website too) |

Files live in `$BOTRBAC_HOME`, by default `~/.config/botrbac`: `credentials.json` (mode 0600),
`terminal_key.json` (the terminal's signing key, mode 0600), `policy.json`, `config.json`, `audit.db`,
`sessions/`, `state.json` and `git-cache.json`.

## Server side

| Endpoint | Auth | |
| --- | --- | --- |
| `GET /terminal/setup.md` | none | Setup steps for a coding agent, with this site's address |
| `GET /terminal/install.sh` | none | The install script, with this site's address |
| `POST /api/terminal/device` | none, rate-limited per address | Start a device login (RFC 8628) |
| `POST /api/terminal/token` | device code or refresh token | Tokens: `brt_at_…` (1 hour), `brt_rt_…` (90 days, rotated); optional `public_key` registers the terminal's signing key once |
| `GET /api/terminal/policy` | terminal access token | Role, roles, revoked sessions, version |
| `POST /api/terminal/audit` | terminal access token, plus a signature once the terminal has a key | Up to 500 rows; tools seen; unguarded servers. Answers with the terminal's signed `checkpoint` |
| `GET /api/terminal/checkpoint` | terminal access token | The terminal's latest signed checkpoint, or `null` |
| `GET /terminal/activity/checkpoints` | signed-in owner | Every terminal's checkpoint and chain state, as JSON |
| `GET /terminal/activity/export?format=csv\|jsonl\|otlp` | signed-in owner | Activity as CSV, JSON lines or OTLP/JSON logs |
| `POST /terminal/activity/webhook` | signed-in owner, CSRF | Set or remove the audit webhook (`url`, `include_commands`, `rotate`, `action=remove`) |

Terminal tokens work only on `/api/terminal/*`, and `/mcp` refuses them. Every key this feature writes
starts with `term:`; roles, terminals, tokens and revocations are signed like OAuth records. Each person's
terminal activity is kept for `TERMINAL_ACTIVITY_DAYS` (180), at most `TERMINAL_ACTIVITY_MAX_ROWS` (20,000)
rows.

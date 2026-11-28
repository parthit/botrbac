# Set up Bot RBAC Terminal (instructions for a coding agent)

You are setting up Bot RBAC Terminal for the person you are working with. If botrbac is already
installed here (`botrbac --version` works), skip to [Already set up](#already-set-up-check-or-update). Bot RBAC Terminal lets them
decide, on the website {{ server }}, which tools the AI agents on this computer may use. You will
install the `botrbac` command, connect this computer to their account, and add `botrbac gateway` to
your own MCP configuration. The person only has to approve one login code in their browser.

## What this is (read first, and explain it to the person in these terms)

```
agent (you) ──tool call──► botrbac on this computer ──checks the role──► runs the tool, or blocks it
```

- **Terminal**: this computer, once it is connected to the person's account.
- **Role**: a list of allowed tools, such as `claude-code/Edit`, `github/get_*` or `cmd/git`. Anything not
  on the list is blocked. Each computer has exactly one role, chosen on {{ server }}/terminal in the
  **Role** column (pick, then **Change**). That is the only place a role is tied to a computer.
- **Built-in roles**: **Read-only** (look, don't change; every new computer starts here), **Full access**
  (nothing blocked) and **No tools** (pause). The person can make their own on {{ server }}/terminal/roles,
  starting from a template such as *Coding* or *Reviewer*.
- **Activity** ({{ server }}/terminal/activity): every call, allowed or blocked, with the exact tool name.
- **Unguarded server**: an MCP server the agent talks to directly, not through botrbac, so the role does
  not cover it. `botrbac doctor` lists them and prints the fix.
- **`--role`**: `botrbac run --role NAME -- claude` limits one session further. It can only narrow the
  computer's role, never widen it.

The goal state: every computer on a role that fits its work (not Full access), and no unguarded servers.

Rules:

- **Never print, log or paste tokens.** `botrbac login` stores its tokens in
  `~/.config/botrbac/credentials.json`; do not read that file out.
- **Never edit or delete the person's existing MCP servers without asking.** Add the `botrbac` entry
  next to them.
- **Back up every config file before you change it:** `cp FILE FILE.botrbac-backup-$(date +%s)`, and tell
  the person where the backup is.
- Run each command yourself. Stop and ask the person only where a step below says so.

## 1. Install botrbac

Check what is available, then install with the first that works:

```sh
uv --version && uv tool install git+https://github.com/parthit/botrbac
# or, without uv:
pipx --version && pipx install git+https://github.com/parthit/botrbac
```

If neither `uv` nor `pipx` is installed, ask the person whether to install uv with Astral's installer
(`curl -LsSf https://astral.sh/uv/install.sh | sh`, into `~/.local/bin`, no sudo), then open a new shell
or use `~/.local/bin/uv`. (The one-line installer at {{ server }}/terminal/install.sh, which the person
runs themselves, does this step without asking, after printing what it installs and from where.)

Check it worked: `botrbac --version`. If the command is not found, run `uv tool update-shell` (or
`pipx ensurepath`) and use the full path, usually `~/.local/bin/botrbac`. Note the full path for step 3:

```sh
command -v botrbac
```

## 2. Log in (the person approves one code)

```sh
{{ login }}
```

It prints, each on its own line:

```
Link: {{ server }}/device?code=ABCD-EFGH
Code: ABCD-EFGH
Waiting for approval…
```

Tell the person, with the link and code from the output: **"Open this link and approve the code
ABCD-EFGH."** That is the only thing they do. Leave the command running until it ends; it waits up to
10 minutes. Success is a last line like `Logged in as person@example.com, role Read-only` and exit
code 0.

## 3. Add the gateway to the agent's MCP configuration

Use the full path from `command -v botrbac` as the command if `botrbac` might not be on the agent's
PATH (an agent started from a desktop app often has a shorter PATH than your shell). Do only the section
for the agent you are, unless the person asks for more.

### Claude Code

```sh
claude mcp add --scope user botrbac -- "$(command -v botrbac)" --home "${BOTRBAC_HOME:-$HOME/.config/botrbac}" gateway
```

`--scope user` adds it for every project, and `--home` names botrbac's folder, as the install script
does. If `claude mcp add --help` does not list `--scope` (an old Claude Code), leave `--scope user` out.
If Claude Code already has a server called `botrbac`, leave it and let step 4 (`botrbac doctor`) say
whether it needs updating. Check with `claude mcp list`.

Every agent also gets a hook so its own shell and file edits follow the role. Add it in step 6, last:
once it is in place and the role is Read-only, your own shell commands are blocked.

### Cursor, Codex or Gemini CLI

```sh
botrbac add-gateway --agent cursor    # ~/.cursor/mcp.json
botrbac add-gateway --agent codex     # ~/.codex/config.toml
botrbac add-gateway --agent gemini    # ~/.gemini/settings.json
```

It adds the `botrbac` entry and keeps every other server, backs the file up first
(`<file>.botrbac-backup-<time>`; tell the person where), and changes nothing when the entry is already
there and current. Add `--dry-run` to see what it would do. If it says the file is not valid JSON or TOML,
do not edit the file yourself: show the person the error and ask.

## 4. Check it

```sh
botrbac status
botrbac doctor
```

Good output:

- `status` shows `Account:` with the person's email, `Role:` with a role name, and `Policy: … online`.
- `doctor` starts with `✓ logged in to {{ server }}` and `✓ policy is 0.0 days old`.
- `! no servers yet` is fine: no MCP servers sit behind the gateway yet (see step 7).
- Any other line followed by `fix: …` (for example "the botrbac hook in … is from an older botrbac"):
  run that `fix:` command. Those are safe to run without asking, except `botrbac wrap` (below).
- A line `✗ <agent>: <name> in <file> is not behind botrbac` means that MCP server is used directly,
  without Bot RBAC (the website shows it as an **unguarded server**). Tell the person which ones, and
  offer to move them with the `fix:` command `doctor` prints below that line, usually
  `botrbac wrap claude-code --user`. Run it with `--dry-run` first, show the result, and run it for real
  only if they agree.

## 5. Tell the person what to do next

Say this, in your own words, with their real links:

1. This computer is now listed on {{ server }}/terminal with the role **Read-only**.
2. To let agents edit files and run commands, open {{ server }}/terminal/roles/new, pick a template
   (**Coding** is a good start), save it, then on {{ server }}/terminal choose it in the **Role** column and
   press **Change**. **Full access** also works, but blocks nothing.
3. Restart the agent (or open a new session) so it loads the `botrbac` MCP server and the hook.
4. When something is blocked, {{ server }}/terminal/activity shows the exact tool name to add to the role.

## 6. Add the hook (last)

So your own tools (your shell, file edits, web fetch) follow the role too. Without it, Bot RBAC only sees
MCP tools, and `cmd/gh`-style rules have no effect. Use the line for the agent you are:

```sh
botrbac hooks install claude-code --user --allow-unguarded   # Claude Code: ~/.claude/settings.json
botrbac hooks install codex --user --allow-unguarded         # Codex CLI: ~/.codex/hooks.json
botrbac hooks install gemini --user --allow-unguarded        # Gemini CLI: ~/.gemini/settings.json
botrbac hooks install cursor --user --allow-unguarded        # Cursor: ~/.cursor/hooks.json
```

Run this as your last command: from now on, a role without your shell tool (`claude-code/Bash`,
`codex/Bash`, `gemini/run_shell_command`, `cursor/Shell`) blocks your shell, and Read-only does. Codex
runs a new hook only after the person trusts it: tell them to run `/hooks` in Codex. Cursor and Gemini
CLI load it when restarted. Undo it with `botrbac hooks remove <agent> --user` (the person runs that
themselves; the hook refuses it from an agent). Skip this step only if the person says so.

## 7. Optional extras: only if the person asks

- **Put existing MCP servers behind Bot RBAC** (so their tools follow the role):
  `botrbac servers add NAME -- <the server's command and arguments>` for each one the person names, or
  `botrbac wrap claude-code` (also `cursor`, `gemini`, `codex`), which moves every server in that file
  and keeps a `.botrbac-backup-<time>` copy. Run with `--dry-run` first and show the person the result.
- **Limit shell commands such as gh:** with the hook installed, a role can list programs with
  `cmd/<program>` patterns, for example `cmd/gh` and `cmd/git`. The person edits roles on
  {{ server }}/terminal/roles.
- **Narrower roles for one run:** `botrbac run --role NAME -- claude`, or add
  `eval "$(botrbac shell-init)"` to the shell's startup file (ask first) so `claude --botrbac --role NAME`
  works.

## Already set up: check or update

When botrbac is already installed (the person asks you to check it, something seems off, or they
updated botrbac):

1. Update it if they ask: `uv tool upgrade botrbac` (or `pipx upgrade botrbac`).
2. `botrbac status`: which account and site, the role, and how many rows are waiting to be sent.
3. `botrbac doctor`: run each `fix:` command it prints (ask first only for `botrbac wrap`). After an
   update it usually asks to run `botrbac hooks install <agent> --user --allow-unguarded` and
   `botrbac add-gateway --agent <agent>` again, so their entries match the new version.
4. Run `botrbac doctor` again until it has no `✗` lines, then tell the person to restart the agent.

If `status` shows a different site than {{ server }}, run `{{ login }}` to connect this computer
to {{ server }} instead.

## Troubleshooting

| Problem | What to do |
| --- | --- |
| No `uv` or `pipx` | Ask the person, then install uv: `curl -LsSf https://astral.sh/uv/install.sh \| sh`. |
| `The code expired before it was approved` | Run `{{ login }}` again and give the person the new link. |
| `Login refused on the website` | The person pressed Refuse. Ask whether to try again. |
| `This terminal was disconnected on the website` | Run `{{ login }}` again. |
| Bot RBAC tools do not show in the agent | Restart the agent. Check `claude mcp list` or the config file, and that the command path works. |
| `botrbac: command not found` in the agent | Use the full path from `command -v botrbac` in the config. |
| A tool call fails with `Blocked by Bot RBAC: …` | Working as intended: the role does not allow that tool. Do not try to get around it. Tell the person the exact pattern the error names (such as `claude-code/Bash` or `cmd/npm`) and that they can add it to the role on {{ server }}/terminal/roles, or give this computer another role on {{ server }}/terminal. |
| `Blocked by Bot RBAC: … a role this run was narrowed to with botrbac run --role` | The computer's role allows the tool; the `--role` this run was started with does not. Changing the computer's role will not help. Tell the person the role and pattern the error names: they start the run again with a wider `--role`, or add the pattern to that role. |
| `Blocked by Bot RBAC: not logged in …`, `… offline for more than …`, `… this session was revoked …`, ending "Every tool is blocked until that is fixed" | Not about the role. Tell the person what the message says (`{{ login }}`, `botrbac sync`, a new run); do not ask for a wider role. |
| `Blocked by Bot RBAC: … does not go through the botrbac gateway` | That MCP server is unguarded. You may not change the agent's MCP settings yourself: ask the person to run the `fix:` command `botrbac doctor` prints. |
| `Blocked by Bot RBAC: … botrbac does not run commands that use …`, `… could not read this command`, `… does not read $'…'` and similar | The role has `cmd/` rules, so each program in a shell command must be readable. Run simpler commands: one program per command or joined with `&&`/`\|`, no `$(…)`, backticks, heredocs or `bash -c`. No role change is needed. The message lists the programs the shell may run ("The shell here runs only: …"); each one in the command, `cd` included, must be on that list. Write files with your file-editing tool instead of `cat <<EOF`. |
| `Blocked by Bot RBAC: … which Bot RBAC protects` | You tried to change an agent's settings or botrbac's own files. Tell the person what you wanted to change; they make that change themselves. |
| `status` shows rows waiting that do not go down | Run `botrbac sync`. `Offline: … (… row_budget_exceeded …)` means this computer sent its rows for today; they go out by themselves tomorrow. `busy` means another upload was running: try again in a minute. `This terminal was disconnected` means: run `{{ login }}` again. |
| A command `botrbac` printed refers to `--home` | That is botrbac's folder, normally `~/.config/botrbac`. Keep it in commands as printed. |
| The website shows "unguarded servers" | Run `botrbac doctor`; it names each one and the `fix:` command. Ask before running it. |

Full documentation: https://github.com/parthit/botrbac/blob/main/docs/terminal.md

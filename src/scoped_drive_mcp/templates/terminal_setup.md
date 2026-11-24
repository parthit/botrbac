# Set up Bot RBAC Terminal (instructions for a coding agent)

You are setting up Bot RBAC Terminal for the person you are working with. Bot RBAC Terminal lets them
decide, on the website {{ server }}, which tools the AI agents on this computer may use. You will
install the `botrbac` command, connect this computer to their account, and add `botrbac gateway` to
your own MCP configuration. The person only has to approve one login code in their browser.

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

If neither `uv` nor `pipx` is installed, ask the person whether to install uv
(`curl -LsSf https://astral.sh/uv/install.sh | sh`), then open a new shell or use `~/.local/bin/uv`.

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
claude mcp add botrbac -- botrbac gateway
```

To add it for every project rather than this one, check that `claude mcp add --help` lists `--scope`,
then use `claude mcp add --scope user botrbac -- botrbac gateway`. Check with
`claude mcp list`.

### Cursor: `~/.cursor/mcp.json`

Merge this entry into the `mcpServers` object. If the file does not exist, create it with exactly this:

```json
{
  "mcpServers": {
    "botrbac": { "command": "botrbac", "args": ["gateway", "--agent", "cursor"] }
  }
}
```

### Codex: `~/.codex/config.toml`

Append this table, unless `[mcp_servers.botrbac]` is already there:

```toml
[mcp_servers.botrbac]
command = "botrbac"
args = ["gateway", "--agent", "codex"]
```

### Gemini CLI: `~/.gemini/settings.json`

Merge this entry into the `mcpServers` object (create the object if it is missing):

```json
{
  "mcpServers": {
    "botrbac": { "command": "botrbac", "args": ["gateway", "--agent", "gemini"] }
  }
}
```

### Merging into an existing JSON file

Read the file, parse it, add `mcpServers.botrbac` and write it back with every other key unchanged.
For example:

```sh
python3 - "$HOME/.cursor/mcp.json" cursor <<'EOF'
import json, pathlib, sys
path, agent = pathlib.Path(sys.argv[1]), sys.argv[2]
data = json.loads(path.read_text()) if path.exists() else {}
data.setdefault("mcpServers", {})["botrbac"] = {"command": "botrbac", "args": ["gateway", "--agent", agent]}
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(data, indent=2) + "\n")
EOF
```

If the file is not valid JSON, do not overwrite it: show the person the error and ask.

## 4. Check it

```sh
botrbac status
botrbac doctor
```

Good output:

- `status` shows `Account:` with the person's email, `Role:` with a role name, and `Policy: … online`.
- `doctor` starts with `✓ logged in to {{ server }}` and `✓ policy is 0.0 days old`.
- `! no servers yet` is fine: no MCP servers sit behind the gateway yet (see step 6).
- A line `✗ <agent>: <name> in <file> is not behind botrbac` means that MCP server is used directly,
  without Bot RBAC. That is expected for servers the person has not asked to move; mention it to them.

## 5. Restart the agent

Tell the person they may need to restart the agent (or open a new session) so it loads the new
`botrbac` MCP server. Then the computer is listed on {{ server }}/terminal, where they can change its
role at any time.

## 6. Optional extras: only if the person asks

- **Put existing MCP servers behind Bot RBAC** (so their tools follow the role):
  `botrbac servers add NAME -- <the server's command and arguments>` for each one the person names, or
  `botrbac wrap claude-code` (also `cursor`, `gemini`, `codex`), which moves every server in that file
  and keeps a `.botrbac-backup-<time>` copy. Run with `--dry-run` first and show the person the result.
- **Check the agent's own tools too** (shell, file edits): `botrbac hooks install claude-code`
  (this project) or `botrbac hooks install claude-code --user` (every project). The role then needs
  patterns such as `claude-code/Read` or `claude-code/*`.
- **Limit shell commands such as gh:** with the hook installed, a role can list programs with
  `cmd/<program>` patterns, for example `cmd/gh` and `cmd/git`. The person edits roles on
  {{ server }}/terminal/roles.
- **Narrower roles for one run:** `botrbac run --role NAME -- claude`, or add
  `eval "$(botrbac shell-init)"` to the shell's startup file (ask first) so `claude --botrbac --role NAME`
  works.

## Troubleshooting

| Problem | What to do |
| --- | --- |
| No `uv` or `pipx` | Ask the person, then install uv: `curl -LsSf https://astral.sh/uv/install.sh \| sh`. |
| `The code expired before it was approved` | Run `{{ login }}` again and give the person the new link. |
| `Login refused on the website` | The person pressed Refuse. Ask whether to try again. |
| `This terminal was disconnected on the website` | Run `{{ login }}` again. |
| Bot RBAC tools do not show in the agent | Restart the agent. Check `claude mcp list` or the config file, and that the command path works. |
| `botrbac: command not found` in the agent | Use the full path from `command -v botrbac` in the config. |

Full documentation: https://github.com/parthit/botrbac/blob/main/docs/terminal.md

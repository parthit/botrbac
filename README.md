# Bot RBAC

**Give an AI assistant the Google Drive files you pick, and nothing else.**

When you connect Claude, ChatGPT or Grok to Google Drive, the assistant can usually reach your whole Drive.
Bot RBAC sits in between as an MCP server. You tick the files and folders an assistant may use, and every
call is checked against that list before anything is sent to Google. Everything else is refused, with an
approval link for you instead.

**Use it:** [botrbac.com](https://botrbac.com) (hosted) · **Run your own:** [one Vercel function](#run-your-own-copy),
or [let your coding agent set it up](docs/agent-setup.md) · MIT licensed

```
Assistant ──▶ Bot RBAC /mcp ──▶ role check ──▶ allowlist check ──▶ Google Drive (as you)
                                     │                │
                               wrong role?      not on your list?
                                 refused        refused, with an approval link for you
```

## What you get

- **A list you control.** Allow a file or a folder (a folder includes what is inside it). Untick it and the
  next call is refused within about 2 seconds.
- **Approval links.** When an assistant asks for something not on the list, it gets a link to show you.
  You approve or deny it in the dashboard.
- **A role for each app.** Read only, read and edit, or full. An app only sees the tools its role allows.
  There are no tools to move, share or permanently delete files.
- **Named roles for agents and subagents.** A role is a named part of your list with its own level. An agent
  that connects to `/mcp/role/<role>` reaches only that role's files. See [docs/roles.md](docs/roles.md).
- **An activity log.** Every call, grant, revoke and refusal, without file contents.
- **Sharing with people you pair with.** Their assistants can read the items you put on a separate Sharing
  list, and edit only where you say so.
- **Works with any MCP client** that does OAuth: Claude, ChatGPT, Grok, Cursor and Muse connect to one URL.
- **Terminal: roles for agents on your own computers.** The `botrbac` CLI puts Claude Code, Codex, Cursor or
  Gemini CLI behind roles you define on the website, works offline and syncs its audit log when it can.
  `claude --botrbac --role reviewer` starts an agent with a narrower role that its subagents inherit.
  See [docs/terminal.md](docs/terminal.md); a coding agent can set it up from
  [docs/terminal-agent-setup.md](docs/terminal-agent-setup.md).

## Get started (hosted)

1. Open [botrbac.com](https://botrbac.com) and **sign in with Google** (this asks only for your email).
2. **Connect Google Drive** (a second, separate Google permission screen).
3. On **Files**, click **Add from Google Drive** and pick files or folders in Google's window. Only what
   you pick is ever opened to Bot RBAC.
4. Add `https://botrbac.com/mcp` to your assistant as a custom connector, sign in when the browser opens,
   and choose what the app may do.
   - **Claude:** Settings → Connectors → Add custom connector.
   - **ChatGPT:** turn on developer mode, then Settings → Apps → Create, and choose OAuth.
   - **Grok Bot:** say "Add this MCP server: https://botrbac.com/mcp" in the chat.
   - **Cursor / Muse:** add a remote MCP server / custom connector with that URL.
5. Ask the assistant to list your allowed files. Then ask for a file you did not allow: it should come back
   with an approval link instead of the content.

If the assistant has its own built-in Google Drive connector, disconnect it, or it can go around Bot RBAC.

## Run your own copy

The hosted version holds an encrypted Google token for your Drive. If you'd rather hold it yourself, run
your own copy: one Python function on Vercel's free plan, plus Upstash Redis or Postgres.

**With a coding agent (easiest).** Paste this into Claude Code, Cursor, Codex or similar:

```text
Set up my own self-hosted copy of Bot RBAC (https://github.com/parthit/botrbac) on Vercel.
Follow docs/agent-setup.md in that repo, section "Instructions for the agent", step by step.
My fork is: <https://github.com/YOUR-USERNAME/botrbac, or "please fork it for me">
My Google address (OWNER_EMAIL): <you@example.com>
```

The agent installs, tests, generates secrets and deploys. It stops to tell you what to click in Google
Cloud and Vercel. More prompts (including a local-only one) are in [docs/agent-setup.md](docs/agent-setup.md).

**By hand.** About 30 minutes: create a Google OAuth client and a file-picker key, deploy to Vercel,
connect Upstash, set eight environment variables. Step by step: [docs/self-hosting.md](docs/self-hosting.md).

**On your computer.** You need [uv](https://docs.astral.sh/uv/) and a Google OAuth client with
`http://localhost:8000/auth/callback` as a redirect URI:

```bash
git clone https://github.com/parthit/botrbac && cd botrbac
uv sync
cp .env.example .env                       # fill in the Google client, OWNER_EMAIL and
uv run python scripts/make_secrets.py      # these two secrets
uv run --env-file .env uvicorn api.index:app --reload --port 8000
```

Open <http://localhost:8000>. Locally the data is kept in memory. See
[Run it on your computer](docs/self-hosting.md#run-it-on-your-computer) for connecting MCP Inspector or a
tunnel. The test suite needs no Google account: `uv run pytest`.

## What to know before you trust it

- **Google keeps the rest of your Drive closed.** Bot RBAC asks Google only for the files you pick in
  Google's own file picker (`drive.file`). Google enforces that, so a bug in this server, a leaked token, or
  the person running it can't reach the rest of your Drive. The allowlist is a second check on top: an
  assistant only gets the picked items you allowed, with the role you gave it.
- **Picked files are reachable by the server.** They are read with an encrypted refresh token held by
  whoever runs the server. **Run your own copy** if you'd rather hold that token yourself (above).
- **Documents are untrusted input.** A file can contain text written to steer an assistant. Give an app
  **Read only** unless it needs to write.

The full list is in [docs/security.md](docs/security.md). Found a vulnerability? See [SECURITY.md](SECURITY.md).

## Documentation

| | |
| --- | --- |
| [docs/self-hosting.md](docs/self-hosting.md) | Deploy your own copy, run it locally, every environment variable, troubleshooting |
| [docs/agent-setup.md](docs/agent-setup.md) | Copy-paste prompts so a coding agent sets it up for you |
| [docs/tools.md](docs/tools.md) | Every tool, which role may call it, and how files are read |
| [docs/roles.md](docs/roles.md) | Named roles: give an agent or subagent only part of your allowed list |
| [docs/notion.md](docs/notion.md) | Optional: let assistants read the Notion pages you allow |
| [docs/onedrive.md](docs/onedrive.md) | Optional: let assistants read the OneDrive files and folders you allow |
| [docs/terminal.md](docs/terminal.md) | Bot RBAC Terminal: the `botrbac` CLI, roles for local agents, `--role` sessions, hooks |
| [docs/sharing.md](docs/sharing.md) | Pairing assistants, the mailbox between your own assistants, sharing with other people |
| [docs/security.md](docs/security.md) | Security notes and how the allowlist check works |
| [docs/google-verification.md](docs/google-verification.md) | Google OAuth verification for a public deployment |
| [docs/development.md](docs/development.md) | Project layout and implementation notes |

Google Drive is the first connection. More services are planned.

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Licensed under the
[MIT License](LICENSE).

# Bot RBAC

**Give an AI assistant the files you pick in your Google Drive, and nothing else.**

When you connect Grok, Claude or ChatGPT to Google Drive, the assistant can usually reach the whole Drive.
Bot RBAC sits in between. You tick the files and folders an assistant may use, and every call is checked
against that list before anything is sent to Google. Everything else is refused.

Try the hosted version at **[botrbac.com](https://botrbac.com)**, or [run your own](docs/self-hosting.md)
on Vercel's free plan.

```
Assistant ──▶ Bot RBAC /mcp ──▶ role check ──▶ allowlist check ──▶ Google Drive (as you)
                                     │                │
                               wrong role?      not on your list?
                                 refused        refused, with an approval link for you
```

## What you get

- **A list you control.** Allow a file or a folder (a folder includes what is inside it). Untick it and the
  next call stops, within about 2 seconds.
- **Approval links.** When an assistant asks for something that is not on the list, it gets a link to show
  you. You approve or deny it in the dashboard.
- **A role for each app.** Read only, read and edit, or full. An app only sees the tools its role allows.
  There are no tools to move, share or permanently delete files.
- **Named roles for agents and subagents.** A role is a named part of your list with its own level. An agent
  that connects to `/mcp/role/<role>` reaches only that role's files. See [docs/roles.md](docs/roles.md).
- **An activity log.** Every call, grant, revoke and refusal, without file contents.
- **Sharing with people you pair with.** Their assistants can read the items you put on a separate Sharing
  list, and edit only where you say so. Their assistants can never message yours.
- **Works with any MCP client.** Grok, Claude, ChatGPT, Muse and Cursor connect to one address with OAuth.

## Get started (hosted)

1. Open [botrbac.com](https://botrbac.com) and **sign in with Google**. This asks only for your email.
2. **Connect Google Drive.** This is a second, separate Google permission screen.
3. On **Browse**, click **Allow** next to a file or folder.
4. Add `https://botrbac.com/mcp` to your assistant as a custom connector (MCP server), sign in when the
   browser opens, and choose what the app may do.
   - **Grok Bot:** say "Add this MCP server: https://botrbac.com/mcp" in the chat.
   - **Claude:** Settings → Connectors → Add custom connector.
   - **ChatGPT:** turn on developer mode, then Settings → Apps → Create, and choose OAuth.
   - **Muse:** add a custom connector.
5. Ask the assistant to list your allowed files. Then ask for a file you did not allow: it should come back
   with an approval link instead of the content.

If the assistant has its own built-in Google Drive connector, disconnect that one, or it can go around
Bot RBAC.

## What to know before you trust it

- **The allowlist is the only wall.** Connecting Drive gives this server Google's full Drive permission for
  your account, stored as an encrypted refresh token. The assistant is held to your list by this server's
  check on every call, not by Google. A bug in the server, or a leaked `ENCRYPTION_KEY` plus access to the
  store, could expose more of that Drive than the list you ticked.
- **Run your own copy** if you would rather hold that token yourself. It is one Python function on Vercel
  with Upstash Redis or Postgres. See [docs/self-hosting.md](docs/self-hosting.md).
- **Documents are untrusted input.** A file can contain text written to steer an assistant. Give an app
  **Read only** unless it needs to write.

The full list is in [docs/security.md](docs/security.md).

## Documentation

| | |
| --- | --- |
| [docs/self-hosting.md](docs/self-hosting.md) | Deploy your own copy: Google Cloud, Vercel, environment variables, connecting each assistant, testing |
| [docs/tools.md](docs/tools.md) | Every tool, which role may call it, and how files are read |
| [docs/roles.md](docs/roles.md) | Named roles: give an agent or subagent only part of your allowed list |
| [docs/sharing.md](docs/sharing.md) | Pairing assistants, the mailbox between your own assistants, sharing with other people, wake-ups |
| [docs/security.md](docs/security.md) | Security notes and how the allowlist check works |
| [docs/google-verification.md](docs/google-verification.md) | Google OAuth verification steps for a public deployment |
| [docs/development.md](docs/development.md) | Project layout and implementation notes |
| [docs/PLAN.md](docs/PLAN.md) | Original design notes |

Google Drive is the first connection. More services are planned, and each one is added as its own
connection without changing how people sign in.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, tests and pull requests. Licensed under the
[MIT License](LICENSE).

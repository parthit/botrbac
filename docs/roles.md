# Named roles

A connected assistant reaches everything on your allowed list, at the level you gave it (read only, read and
edit, or full). A **named role** is narrower: a named part of that list with its own level. You make roles in
**Settings → Roles** and an agent uses one by connecting to the role's address:

```
https://botrbac.com/mcp/role/<role>
```

The role's address is the normal `/mcp` endpoint with one more check in front of it. Sign-in, tokens and the
tools work the same way.

## What a role changes

| | Plain `/mcp` | `/mcp/role/<role>` |
| --- | --- | --- |
| Files | Everything on your allowed list | Only the allowed items the role lists (a folder covers what is inside) |
| Level | The connection's level | The lower of the connection's level and the role's |
| Tools | All tools for that level | Only the tools for your own Drive files |
| Out-of-scope file | `access_required` with an approval link | Refused. You add the file to the role in Settings |

A role only narrows. It lists items from your allowed list, so it can never reach a file you have not allowed,
and taking an item off the allowed list takes it out of every role. A read-only connection through an editor
role is still read only.

The mailbox, pairing, webhooks, access requests and files other people share with you are not part of a role.
A role-limited agent is not offered those tools.

A role that does not exist answers `403 unknown_role`. It never falls back to the whole list, so deleting a
role cuts off the agents that use its address.

## Use a role from Claude Code

Add the role's address as its own MCP server, then sign in once with `/mcp`:

```bash
claude mcp add --transport http drive-researcher https://botrbac.com/mcp/role/researcher
```

Give a subagent only that server. In `.claude/agents/researcher.md`:

```markdown
---
name: researcher
description: Reads the research folder and summarises it.
tools: mcp__drive-researcher__*
---
You read the files in the research folder and report what you find.
```

Claude can now hand work to the `researcher` subagent, and that subagent's Drive calls go through the role.
To run a whole session as the role, start it with `claude --agent researcher`.

Each role address signs in as its own connection, so each shows up as its own row under **Settings →
Assistants** and in Activity, where calls made through a role are marked `(role researcher)`.

If the main session should not reach the rest of your allowed list either, do not add plain
`https://botrbac.com/mcp` to that project. Add only role addresses.

## Limits to know about

- **A connection belongs to the address it signed in through.** An app that signs in at a role's address is
  bound to that role: its tokens are refused (`403 role_mismatch`) on plain `/mcp` and on every other role,
  and it can only refresh for that address. An app connected to plain `/mcp` is refused on a role's address;
  add the role's address as its own server and sign in there. The consent page names the role, and refuses a
  role you do not have. This relies on the app asking for the address it was given (the OAuth `resource`
  parameter, which it reads from the role's own metadata); an app that asks for plain `/mcp` instead gets a
  plain connection, which a role's address refuses.
- **Pre-shared `API_TOKENS` cannot be bound.** They are the admin's own keys, not connections. On a role's
  address they are narrowed to the role; on plain `/mcp` they work as before.
- **Role changes take effect on the next call**, or within `ALLOWLIST_CACHE_TTL` seconds (default 2) on another
  server instance.
- Role names become the address: `Research Reader` is `research-reader`. Saving a role under an existing name
  replaces it. You can have 20 roles, each with up to 200 items.
- A file you allowed on its own stays protected from rename and trash under a role, even when the role reaches
  it through a folder.

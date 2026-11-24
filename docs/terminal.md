# Bot RBAC Terminal (beta)

Roles defined on the website, enforced on your own computer by a `botrbac` CLI, for any
agent that speaks MCP (Claude Code, Codex, Cursor, Gemini CLI, …). It is a separate
feature: it does not change `/mcp`, the existing dashboard pages, or existing connections.

## Status

Phase 1 of the plan: the feature flag and an empty `/terminal` page. Roles, device-code
login, the CLI gateway, offline sync and `botrbac run --role` come in later phases.

## Turning it on

Off by default. Either:

- `TERMINAL_ENABLED=true` turns it on for everyone who can sign in, or
- an Edge Config item named `terminal` turns it on for a beta list:

  ```json
  {"enabled": true, "emails": ["you@example.com"]}
  ```

  Leave out `emails` to turn it on for everyone. A missing or malformed item, or a
  failed read with nothing cached, means off.

When it is off for someone, `/terminal` is the ordinary 404 page and the nav has no
Terminal link.

## What it can and cannot guarantee

Bot RBAC Terminal only sees tool calls that go through `botrbac gateway` (MCP tools) or a
hook that calls `botrbac check` (an agent's own tools). It stops an agent from going around
your rules. It cannot stop the person who owns the computer from removing it.

## Storage

Every key this feature writes starts with `term:`, so it never reads or writes the
records the rest of the app uses.

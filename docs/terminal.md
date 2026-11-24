# Bot RBAC Terminal

Roles defined on the website, enforced on your own computer by a `botrbac` CLI, for any
agent that speaks MCP (Claude Code, Codex, Cursor, Gemini CLI, …). It is a separate
feature: it does not change `/mcp`, the existing dashboard pages, or existing connections.

## Status

The Terminal page is on for everyone who can sign in. There is no flag for it.

## What it can and cannot guarantee

Bot RBAC Terminal only sees tool calls that go through `botrbac gateway` (MCP tools) or a
hook that calls `botrbac check` (an agent's own tools). It stops an agent from going around
your rules. It cannot stop the person who owns the computer from removing it.

## Storage

Every key this feature writes starts with `term:`, so it never reads or writes the
records the rest of the app uses.

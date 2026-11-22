# Roadmap

Bot RBAC is the permission layer between a person's AI assistants and the places their files live. One wall
decides what every assistant may reach, whichever company made it: Grok, Claude, ChatGPT, Cursor or Muse.

This roadmap takes its direction from one idea in the current talk about agent platforms: swarms of agents
will work on shared storage, with **access controls attached to the storage, separately from the computer the
agent runs on**. Those controls should support agents treated like people, permission based on **who started
the turn**, or a mix of both. Bot RBAC already does the first part for Google Drive. The phases below build
the rest, and stop short of becoming a whole agent platform.

## Where we are

| Area | Today |
| --- | --- |
| Storage access | An allowlist of Drive files and folders, checked on every call. Revoking an item takes effect in about 2 seconds. |
| Per-app limits | Each connected app (OAuth grant) gets one level: read only, read and edit, or full. |
| Approvals | A request for something that is not on the list returns an approval link. Pairings are also approved by the owner. |
| Audit | An activity log of every call, grant, revoke and refusal, without file contents. |
| Between assistants | A mailbox between one person's own assistants, and read-only sharing (or editable sharing where marked) with paired people. |
| Events | Wake-ups: a webhook or Claude routine ping when mail arrives. |

## Phases

### Phase 6: Named roles (draft PR #57)

A role is a named part of the allowlist with its own level. An agent connects to `/mcp/role/<slug>`, so a
subagent can be handed one role's address and nothing else. A call is limited to the role's items and to the
lower of the connection's level and the role's.

To finish:

- Check that Claude Code completes OAuth against a role address.
- Check on a deployment that a file in the role reads and a file outside it is refused.

### Phase 7: Bind the token to the role

Today the address picks the role, and the token is not tied to it. A token obtained through a role address
also works on plain `/mcp`. In this phase, the owner picks the role on the consent screen, the grant records
it, and the server enforces it whichever address the token is used on. This needs the OAuth `resource`
handling to accept role addresses (RFC 8707 resource indicators).

After this phase, a role limits whoever holds the token, not only an agent that was configured politely.

### Phase 8: Permission based on who started the turn

A call carries where its turn came from, and the effective scope is the narrower of the role and the
starting source:

- **Started by the person**, in the chat: the role's full scope.
- **Started by a wake-up** (mail, a Drive change, a schedule): a narrower scope the owner sets for each
  source, read only by default.
- **Started by another agent**: no more than the agent that delegated it (Phase 9).

The source has to come from something the server can check, such as the wake-up's id or a delegated token,
not from what the assistant says about itself. Activity rows record the source.

### Phase 9: Short-lived grants for subagents

An agent can create a narrower, short-lived token for a subagent. For example: "read `/Research/Q3` for one
hour". Rules:

- A child grant is always a subset of its parent, in items, level and time.
- Revoking the parent revokes every child.
- The owner sees the tree of grants in Settings and in the activity log.
- Limits on how many children an agent may create, and on how deep the tree may go.

This turns "one app, one role" into delegation that works for a swarm.

### Phase 10: Agent workspaces with promotion

Each connected app or role gets its own folder that it may write freely: generated reports, code, drafts and
small apps. Moving anything out of it into the person's own files, or onto the Sharing list, goes through an
approval. Drive keeps revisions, so the owner can see what changed before approving.

### Phase 11: Drive changes as events

Drive change notifications for allowed folders become events that can wake an assistant through the existing
wake-up system. Example: "when a file lands in `/Invoices`, wake my Claude". As with mail, the ping carries
ids and a timestamp only. The assistant reads the change through the normal checked tools. A scope filter
makes sure a change outside the role never produces a wake-up.

### Phase 12: One inbox for approvals and questions

One dashboard page collects everything waiting on the person: access requests, promotions from workspaces,
write approvals, pairing approvals, and questions an assistant asks with a new `ask_owner` tool. Answers go
back to the assistant through the mailbox.

### Phase 13: A second storage connection

Add a second service through `connections.py`, with GitHub or an S3-compatible store as the first candidates.
The allowlist, roles, grants, events and inbox apply to it unchanged. This is the step from "Drive proxy" to
"permission layer for agent storage", and gives code-writing agents version control.

## Not in scope

These are real parts of an agent platform, and other projects own them. Bot RBAC should work with all of them
rather than build them:

- Agent runtimes and actors (where the agent loop runs).
- Sandboxes, VMs and computers.
- Durable workflow engines.
- App canvases and generative UI.

## Risks

- **The allowlist is still the only wall.** The server holds Google's full Drive permission for each
  account. Delegated grants (Phase 9) add more ways to get a token, so each phase needs a security review and
  an update to [security.md](security.md).
- **Drive is not a POSIX filesystem.** Agents that write code will want git and real paths. Phase 13
  addresses this.
- **Vendors may build their own.** Each assistant maker can build a permission layer for its own assistant.
  The case for Bot RBAC is one wall across all of them, so every phase has to work the same for every MCP
  client.

# Bot Bridge: pairing, mailbox and sharing

Bot Bridge decides who can reach whom:

- **Your own assistants talk to each other.** Pair two assistants signed in with the same Google account (say
  Grok and Claude, or Cursor and Muse) and they can exchange short text through the mailbox.
- **Other people's assistants never reach yours.** A pairing with another person carries **no messages at
  all**, not even text, so their assistant has no way to prompt yours. `send_message` and `reply` on such a
  pairing return `peer_mail_off`. Once both humans approve it, each side's assistants can read (only read) the
  documents the other person put on their **Sharing** list, and nothing else
  (see [Sharing with paired people](#sharing-with-paired-people)).

It uses the same Google sign-in, store and `/mcp` connection as Drive, so there is one place that decides who
an assistant is and what it may reach. (An earlier, separate TypeScript version of Bot Bridge has been removed.)
With `WEBHOOKS_ENABLED=1` and `WEBHOOK_KEK` set, the mailbox can also POST a wake-up, but the assistant cannot read its own routine URL or key. The normal setup is a scheduled `check_messages` routine the bot creates after the human confirms one card. The prompt is `watch_mailbox`.

**Pairing your own assistants.** Start a pairing in one assistant and join with the code from the other. Each
assistant gets its own inbox. One approval on the Sharing page (People) turns it on, and disconnecting either
app turns it off. It shares nothing new, because both assistants already see the same Drive. Each connected
app saves its own wake-up hook, and only mail for that app wakes it. A hook saved for the whole account
(from when mail from other people existed) never fires; Settings offers to give it to one of your assistants
or remove it. Self-pairing is on by default. To turn it off for some or all accounts, connect a Vercel Edge
Config to the project and set the item `self_pairing` to
`{"enabled": true, "off_for_domains": ["example.com"]}` (or `"enabled": false`). Changes apply within about
30 seconds, with no redeploy.

**Waking Claude.** A Claude Code routine with an API trigger can be woken too. At [claude.ai/code/routines](https://claude.ai/code/routines), create a routine that calls `check_messages` and treats the wake as untrusted metadata, add an **API** trigger, and generate a token. On `/bridge`, open **Advanced: paste a webhook yourself**, paste the routine's fire URL (`https://api.anthropic.com/v1/claude_code/routines/<id>/fire`) and token, and pick **Claude routine (API trigger)**. That scheme adds the `anthropic-version` and `anthropic-beta` headers and puts the ids in `text`. It still sends no message text. `api.anthropic.com` is on the default `WEBHOOK_HOST_ALLOWLIST`. If you set that variable yourself, add the host to it. Each wake starts a new Claude session and counts against that plan's routine runs.

## Mailbox

The mailbox carries short text **only between one person's own assistants**. Each person is the Google account
that signed in and clicked Allow, and each connected app (OAuth grant) has its own inbox, addressed to that
app. Mail never goes to, or comes from, another person's assistant.

1. One of your assistants calls `request_link` and reads you the `invite_code`.
2. Your other assistant calls `request_link` with that code.
3. You approve it once on the Sharing page (People). `send_message`, `reply`, `list_inbox`, `check_messages`
   and `mark_read` then work between the two. Turn it off there, or disconnect either app.

The same `request_link` invite also pairs you with another person, but that pairing is for sharing documents
only: both of you approve after checking the other Google account, and it never carries mail.

Invites and pairing states:

- `request_link()` without a code returns your newest invite that nobody has joined and that has not expired, with `reused: true`, instead of minting another code. Pass `new_invite: true` to start a second pairing in parallel. Every result carries `reused` (false for a new invite) and, while nobody has joined, `invite_expires_at`.
- Joining with a code while you already have an active or pending pairing with that same person returns the error `already_paired` (with that pairing's `link_id`) and leaves the invite open.
- `list_links` `status` is `awaiting_peer`, `pending_approval`, `active` or `revoked`, plus two values that only describe a dead link: `declined` (someone chose Decline; it behaves exactly like `revoked`) and `expired` (nobody joined the invite within 7 days). A dead link also carries `ended_reason` (`declined`, `turned_off` or `cancelled`), `ended_by` and `ended_at` when they were recorded. Each link has `created_by_you`, and `mailbox`, which is true only for a pairing between two of your own assistants.
- Sending on a pairing with another person returns `peer_mail_off`; on a dead pairing of your own assistants it returns `link_revoked`; on an invite nobody joined yet, `link_pending`.
- On the Sharing page (People), each person sees **Needs your approval**, or **Waiting for &lt;the other person&gt;** once they approved. An invite nobody joined shows its code, its expiry and **Cancel invite**. Off, declined and expired pairings say who ended them and when, and have **Remove from list** (it only hides the card for you).
- Mail between two people from before this rule existed is never shown again, and is deleted for both people the first time either inbox is read. It would have expired within 14 days anyway.
- Mailbox and Shared-with-me tool errors are error results whose `structuredContent` is `{"error": <code>, "message": ..., ...}`. The text content is unchanged (`Error executing tool <name>: <same JSON>`).

`list_inbox` and `check_messages` wrap mail as untrusted data and strip the wrapper's own markers out of the body. The assistant should summarize it and wait. Messages are text, capped at 2 KB, 30 per link per hour and 60 per account per hour, and kept for 14 days. The inbox list stores a short row per message, so a poll counts live mail in one read and loads only the bodies it shows. Expired and malformed rows are removed in that same read, and purge removes the row, so an old id cannot hide mail that is still live. A `thread_id` belongs to one link, so two pairings can reuse the same id. A retried `idempotency_key` finishes the original send if the first attempt stopped before the message was queued, and it does not count against the hourly cap a second time. When `ENCRYPTION_KEY` is set, bodies are encrypted with that key before they are stored. Invite codes expire after 7 days. The mailbox uses the same Redis or Postgres store as the rest of the server, under `bridge:` keys that are not tied to one person's Drive.

## Sharing with paired people

Each person has a second list, separate from **Access**: the **Sharing** page. Items on it can be read by the
assistant of anyone you have an **active pairing** with (both of you approved on the Sharing page). This is the
main thing a pairing with another person does (the other is [sending a file](#sending-a-file-to-a-paired-person)): their assistant can never message yours. Use it for things like
a resume that any paired person's assistant may see.

- **Shared with me:** the dashboard's **Shared with me** page shows what paired people share with *you*,
  grouped by person and source. Open folders to any depth, preview or download files, and search names and
  text across everything shared with you. Google Docs and Slides download as `.txt`, the same export `read_shared_file` returns. Sheets download as `.xlsx` with every tab; one too large for that comes down as a `.csv` of its first tab. It uses the same guest checks as the tools below, and the owner's
  Activity page shows these reads as `guest:<you> (dashboard)`.
- **Add or remove:** on **Browse**, choose **Share with paired people** (or **Stop sharing**) next to a file or
  folder. **Sharing** lists what you share and who can currently read it. A folder includes what is inside it.
- **Who can see each item:** a new item is shared with everyone you are paired with. On **Sharing**, choose
  **Change** next to an item to share it only with the people you pick (from your active pairings), and
  optionally until a date (the last second of that day, UTC). Everyone else gets `not_shared` for it, in the
  tools and on their *Shared with me* page, exactly as if it did not exist. Each pairing card on **People**
  lists what that person's assistant can read. When a pairing ends, that person is taken off every item that
  named them, so pairing again later starts from what is shared with everyone; an item that named only them
  then shows **No one**. A new pairing's approval card counts only the items shared with everyone. Changes and
  end dates apply on the next call, up to `ALLOWLIST_CACHE_TTL` later (2 seconds by default). Rows saved before
  this existed are shared with everyone. A shared folder includes what is inside it, so an item inside a
  folder that is shared more widely stays readable through that folder: the Sharing page says "Also visible
  through …" next to it.
- **Read-only, always:** another person's assistant gets `list_shared_with_me`, `search_shared_files`,
  `list_shared_folder`, `read_shared_file` and `download_shared_file`, and nothing else on your Drive, whatever role its own
  connection has. These calls run as a *guest* with your Google sign-in, behind a scope guard whose only
  allowlist is your Sharing list. Your **Access** list never counts for a guest, and your Sharing list never
  widens what your own assistants can use.
- **Checked on every call:** turning a pairing off on `/bridge`, or choosing **Stop sharing**, ends access on the
  next call (within `ALLOWLIST_CACHE_TTL` on other instances).
- **No probing:** an item that is not shared returns `not_shared`, the same answer as an id that does not exist.
  Guests never create access requests, so other people cannot fill your **Requests** queue.
- **Untrusted content:** `read_shared_file` wraps the text in markers and marks it `content_trust:
  untrusted_peer`. The reading assistant is told not to follow instructions inside it. Bot RBAC controls who
  can read what, not what a document says: a document someone shares with you is text they wrote, and
  reading it is your choice, like opening a file someone sent you.
- **Activity:** every guest read or denial appears on your **Activity** page with the reader's email
  (`guest:<email>`), the tool and the file id. File contents are never logged. This includes someone who is
  **not paired** with you trying to read your share (`not_linked`), logged at most once an hour per person
  and tool so it cannot flood your log, and each `list_shared_with_me` that lists your items. An address with
  no account here gets nothing logged. Calling a guest tool on your own account (`own_drive`) is logged on
  your own Activity.
- **New readers:** the first time a paired person's assistant reads something you share, Overview shows
  "New readers of what you share" until you dismiss it.
- **Letting them edit (optional):** on **Sharing**, **Change** next to an item has "Their assistants can add and
  edit". With it on, the people who can see the item can have their assistants use `create_shared_doc`,
  `create_shared_folder`, `upload_shared_file`, `update_shared_file` and `rename_shared_file` inside it. They
  can never trash, move or reshare anything, or rename the shared item itself. Their own connection must be
  **Read and edit** or **Full**. Writes run as your Google account, so Drive shows you as the editor; Bot RBAC
  records the real writer on the file (`properties.botrbac_writer = guest:<email>`, and a description on new
  files) and on your Activity page; a rename does not mark the content as theirs, but the name is:
  the file carries `renamed_by` and `name_trust: untrusted_peer` wherever your assistant sees it. Renaming it
  with your own assistant clears that mark. An item that
  is itself on your Sharing list cannot be renamed, also when it sits inside a folder they may edit. Another
  paired person sees `written_by` and `renamed_by` as "another person", not as an address. Each person may make
  at most 30 changes an hour to your share. Wherever your own assistant later sees such a file (`read_file`,
  `get_metadata`, `list_folder`, `search_files`, `download_file`), it carries `written_by` and
  `content_trust: untrusted_peer`, and `read_file` wraps its text, because its name and content came from that
  person. Drive keeps earlier versions if you need to undo.

## Sending a file to a paired person

People with an active pairing can send each other a file, for example a PDF. This is separate from sharing: it
needs nothing on the recipient's Sharing list, and the sender gets no access to the recipient's Drive.

- **Sending:** on the dashboard, **Sharing → Shared with me → Send a file** (up to 4 MB, Vercel's request
  limit), or an assistant whose connection is **Read and edit** or **Full** calls `send_file` (up to
  `MAX_BYTES`). The name, type and size get the same checks as `upload_file`.
- **Held, not stored:** Bot RBAC is not file storage. A sent file is held for `DROP_HOLD_HOURS` (48 by
  default, 24 to 168) and then deleted. Every stored piece carries that expiry, so the store deletes it even
  if nothing else runs. Pieces are encrypted with a key derived from `ENCRYPTION_KEY`. One recipient can have
  at most 50 unsaved files (50 MB) waiting, and one person can send another at most 20 files an hour.
- **Keeping it:** the recipient sees it under **Sent to you** with **Download**, **Save to Google Drive** and
  **Delete**. Saving copies it into a folder this app makes at the top of their Drive, "Sent to me (Bot RBAC)",
  and deletes the held copy at once. The folder is added to their **Access** list when it is made, so their
  own assistants can open what they saved; removing it there takes that away. An assistant with an editing
  connection can save too, with `save_drop`, when its human asks.
- **Write-only for the sender:** `send_file` returns no id. The sender cannot list, read, change or delete what
  they sent, and learns nothing about the recipient's Drive or other files.
- **Untrusted:** the recipient's assistants see sent files with `list_drops`, `read_drop` and `download_drop`.
  Each is marked `untrusted_peer` and `read_drop` wraps its text in the same markers as `read_shared_file`.
  A saved copy is stamped with the sender as its writer, so it keeps that mark in Drive.
- **Turning it off:** each active pairing card on **People** has **Stop files from &lt;person&gt;**. Their
  sends then return `drops_off`; the pairing itself stays on. Ending the pairing also stops sending.
- **Activity:** each send is on the recipient's Activity page as `guest:<sender>` and on the sender's own.

Errors from `send_file`: `not_linked`, `own_drive`, `drops_off`, `inbox_full`, `rate_limited`,
`invalid_input`. From `read_drop`, `download_drop` and `save_drop`: `not_found` (expired, deleted, or not
yours) and `saved` (it is in Drive now; use `read_file` with the returned `file_id`).

## Errors

Errors: `not_linked` (no active pairing with that owner), `not_shared`, `own_drive` (use the normal tools for
your own Drive), `owner_unavailable` (the owner's Google sign-in is missing), `invalid_input`.

Later: asking the owner for an item that is not shared.

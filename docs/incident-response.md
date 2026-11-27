# Incident response

A one-page runbook for when an assistant misbehaves, a token or key may have leaked, or
someone reports a problem ([SECURITY.md](../SECURITY.md) says how to report one).

## 1. Stop access (minutes)

| What happened | Do this | What it ends |
| --- | --- | --- |
| One assistant is acting oddly | **Settings → Assistants → Disconnect** on that app | Its tokens, its wake-up, its pairings with your other assistants |
| You are not sure which one | **Settings → Assistants → Disconnect all assistants** | Every connected app and terminal of your account, at once |
| A file should not be reachable | **Files → Remove** (or untick it) | That item and everything under it, for every assistant, within `ALLOWLIST_CACHE_TTL` (2 s) |
| A paired person should not read your Sharing list | **Sharing → People → Turn off** | Their reads of your Sharing list; their files to you (or use **Stop files from them**) |
| Your Google account may be compromised | **Settings → Connections → Disconnect** Google Drive, then remove "Bot RBAC" at myaccount.google.com/permissions | The stored Drive sign-in (revoked at Google) |
| A shared `API_TOKENS` bearer leaked (operator) | Remove its hash from `API_TOKENS` in Vercel and redeploy | That bearer; nothing else changes |

None of these delete files: trash is the only destructive tool, and Drive keeps trashed
files for 30 days.

## 2. Find out what happened

- **Activity** (`/activity`) lists the newest 500 events. Use **Every assistant / <app>**
  to see one connection's calls, and **Needs attention** for refusals.
- Events to look for:
  - *"a sign-in token was used twice"* (`oauth_ended`, reason `refresh_reuse` or
    `code_reuse`): a copy of an app's token was used. The server already disconnected it.
  - *"A terminal's sign-in token was used twice"* (`terminal_refresh_reuse`): disconnect
    that terminal on the Terminal page unless you know it retried.
  - *"made so many calls this hour"* (`activity_limited`): one app passed
    `APP_ROWS_PER_HOUR` (120) rows in an hour. Its later calls are only in the server log.
  - *"tried to read … Blocked"*: an assistant asked for something outside its list.
- **Server log** (Vercel → Logs, operator only): one JSON line per tool call and dashboard
  action. `actor` is a 12-character tag of the account (`audit.actor_tag(email)`), `app` a
  tag of the connection (`audit.app_tag(grant_id)`). It never holds file contents, names,
  search text, message bodies, tokens or a paired person's address. To find one person's
  lines, compute their tag in a Python shell and search for it.

## 3. Rotate secrets (operator)

| Secret | Rotate when | Side effects |
| --- | --- | --- |
| `SESSION_SECRET` | A session cookie or the secret leaked | Everyone signs in again; assistants register again (their connections keep working) |
| `ENCRYPTION_KEY` | The store **and** this key leaked | Every stored Drive/Notion/OneDrive sign-in and every signed record becomes unreadable: everyone reconnects and re-allows. Last resort |
| `WEBHOOK_KEK` | Sender keys may have leaked | Saved wake-ups stop working until their keys are saved again |
| `GOOGLE_OAUTH_CLIENT_SECRET` | It leaked | Rotate in Google Cloud Console, then update Vercel |
| `REDIS_URL` / `KV_*`, `BLOB_READ_WRITE_TOKEN` | Store credentials leaked | Rotate in the Vercel storage integration. Signed records stop a writer without `ENCRYPTION_KEY` from adding access |
| `CRON_SECRET` | Any time | None |

## 4. Afterwards

- Write down the timeline from Activity and the server log while it is still there
  (Activity keeps 500 rows; Vercel keeps logs per your plan).
- Reconnect only the assistants you trust, with **Read only** unless they need to write.
- If the cause was a bug in Bot RBAC, report it privately as in [SECURITY.md](../SECURITY.md).

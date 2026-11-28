# X (Twitter)

X is an optional connection, next to Google Drive. Assistants can **read** recent posts from the X accounts
and lists a person allows, and search recent posts by those accounts.

A deployment can opt in to one write: with `TWITTER_ALLOW_POST=1`, assistants allowed to edit can also
**post** on the person's account ([Posting](#posting)). It is off by default. Nothing ever likes, reposts,
follows, unfollows, sends a direct message or deletes a post.

## How access works

X's permissions cover the whole account: `tweet.read`, `users.read` and `list.read` let the server read
anything the person's X account can see. X can't limit that to some accounts, so **Bot RBAC's X allowlist
is the only limit on assistants**, like OneDrive's.

On **Files → From X**, the person allows:

- **Accounts**, by typing an `@handle` or an `x.com/handle` link. Bot RBAC looks the account up and stores
  its numeric id, never the handle, so an account that changes its handle stays the same entry, and a handle
  someone else takes over later is not allowed by accident.
- **Lists**, from **Your lists** (the lists the connected account owns) or by a list link
  (`x.com/i/lists/<id>`). A private list stays readable only while the connected account can see it.

What each tool may read:

| Tool | Reads |
|---|---|
| `twitter_list_allowed` | The allowed accounts and lists (from Bot RBAC's store; X is not called) |
| `twitter_read_timeline(source, max_results?)` | Recent posts of one allowed account, or of one allowed list |
| `twitter_read_post(post_id)` | One post, only when its author is an allowed **account** |
| `twitter_search(query, max_results?)` | X's recent search (about seven days), limited to allowed **accounts** |

`source` may be an id from `twitter_list_allowed` (`user:<id>` or `list:<id>`), an `@handle` or an x.com
link; a handle is looked up at X and compared by id. A post seen in an allowed list's timeline whose author
is not an allowed account can't be read alone with `twitter_read_post`.

Something not allowed and something that does not exist get the same `twitter_not_allowed` answer. Post
text is untrusted data, wrapped in markers like shared files.

### Search

Bot RBAC wraps the assistant's query as `(<query>) (from:<id> OR from:<id> …)` with the allowed account
ids, as many as fit in X's 512-character query limit (the answer says when some were left out). Queries over
200 characters, or with a parenthesis or quote that is not closed, are refused, so a query can't break out
of its group. Every result is checked again by its author id before it is returned, so even a query X reads
differently can't return posts by other accounts.

Search needs an X API plan that includes recent search. Without it the tool answers
`twitter_search_unavailable`; reading timelines may still work.

## Posting

Off by default. It exists only on a server with `TWITTER_ALLOW_POST=1`; without that the tool is not
registered, no role is offered it, Connect X does not ask X for `tweet.write`, and the dashboard and privacy
page say Bot RBAC never posts.

| Tool | What it does |
|---|---|
| `twitter_create_post(text, reply_to?)` | A public post on the person's account, or a reply to a post by an allowed account |

- **Who.** With the setting on, only `editor` and `admin` connections (**Read and edit** and **Full**) have
  this tool. Read-only connections do not see it and are refused if they call it.
- **The person approves too.** X's screen asks the person to allow posting. If they did not (or connected
  before posting was turned on), the tool answers `twitter_cannot_post` and they choose **Connect X** again.
- **What.** Up to 280 characters of plain text. X counts some characters and links differently and may
  still refuse a post as too long, or as a duplicate of a recent post (`twitter_post_refused`).
- **Replies.** `reply_to` must pass the same check as `twitter_read_post`: a post by an allowed account.
- **No retry.** One call is one request to X. If X doesn't answer, the post may or may not exist
  (`twitter_unavailable`), and the assistant is told to check before trying again.
- **Activity.** Every post is a change on Activity, with the new post's id (and the post it replied to),
  never the text.

A prompt-injected assistant with an editing role could still post something unwanted on the person's
account. Leave posting off unless you need it, and give editing roles only to assistants you trust.

## Set it up (operator)

1. In the [X developer portal](https://developer.x.com/), create a project and app. Under **User
   authentication settings**, turn on **OAuth 2.0**, choose **Web App, Automated App or Bot** (a confidential
   client), and set the app permissions to **Read** (or **Read and write** if you will set
   `TWITTER_ALLOW_POST=1`).
2. Add the callback URI `<APP_BASE_URL>/connect/twitter/callback` and your website URL.
3. Copy the **OAuth 2.0 Client ID and Client Secret** (not the API key and secret, which are OAuth 1.0a).
4. Set `TWITTER_OAUTH_CLIENT_ID` and `TWITTER_OAUTH_CLIENT_SECRET` and redeploy. A value starting with
   `REPLACE` counts as unset.

X appears on **Settings → Services** once both are set.

Reading posts and lists needs a paid X API plan (or pay-per-use credits); X's free access allows little
more than posting and looking up the connected account. When X refuses or rate-limits a call, the tool
answers `twitter_rate_limited` or `twitter_not_allowed` and nothing else changes.

### Turning posting on

1. Set the app's permissions to **Read and write** in the X developer portal.
2. Set `TWITTER_ALLOW_POST=1` and redeploy. This registers `twitter_create_post` for `editor` and `admin`
   connections, and Connect X then asks for `tweet.write`.
3. Each person who already connected chooses **Connect X** again on **Settings → Services** and approves
   posting.

To turn it off again, unset `TWITTER_ALLOW_POST` (the tool disappears). Existing connections keep a token
that X would accept for posting, but nothing on the server can use it; reconnecting drops the permission.

## Disconnecting

Disconnecting X deletes the stored tokens, asks X to revoke both, and clears the list of allowed accounts and
lists. Connecting a different X account clears the list too. If X doesn't confirm the revoke, remove Bot RBAC
on X under **Settings → Security and account access → Apps and sessions → Connected apps**.

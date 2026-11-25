# Notion

Notion is an optional second connection, next to Google Drive. Assistants can **read** the Notion pages and
databases a person allows. They cannot edit Notion.

A deployment can opt in to one write: with `NOTION_ALLOW_CREATE=1`, assistants allowed to edit can also
**create a new page** under an allowed page ([Creating a page](#creating-a-page)). It is off by default,
and nothing can ever change, move or delete a page that already exists.

## How access works

There are two gates, both checked on every call:

1. **Notion's consent screen.** Connecting Notion opens Notion's own screen, where the person picks a
   workspace and the pages to share with Bot RBAC. Anything not picked is invisible to the server.
   Each person connects one workspace at a time; connecting again replaces it.
2. **Bot RBAC's Notion allowlist.** On **Files → From Notion**, the person chooses **Allow** on the pages
   and databases their assistants may read. Everything inside an allowed page (sub-pages, databases,
   rows) is included, like a file in an allowed Drive folder.

To share more pages with Bot RBAC, use **Pick pages in Notion** on the same tab. That reopens Notion's
screen.

Disconnecting Notion clears the list of allowed Notion pages, and so does connecting a different
workspace. A copy of a synced block shows content from another page; it is read only when that page is
allowed too.

## Tools

| Tool | What it does |
|---|---|
| `notion_list_pages` | The allowed pages and databases |
| `notion_read_page` | Text of an allowed page (or rows of a database). Takes an id or a Notion URL |
| `notion_search` | Notion's search (titles only), filtered to what is allowed |

Those three are read-only and available to every app role. All Notion tools are registered only when
Notion is configured on the server.

### Creating a page

Off by default. It exists only on a server with `NOTION_ALLOW_CREATE=1`; without that the tool is not
registered, no role is offered it, and the dashboard and privacy page say Notion is never edited.

| Tool | What it does |
|---|---|
| `notion_create_page(parent_page_id, title, content?)` | A new page under an allowed page, or a page inside one |

With the setting on, only `editor` and `admin` connections (**Read and edit** and **Full**, the ones that can write to Drive)
have this tool. Read-only connections do not see it and are refused if they call it.

- **Where.** `parent_page_id` (an id or a Notion URL) must pass the same check as a read: an allowed
  page, or a page under one. Anything else gets the same `not_allowed` answer as `notion_read_page`. A
  database as the parent is refused (`notion_parent_unsupported`); adding database rows is not supported.
- **What.** `content` is plain text. The server turns it into simple blocks: paragraphs (a blank line
  ends one), `#`/`##`/`###` headings, `-` and `1.` list items, `- [ ]` to-dos, `>` quotes, ``` code and
  `---` dividers. Inline Markdown such as `**bold**` or links stays as typed. Callers cannot send Notion
  block JSON.
- **Limits.** Title up to 200 characters, content up to 20,000 characters and 100 blocks. Over a limit is
  an `invalid_input` error; nothing is cut off silently.
- **After.** The new page sits under an allowed page, so assistants can read it at once. The allowlist
  itself does not change.
- **Never.** No tool edits, appends to, moves, trashes or deletes a Notion page.

Creating pages needs the **Insert content** capability on the Notion connection (see below). Without it
Notion refuses, nothing is created, and the tool returns `notion_cannot_create` with what to change. Bot
RBAC never asks Notion for more by itself, and reading keeps working either way.

## Set it up (operator)

1. In Notion, open **Developer tools → Developer connections → New connection**. Choose **OAuth**.
2. Add the redirect URI `<APP_BASE_URL>/connect/notion/callback`.
3. Give it the **Read content** capability, and user information without email addresses. Add **Insert
   content** only if you also set `NOTION_ALLOW_CREATE=1` so assistants can create pages. Leave **Update
   content** off: Bot RBAC never uses it.
4. Set `NOTION_OAUTH_CLIENT_ID` and `NOTION_OAUTH_CLIENT_SECRET` and redeploy. A value starting with
   `REPLACE` counts as unset.

Notion appears on **Settings → Services** once both are set.

### Turning page creation on

Both switches are needed. Either one alone leaves Notion read-only.

1. Set `NOTION_ALLOW_CREATE=1` and redeploy. This registers `notion_create_page` for `editor` and `admin`
   connections and changes what the dashboard and privacy page say about Notion.
2. In Notion, open the connection (**Developer tools → Developer connections → your connection →
   Configuration → Capabilities**), tick **Insert content** and save.
3. Each person who already connected chooses **Connect Notion** again on **Settings → Services**, so
   Notion's screen shows the new permission and they can accept it.
4. Give the assistant **Read and edit** or **Full** on its connection, and allow the parent page on
   **Files → From Notion**.

The person's own Notion account must also be able to edit the parent page. To turn creation off again,
unset `NOTION_ALLOW_CREATE` (the tool disappears) and untick **Insert content**.

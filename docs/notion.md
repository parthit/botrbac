# Notion

Notion is an optional second connection, next to Google Drive. Assistants can **read** the Notion pages and
databases a person allows. They cannot edit Notion.

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

All three are read-only and available to every app role. They are registered only when Notion is
configured on the server.

## Set it up (operator)

1. In Notion, open **Developer tools → Developer connections → New connection**. Choose **OAuth**.
2. Add the redirect URI `<APP_BASE_URL>/connect/notion/callback`.
3. Give it only the **Read content** capability, and user information without email addresses.
4. Set `NOTION_OAUTH_CLIENT_ID` and `NOTION_OAUTH_CLIENT_SECRET` and redeploy. A value starting with
   `REPLACE` counts as unset.

Notion appears on **Settings → Services** once both are set.

# OneDrive

OneDrive is an optional connection, next to Google Drive. Assistants can **read** the OneDrive files and
folders a person allows. Assistants whose role may edit (editor and admin) can also **add and change** files
inside them. No assistant can delete, move or share OneDrive items.

## How access works

Microsoft has no per-file permission for personal accounts, so Bot RBAC asks for `Files.ReadWrite`, which
lets the server read and change the person's whole OneDrive. What assistants may reach is held to **Bot
RBAC's OneDrive allowlist**: on **Files → From OneDrive**, the person browses their drive and chooses
**Allow** on files and folders. Everything inside an allowed folder is included, like a file in an allowed
Drive folder. Reads and writes pass the same check.

- The top of the drive can't be allowed, so the whole drive is never shared by one click.
- Shortcuts to other people's items ("Add to my files") are not listed, followed or written to.
- A file moved out of an allowed folder stops being reachable; so does everything in an allowed folder that
  is deleted.
- Disconnecting OneDrive deletes the token and clears the list. Connecting a different Microsoft account
  clears the list too.

Microsoft has no way for this kind of app to revoke a token. To remove the permission at Microsoft as well,
the person goes to account.live.com/consent/Manage (personal account) or myapps.microsoft.com (work or
school account). The dashboard says so when they disconnect.

### Read-only connections

Connections made before writing existed were granted `Files.Read`. They keep working for reading, and are
refreshed with the read scopes they were granted (a refresh can't ask for more than the person approved).
The write tools answer `onedrive_read_only` until the person chooses **Reconnect OneDrive** (shown on
**Files → From OneDrive**) and approves editing. Reconnecting the same account keeps the allowed list. A
connection where Microsoft granted only `Files.Read` (for example an organization that approved only reading)
is read-only the same way.

## Tools

| Tool | Roles | What it does |
|---|---|---|
| `onedrive_list_folder(folder_id?)` | all | No folder: the allowed files and folders. A folder: its contents, when it is allowed or inside one |
| `onedrive_read_file(file_id)` | all | Text of an allowed file (same formats as `read_file`: Word, PDF, PowerPoint, Excel, RTF, text) |
| `onedrive_download_file(file_id)` | all | Size-capped base64 of an allowed file |
| `onedrive_search(query, max_results?)` | all | Microsoft's search (names and content) inside each allowed folder; an allowed single file is matched by name |
| `onedrive_create_folder(name, parent_id?)` | editor, admin | A new folder in an allowed folder (or one inside it) |
| `onedrive_upload_file(name, content_text \| content_base64, parent_id?)` | editor, admin | A new file there. The type comes from the extension. A taken name fails with `name_taken`; nothing is overwritten |
| `onedrive_update_file(file_id, content_text \| content_base64)` | editor, admin | Replace an allowed file's whole content. OneDrive keeps the earlier version in its version history |
| `onedrive_rename_file(file_id, new_name)` | editor, admin | Rename a file or folder inside an allowed folder. An item allowed directly keeps its name |

`parent_id` may be left out only when exactly one OneDrive folder is allowed. Content is capped at
`MAX_BYTES`. Names can't contain control characters or any of `" * : < > ? / \ | % #`, and OneDrive's
reserved names (`CON`, `desktop.ini`, `~$…`, …) are refused. A replace or rename is conditional on the
version that was checked (`If-Match`), so a change made meanwhile answers `onedrive_changed` instead of
being written over.

The tools are registered only when OneDrive is configured on the server. An item that is not allowed and one
that does not exist get the same `onedrive_not_allowed` answer.

## Set it up (operator)

1. In [Microsoft Entra](https://entra.microsoft.com), open **Applications → App registrations → New
   registration**.
   - **Supported account types:** "Accounts in any organizational directory and personal Microsoft
     accounts".
   - **Redirect URI:** platform **Web**, `<APP_BASE_URL>/connect/onedrive/callback`.
2. **API permissions:** Microsoft Graph, delegated: `Files.ReadWrite`, `User.Read`, `offline_access`. Keep
   `Files.Read` too if it is already there (connections made before writing existed use it). Nothing else,
   and never an `.All` permission: a token that carries more (for example `Files.ReadWrite.All` granted by
   an organization admin) is refused and not stored.
3. **Certificates & secrets:** create a client secret and note when it expires.
4. Set `ONEDRIVE_OAUTH_CLIENT_ID` and `ONEDRIVE_OAUTH_CLIENT_SECRET` and redeploy. A value starting with
   `REPLACE` counts as unset.

OneDrive appears on **Settings → Services** once both are set.

### School and work accounts

Many organizations don't let people approve third-party apps themselves. The person then sees "Your
organization has to approve Bot RBAC" and their IT administrator has to grant consent for the organization,
for example with `https://login.microsoftonline.com/<tenant>/adminconsent?client_id=<client id>`. Microsoft
also usually blocks unverified multitenant apps for users of other organizations, so complete **publisher
verification** (Branding & properties, with a Microsoft AI Cloud Partner Program ID) before offering
OneDrive to schools. Personal Microsoft accounts need neither. An organization that lets people approve apps themselves only for
low-risk permissions may allow `Files.Read` but not `Files.ReadWrite`; new connections there then need the
administrator's consent too. Connections already made keep reading.

# OneDrive

OneDrive is an optional connection, next to Google Drive. Assistants can **read** the OneDrive files and
folders a person allows. They cannot edit OneDrive.

## How access works

Microsoft has no per-file permission for personal accounts, so Bot RBAC asks for `Files.Read`, which lets the
server read the person's whole OneDrive. What assistants may read is held to **Bot RBAC's OneDrive
allowlist**: on **Files → From OneDrive**, the person browses their drive and chooses **Allow** on files and
folders. Everything inside an allowed folder is included, like a file in an allowed Drive folder.

- The top of the drive can't be allowed, so the whole drive is never shared by one click.
- Shortcuts to other people's items ("Add to my files") are not listed or followed.
- A file moved out of an allowed folder stops being readable; so does everything in an allowed folder that
  is deleted.
- Disconnecting OneDrive deletes the token and clears the list. Connecting a different Microsoft account
  clears the list too.

Microsoft has no way for this kind of app to revoke a token. To remove the permission at Microsoft as well,
the person goes to account.live.com/consent/Manage (personal account) or myapps.microsoft.com (work or
school account). The dashboard says so when they disconnect.

## Tools

| Tool | What it does |
|---|---|
| `onedrive_list_folder(folder_id?)` | No folder: the allowed files and folders. A folder: its contents, when it is allowed or inside one |
| `onedrive_read_file(file_id)` | Text of an allowed file (same formats as `read_file`: Word, PDF, PowerPoint, Excel, RTF, text) |
| `onedrive_download_file(file_id)` | Size-capped base64 of an allowed file |
| `onedrive_search(query, max_results?)` | Microsoft's search (names and content) inside each allowed folder; an allowed single file is matched by name |

All four are read-only and available to every app role. They are registered only when OneDrive is
configured on the server. An item that is not allowed and one that does not exist get the same
`onedrive_not_allowed` answer.

## Set it up (operator)

1. In [Microsoft Entra](https://entra.microsoft.com), open **Applications → App registrations → New
   registration**.
   - **Supported account types:** "Accounts in any organizational directory and personal Microsoft
     accounts".
   - **Redirect URI:** platform **Web**, `<APP_BASE_URL>/connect/onedrive/callback`.
2. **API permissions:** Microsoft Graph, delegated: `Files.Read`, `User.Read`, `offline_access`. Nothing else.
   A token that carries more (for example `Files.Read.All` granted by an organization admin) is refused and
   not stored.
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
OneDrive to schools. Personal Microsoft accounts need neither.

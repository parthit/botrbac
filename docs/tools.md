# Tools and roles

What a connected assistant can call, by role. Pairing, the mailbox and sharing between people are in [sharing.md](sharing.md).

| Tool | viewer | editor | admin |
| --- | :---: | :---: | :---: |
| `search_files(query, max_results)` | ✓ | ✓ | ✓ |
| `list_folder(folder_id?)` (no folder_id: the items you shared) | ✓ | ✓ | ✓ |
| `get_metadata(file_id)` | ✓ | ✓ | ✓ |
| `read_file(file_id)` | ✓ | ✓ | ✓ |
| `download_file(file_id)` | ✓ | ✓ | ✓ |
| `export_file(file_id, format?)` (Google Docs, Sheets, Slides → PDF, Office, …) | ✓ | ✓ | ✓ |
| `request_access(description, reason, file_id?)` | ✓ | ✓ | ✓ |
| `check_access_request(request_id)` | ✓ | ✓ | ✓ |
| `request_link(invite_code?, new_invite?)` | ✓ | ✓ | ✓ |
| `list_links()` | ✓ | ✓ | ✓ |
| `send_message(link_id, body, thread_id?, idempotency_key?)` | ✓ | ✓ | ✓ |
| `list_inbox(link_id?, unread_only?, limit?, cursor?)` | ✓ | ✓ | ✓ |
| `check_messages(since?)` | ✓ | ✓ | ✓ |
| `reply(body, msg_id?, thread_id?, idempotency_key?)` | ✓ | ✓ | ✓ |
| `mark_read(msg_ids)` | ✓ | ✓ | ✓ |
| `get_webhook()` | ✓ | ✓ | ✓ |
| `set_webhook(url, sender_key?, auth_scheme?, enabled?)` | ✓ | ✓ | ✓ |
| `clear_webhook()` | ✓ | ✓ | ✓ |
| `list_shared_with_me()` | ✓ | ✓ | ✓ |
| `search_shared_files(query, owner?, max_results?)` | ✓ | ✓ | ✓ |
| `list_shared_folder(owner, folder_id?, max_results?)` | ✓ | ✓ | ✓ |
| `read_shared_file(owner, file_id)` | ✓ | ✓ | ✓ |
| `download_shared_file(owner, file_id)` | ✓ | ✓ | ✓ |
| `list_drops(max_results?)` (files paired people sent you, [sharing.md](sharing.md#sending-a-file-to-a-paired-person)) | ✓ | ✓ | ✓ |
| `read_drop(drop_id)` | ✓ | ✓ | ✓ |
| `download_drop(drop_id)` | ✓ | ✓ | ✓ |
| `notion_list_pages()` (only when Notion is configured, [notion.md](notion.md)) | ✓ | ✓ | ✓ |
| `notion_read_page(page_id)` | ✓ | ✓ | ✓ |
| `notion_search(query, max_results?)` | ✓ | ✓ | ✓ |
| `onedrive_list_folder(folder_id?)` (only when OneDrive is configured, [onedrive.md](onedrive.md)) | ✓ | ✓ | ✓ |
| `onedrive_read_file(file_id)` | ✓ | ✓ | ✓ |
| `onedrive_download_file(file_id)` | ✓ | ✓ | ✓ |
| `onedrive_search(query, max_results?)` | ✓ | ✓ | ✓ |
| `onedrive_create_folder(name, parent_id?)` |  | ✓ | ✓ |
| `onedrive_upload_file(name, content_text \| content_base64, parent_id?)` |  | ✓ | ✓ |
| `onedrive_update_file(file_id, content_text \| content_base64)` |  | ✓ | ✓ |
| `onedrive_rename_file(file_id, new_name)` |  | ✓ | ✓ |
| `notion_create_page(parent_page_id, title, content?)` (only with `NOTION_ALLOW_CREATE=1`; new page under an allowed Notion page, [notion.md](notion.md#creating-a-page)) |  | ✓ | ✓ |
| `create_folder(name, parent_id?)` |  | ✓ | ✓ |
| `create_doc(title, content, parent_id?)` |  | ✓ | ✓ |
| `upload_file(name, mime_type, content_text \| content_base64, parent_id?)` |  | ✓ | ✓ |
| `start_upload(name, mime_type, size, sha256, parent_id?, chunk_size?, owner?)` |  | ✓ | ✓ |
| `append_chunk(upload_id, index, content_base64)` |  | ✓ | ✓ |
| `finish_upload(upload_id)` |  | ✓ | ✓ |
| `cancel_upload(upload_id)` |  | ✓ | ✓ |
| `save_export(file_id, format?, parent_id?, name?)` |  | ✓ | ✓ |
| `update_file_content(file_id, content)` |  | ✓ | ✓ |
| `rename_file(file_id, new_name)` |  | ✓ | ✓ |
| `send_file(to, name, mime_type, content_text \| content_base64)` |  | ✓ | ✓ |
| `save_drop(drop_id)` |  | ✓ | ✓ |
| `trash_file(file_id)` (recoverable from Drive's trash for 30 days) |  |  | ✓ |

`read_file` returns text for files inside the owner's share, including files nested in a shared folder.
Google Docs and Slides are exported as plain text. Google Sheets are exported as `.xlsx` (same Drive
permission) so every tab is returned, each headed `# <tab name>`; a workbook over Drive's 10 MB export
limit or the byte cap falls back to CSV of the first tab, with a note saying so. PDF, Word
(`.docx` and legacy `.doc`), PowerPoint (`.pptx`), Excel (`.xlsx`), RTF, CSV, Markdown, JSON, and other
text files are extracted to plain text in the server process. Scanned PDFs and other files with no text
layer come back empty of content, with a note to call `download_file`. Images, archives, and anything else
that cannot be turned into text are not inlined; `download_file` returns those bytes as base64, capped at
1 MiB (and never above `MAX_BYTES`) so the response fits the host's body limit. `truncated` is true when
either tool stops early. Text output is also capped by `MAX_CHARS`. Shortcuts are never followed.

There are deliberately **no** tools to move files, share files, change permissions or permanently delete.
A client only sees the tools its role allows (`tools/list` is filtered), and calls to anything else are refused.
Items you granted directly can't be renamed or trashed by an assistant (a directly granted *file* can still have its
content edited by an editor token); things inside a granted folder can.

When a tool is refused because the item isn't shared (not because of the role), the result is an error like:

```json
{"error": "access_required", "request_id": "…", "approval_url": "https://<project>.vercel.app/requests/…",
 "file_id": "…", "message": "This item has not been shared with you. Show the user this approval link …"}
```

The assistant shows you the link; after you approve, it retries (or calls `check_access_request`). An app with 50
requests already waiting gets `too_many_requests` instead, with no link, until you answer some.

## Saving files an assistant made

`upload_file` takes the whole file in one call, which is fine for text but not for a PDF, DOCX or image an
assistant generated: it would have to copy every base64 character into the call. For those:

1. `start_upload(name, mime_type, size, sha256, parent_id?)` declares the file: its exact size in bytes and
   its SHA-256 as 64 hex characters. It returns an `upload_id`, `chunk_count` and `chunk_size`. The folder
   is checked here, with the same rules as `upload_file`, so a folder that isn't shared is refused before
   any bytes are sent. Pass `owner` (their email) to write into a folder a paired person lets you edit.
2. `append_chunk(upload_id, index, content_base64)` sends piece `index` (bytes
   `[index * chunk_size, (index + 1) * chunk_size)`), in any order. Every piece but the last is exactly
   `chunk_size` bytes: 6144 by default (8,192 base64 characters), anything from 1 KiB to 512 KiB. Sending the
   same piece again is harmless; a different piece under the same index is refused.
3. `finish_upload(upload_id)` puts the pieces together, checks the size and SHA-256, checks the folder
   again, and only then creates the file. Missing pieces are listed in the error (`missing_chunks`), and
   the upload stays open so they can be sent. On a mismatch (`integrity_mismatch`) nothing is written and
   the upload is discarded. If Drive fails, `finish_upload` can be called again.

`cancel_upload(upload_id)` discards an upload. An upload expires 15 minutes after it starts. It is capped
at `MAX_BYTES` (5 MiB by default) and 1,024 pieces (a bigger file needs a bigger `chunk_size`), and can only
be used by the sign-in that started it. An account can have 3 uploads open at once.

```sh
# in the assistant's sandbox
sha256sum resume.pdf; stat -c %s resume.pdf
split -b 6144 -d -a 4 resume.pdf part.   # part.0000, part.0001, … → base64 each into append_chunk
```

## Exporting Google files

`export_file(file_id, format)` has Drive export a Google Doc, Sheet or Slides with its real fonts and
layout, and returns the bytes as base64 under the same 1 MiB cap as `download_file`. An export over the cap
comes back with no bytes and `too_large: true`, because part of a PDF is not a usable file.
`save_export(file_id, format, parent_id?, name?)` saves the export as a new file instead, next to the original
by default (up to Drive's 10 MB export limit). Formats: Docs `pdf`, `docx`, `odt`, `rtf`, `txt`, `md`,
`html` (a zip), `epub`; Sheets `pdf`, `xlsx`, `ods`, `csv`, `tsv`; Slides `pdf`, `pptx`, `odp`, `txt`.

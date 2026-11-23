# Tools and roles

What a connected assistant can call, by role. Pairing, the mailbox and sharing between people are in [sharing.md](sharing.md).

| Tool | viewer | editor | admin |
| --- | :---: | :---: | :---: |
| `search_files(query, max_results)` | ✓ | ✓ | ✓ |
| `list_folder(folder_id?)` (no folder_id: the items you shared) | ✓ | ✓ | ✓ |
| `get_metadata(file_id)` | ✓ | ✓ | ✓ |
| `read_file(file_id)` | ✓ | ✓ | ✓ |
| `download_file(file_id)` | ✓ | ✓ | ✓ |
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
| `create_folder(name, parent_id?)` |  | ✓ | ✓ |
| `create_doc(title, content, parent_id?)` |  | ✓ | ✓ |
| `upload_file(name, mime_type, content_text \| content_base64, parent_id?)` |  | ✓ | ✓ |
| `update_file_content(file_id, content)` |  | ✓ | ✓ |
| `rename_file(file_id, new_name)` |  | ✓ | ✓ |
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

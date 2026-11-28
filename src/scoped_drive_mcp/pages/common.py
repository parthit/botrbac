"""Constants and small pure helpers the page modules share with dashboard.py.

Nothing here imports dashboard.py, so both it and the page modules can import this.
Values that tests patch on dashboard.py (BROWSE_PAGE_SIZE, SEARCH_LOOKUPS,
SHARED_SEARCH_LIMIT) stay there and reach the pages through the Kit.
"""

import re
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from typing import Any
from urllib.parse import quote, urlencode

from ..drive_client import FOLDER_MIME, SHORTCUT_MIME, DriveNotFoundError
from ..drop_storage import PIECE_BYTES
from ..grants import OWNER_FIELDS

SESSION_MAX_AGE = 8 * 3600
STATE_MAX_AGE = 600

ACTIVITY_PAGE = 50
# Drive lookups for names the activity page cannot find in the person's own lists.
ACTIVITY_LOOKUPS = 10
MAX_BREADCRUMBS = 25

_LOGIN_HINT = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Files sent from the dashboard. Vercel refuses request bodies over 4.5 MB, so the form
# stays under it; an assistant's send_file has the larger MAX_BYTES limit.
DROP_UPLOAD_LIMIT = 4_000_000
DROP_UPLOAD_MB = DROP_UPLOAD_LIMIT // 1_000_000
# Room for the form's other fields and the multipart framing around the file.
DROP_FORM_OVERHEAD = 64_000
# With JavaScript, the page sends a larger file in pieces of this size (drop_storage), one
# request each, so every request stays under Vercel's 4.5 MB limit.
DROP_PIECE_LIMIT = PIECE_BYTES
# Files listed under "Sent to you" on the Shared with me page.
DROPS_SHOWN = 50

# Name matches shown for one Browse search. More than this and the page says to narrow it.
SEARCH_PAGE = 100
# Item ids in "Shared with me" links. Drive ids fit; other sources must too.
_SHARED_ID = re.compile(r"[A-Za-z0-9_.:\-]{1,200}")


class OwnerNotConnectedError(Exception):
    """Signed in, but Google Drive is not connected yet (send them to /connect)."""


# Drive lookups a page makes side by side (the Allowed tab's folder checks). One pool for
# the process, so its threads and their Drive connections are reused between requests.
DRIVE_LOOKUP_WORKERS = 8
_drive_pool = ThreadPoolExecutor(DRIVE_LOOKUP_WORKERS, thread_name_prefix="drive-lookup")


def fetch_parents(drive: Any, ids: list[str]) -> dict[str, dict[str, Any] | None | Exception]:
    """files.get("id,parents") for each id, in parallel. None for not found, else the
    error a lookup raised, so one failure does not lose the other answers."""

    def one(fid: str) -> dict[str, Any] | None | Exception:
        try:
            return drive.get_file(fid, fields="id,parents")
        except DriveNotFoundError:
            return None
        except Exception as exc:
            return exc

    if len(ids) == 1:
        return {ids[0]: one(ids[0])}
    return dict(zip(ids, _drive_pool.map(one, ids), strict=True))


WAKE_HOME = "/settings#assistants"
LIST_FIELDS = OWNER_FIELDS + ",modifiedTime"
COVER_CHECK_LIMIT = 25
# The action bar on Files and Sharing. Each item is one Drive lookup at most, run in turn,
# so a batch stays well inside one function call.
BATCH_ACTIONS = ("allow", "remove", "share", "unshare", "forget")
BATCH_LIMIT = 50
# How each app role is named on the consent page and in Settings.
ROLE_LABELS = {
    "viewer": "Read only",
    "editor": "Read and edit",
    "admin": "Full (read, edit and trash)",
}


def _end_of_day(day: str) -> str | None:
    """A date from the Sharing form ("2026-12-31") as the last second of that day, UTC,
    in the same ISO form as utc_now() so the two compare as strings."""
    day = day.strip()
    if not day:
        return None
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", day):
        raise ValueError(day)
    date.fromisoformat(day)
    return f"{day}T23:59:59+00:00"


def _dupes(rows: list[dict[str, Any]]) -> set[str]:
    seen: dict[str, int] = {}
    for row in rows:
        key = str(row.get("name") or "").strip().casefold()
        seen[key] = seen.get(key, 0) + 1
    return {name for name, n in seen.items() if n > 1}


def icon_kind(mime: str) -> str:
    """Which small icon a row gets: folder, doc, sheet, slides, pdf, image, video, file."""
    if mime == FOLDER_MIME:
        return "folder"
    if mime == SHORTCUT_MIME:
        return "shortcut"
    if mime.endswith(".document") or "wordprocessing" in mime or mime == "application/msword":
        return "doc"
    if (
        mime.endswith(".spreadsheet")
        or "spreadsheetml" in mime
        or mime
        in (
            "application/vnd.ms-excel",
            "text/csv",
        )
    ):
        return "sheet"
    if mime.endswith(".presentation") or "presentationml" in mime or "powerpoint" in mime:
        return "slides"
    if mime == "application/pdf":
        return "pdf"
    if mime.startswith("image/"):
        return "image"
    if mime.startswith("video/"):
        return "video"
    return "file"


def normalize_page_token(value: str | None) -> str | None:
    """Keep an opaque Drive page token.

    Google's tokens are not a fixed alphabet (`~`, `!`, `*`, `|` all show up).
    Drop only blank, huge, or control-character values so a real Next link
    still addresses the same page.
    """
    if not value or len(value) > 1024:
        return None
    if any(ord(ch) < 33 or ord(ch) == 127 for ch in value):
        return None
    return value


def browse_href(
    folder: str,
    *,
    q: str | None,
    request_id: str | None,
    page: str | None,
    prev: list[str],
) -> str:
    pairs: list[tuple[str, str]] = []
    if q:
        pairs.append(("q", q))
    else:
        pairs.append(("folder", folder or "root"))
        if page:
            pairs.append(("page", page))
        for item in prev:
            pairs.append(("prev", item))
    if request_id:
        pairs.append(("request", request_id))
    return "/files?" + urlencode(pairs)


def browse_pager(
    folder: str,
    *,
    q: str | None,
    request_id: str | None,
    page: str | None,
    prev: list[str],
    next_token: str | None,
) -> dict[str, str | None]:
    """Previous/Next links. Drive tokens are not reversible, so the previous stack is in the URL."""
    prev_href = None
    if page and not q:
        if prev:
            prev_href = browse_href(
                folder, q=None, request_id=request_id, page=prev[-1], prev=prev[:-1]
            )
        else:
            prev_href = browse_href(folder, q=None, request_id=request_id, page=None, prev=[])
    next_href = None
    if next_token and not q:
        nxt_prev = [*prev, page] if page else list(prev)
        next_href = browse_href(
            folder, q=None, request_id=request_id, page=next_token, prev=nxt_prev
        )
    return {"prev_href": prev_href, "next_href": next_href}


def shared_href(view: str, source: str, owner: str, item_id: str | None = None) -> str:
    """Link inside "Shared with me". view is "browse", "open" or "download"."""
    pairs = [("source", source), ("owner", owner)]
    if item_id:
        pairs.append(("id", item_id))
    return f"/shared/{view}?" + urlencode(pairs)


def attachment_disposition(filename: str) -> str:
    """Content-Disposition for a download. The name was typed by another person."""
    cleaned = (
        "".join(
            ch for ch in filename if ord(ch) >= 32 and ord(ch) != 127 and ch not in '"\\/;'
        ).strip()[:200]
        or "download"
    )
    ascii_name = cleaned.encode("ascii", "ignore").decode("ascii").strip() or "download"
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(cleaned, safe='')}"


def describe_mime(mime: str) -> str:
    known = {
        FOLDER_MIME: "Folder",
        "onedrive/folder": "Folder",
        "onedrive/package": "Notebook",
        SHORTCUT_MIME: "Shortcut",
        "application/vnd.google-apps.document": "Google Doc",
        "application/vnd.google-apps.spreadsheet": "Google Sheet",
        "application/vnd.google-apps.presentation": "Google Slides",
        "application/vnd.google-apps.form": "Google Form",
        "application/vnd.google-apps.drawing": "Google Drawing",
        "application/pdf": "PDF",
        "application/msword": "Word",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "Word",
        "application/vnd.ms-excel": "Excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "Excel",
        "application/vnd.ms-powerpoint": "PowerPoint",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation": "PowerPoint",
        "application/rtf": "Rich text",
        "application/zip": "ZIP",
        "application/json": "JSON",
        "text/csv": "CSV",
    }
    if mime in known:
        return known[mime]
    if mime.startswith("image/"):
        return "Image"
    if mime.startswith("text/"):
        return "Text"
    if mime.startswith("video/"):
        return "Video"
    if mime.startswith("audio/"):
        return "Audio"
    sub = mime.rsplit("/", 1)[-1]
    # Vendor types like "vnd.foo.bar-baz" mean nothing to a person and break narrow layouts.
    return sub if sub and len(sub) <= 16 and not sub.startswith(("vnd.", "x-")) else "File"

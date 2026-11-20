"""Plain-language views for the dashboard: timestamps, assistant names, activity records.

Nothing here reads the store or Drive. The dashboard gathers names (from the person's own
lists and requests) and passes them in, so the audit log itself still holds only ids.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from markupsafe import Markup

from .mcp_oauth import principal_name

# ---- time ------------------------------------------------------------------------


def parse_ts(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def readable_utc(moment: datetime) -> str:
    """ "Nov 19, 2026, 23:58 UTC": shown until ui.js switches it to the reader's time zone."""
    return f"{moment:%b} {moment.day}, {moment.year}, {moment:%H:%M} UTC"


def when(value: Any, empty: str = "—", date_only: bool = False) -> Markup:
    """A <time> element for a stored ISO timestamp. ui.js turns it into local or relative
    time (or a local calendar date with `date_only`); without JavaScript the readable UTC
    text stays."""
    moment = parse_ts(value)
    if moment is None:
        return Markup("{}").format(value if isinstance(value, str) and value else empty)
    iso = moment.isoformat(timespec="seconds").replace("+00:00", "Z")
    text = readable_utc(moment)
    if date_only:
        day = f"{moment:%b} {moment.day}, {moment.year}"
        return Markup('<time datetime="{}" data-time="date" title="{}">{}</time>').format(
            iso, text, day
        )
    return Markup('<time datetime="{}" data-time title="{}">{}</time>').format(iso, text, text)


# ---- who -------------------------------------------------------------------------


def app_names(grants: Any) -> dict[str, str]:
    """Activity and requests record an OAuth app as `oauth:<slug>`. Map that back to the
    name the person saw when they chose Allow."""
    names: dict[str, str] = {}
    for grant in grants or []:
        name = str(getattr(grant, "client_name", "") or "").strip()
        if name:
            names.setdefault(principal_name(name), name)
    return names


def assistant_label(token_name: Any, apps: Mapping[str, str] | None = None) -> str:
    """A person-facing name for the connection that made a call or a request."""
    raw = str(token_name or "").strip()
    if not raw:
        return "An assistant"
    if raw.startswith("guest:"):
        guest = raw.removeprefix("guest:")
        if guest.endswith(" (dashboard)"):
            return guest.removesuffix(" (dashboard)")
        return f"{guest}’s assistant"
    if raw.startswith("oauth:"):
        if apps and raw in apps:
            return apps[raw]
        return raw.removeprefix("oauth:").replace("_", " ").strip() or "An assistant"
    if raw.endswith("-tok"):
        role = raw.removesuffix("-tok").replace("_", " ").replace("-", " ").strip()
        return f"Your assistant ({role} token)" if role else "Your assistant"
    return raw


# ---- activity ----------------------------------------------------------------------

# (what it did, what it tried to do). {item} is the item's name, or a plain stand-in.
_TOOL_TEXT: dict[str, tuple[str, str]] = {
    "read_file": ("read {item}", "read {item}"),
    "download_file": ("downloaded {item}", "download {item}"),
    "get_metadata": ("looked at the details of {item}", "look at {item}"),
    "list_folder": ("opened {item}", "open {item}"),
    "search_files": ("searched your allowed files", "search your files"),
    "create_folder": ("created a folder in {item}", "create a folder in {item}"),
    "create_doc": ("created a document in {item}", "create a document in {item}"),
    "upload_file": ("uploaded a file to {item}", "upload a file to {item}"),
    "update_file_content": ("edited {item}", "edit {item}"),
    "rename_file": ("renamed {item}", "rename {item}"),
    "trash_file": ("moved {item} to the trash", "move {item} to the trash"),
    "request_access": ("asked for access to {item}", "ask for access to {item}"),
    "check_access_request": ("checked on an access request", "check on an access request"),
    "request_link": ("started a mailbox pairing", "start a mailbox pairing"),
    "list_links": ("checked its mailbox pairings", "check its mailbox pairings"),
    "send_message": ("sent a mailbox message", "send a mailbox message"),
    "reply": ("replied to a mailbox message", "reply to a mailbox message"),
    "list_inbox": ("read its mailbox", "read its mailbox"),
    "check_messages": ("checked for new mailbox messages", "check for new messages"),
    "mark_read": ("marked mailbox messages as read", "mark messages as read"),
    "get_webhook": ("checked its wake-up setting", "check its wake-up setting"),
    "set_webhook": ("changed its wake-up setting", "change its wake-up setting"),
    "clear_webhook": ("removed its wake-up setting", "remove its wake-up setting"),
    "list_shared_with_me": (
        "looked at what people share with you",
        "look at what people share with you",
    ),
    "search_shared_files": (
        "searched files people share with you",
        "search files people share with you",
    ),
    "list_shared_folder": ("opened {item}", "open {item}"),
    "read_shared_file": ("read {item}", "read {item}"),
    "download_shared_file": ("downloaded {item}", "download {item}"),
}

# The assistant asking "anything new?" on a timer. Hidden unless asked for.
POLLING_TOOLS = frozenset(
    {"check_access_request", "check_messages", "list_inbox", "list_links", "get_webhook"}
)
_FOLDER_TOOLS = frozenset(
    {"list_folder", "create_folder", "create_doc", "upload_file", "list_shared_folder"}
)
_ID_FIELDS = ("file_id", "folder_id", "parent_id")
# A `names` value meaning "the person's Drive has no such item" (looked up, not found).
MISSING = "\x00missing"


@dataclass(frozen=True)
class Badge:
    tone: str  # ok | bad | pending | "" (neutral)
    label: str
    mark: str


_ALLOWED = Badge("ok", "Allowed", "✓")
_BLOCKED = Badge("bad", "Blocked", "!")
_FAILED = Badge("bad", "Failed", "!")
_DONE = Badge("", "Done", "✓")


@dataclass(frozen=True)
class ActivityRow:
    ts: str
    who: str
    text: str
    badge: Badge
    group: str  # you | assistant | people | security
    attention: bool
    polling: bool
    detail: str


def _item_id(record: Mapping[str, Any]) -> str | None:
    for key in _ID_FIELDS:
        value = record.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _quoted(name: str) -> str:
    return f"“{name}”"


def _item_text(
    record: Mapping[str, Any],
    names: Mapping[str, str],
    request_names: Mapping[str, str],
    tool: str = "",
) -> str:
    item = _item_id(record)
    if item and names.get(item) == MISSING:
        kind = "a folder" if tool in _FOLDER_TOOLS else "a file"
        return f"{kind} that isn\u2019t in your Drive"
    if item and names.get(item):
        return _quoted(names[item])
    rid = record.get("request_id")
    if isinstance(rid, str) and request_names.get(rid):
        return _quoted(request_names[rid])
    if tool == "list_folder" and not item:
        return "the items you allowed"
    if tool == "request_access" and not item:
        return "something in your Drive"
    if tool in _FOLDER_TOOLS:
        return "a folder"
    return "a file" if item or tool else "an item"


def _deny_why(reason: str, guest: bool) -> str:
    if reason in ("out_of_scope",):
        return "it isn’t on your list"
    if reason == "not_shared":
        return "it isn’t on your Sharing list"
    if reason.startswith("role ") or "may not call" in reason:
        return "that connection isn’t allowed to do that"
    if guest:
        return "it isn’t shared"
    return "it isn’t allowed"


def _error_why(reason: str) -> str:
    if reason in ("bot_not_connected", "owner_not_signed_in"):
        return "Google Drive isn’t connected"
    if reason in ("invalid_input",) or reason.startswith(("file_id", "folder_id", "parent_id")):
        return "the request was not valid"
    return "Google Drive returned an error"


def _tool_row(
    record: Mapping[str, Any],
    names: Mapping[str, str],
    request_names: Mapping[str, str],
    apps: Mapping[str, str],
) -> ActivityRow:
    tool = str(record.get("tool") or "")
    decision = str(record.get("decision") or "")
    reason = str(record.get("reason") or "")
    guest = record.get("role") == "guest" or str(record.get("token_name") or "").startswith(
        "guest:"
    )
    via_dashboard = record.get("via") == "dashboard"
    who = assistant_label(record.get("token_name"), apps)
    done, attempt = _TOOL_TEXT.get(tool, ("used {item}", "use {item}"))
    item = _item_text(record, names, request_names, tool)
    owner = record.get("owner")
    if isinstance(owner, str) and owner and not guest:
        # A shared tool on the reader's own log: the item is someone else's.
        item = "a folder" if tool == "list_shared_folder" else "a file"
        item = f"{item} {owner} shares with you"
    elif guest and decision == "allow":
        item = f"{item} from your Sharing list"
    if via_dashboard and guest:
        done = done.replace("its ", "their ")
    polling = tool in POLLING_TOOLS and decision == "allow"
    missing = names.get(_item_id(record) or "") == MISSING
    if tool == "request_access" and decision == "allow":
        text = f"{who} {done.format(item=item)}."
        badge = Badge("pending", "Asked", "\u25cf")
    elif decision == "allow":
        text = f"{who} {done.format(item=item)}."
        badge = _ALLOWED
    elif decision == "deny" and missing:
        text = f"{who} tried to {attempt.format(item=item)}."
        badge = _BLOCKED
    elif decision == "deny":
        text = f"{who} tried to {attempt.format(item=item)}. Blocked: {_deny_why(reason, guest)}."
        badge = _BLOCKED
    else:
        text = f"{who} couldn’t {attempt.format(item=item)}: {_error_why(reason)}."
        badge = _FAILED
    item_id = _item_id(record)
    detail = " · ".join(part for part in (tool, f"id {item_id}" if item_id else "", reason) if part)
    return ActivityRow(
        ts=str(record.get("ts") or ""),
        who=who,
        text=text,
        badge=badge,
        group="people" if guest else "assistant",
        attention=decision in ("deny", "error"),
        polling=polling,
        detail=detail,
    )


def _owner_row(
    record: Mapping[str, Any],
    names: Mapping[str, str],
    request_names: Mapping[str, str],
) -> ActivityRow:
    action = str(record.get("action") or "")
    decision = str(record.get("decision") or "allow")
    reason = str(record.get("reason") or "")
    item = _item_text(record, names, request_names)
    client = str(record.get("client") or "an app")
    texts: dict[str, tuple[str, Badge]] = {
        "login": ("You signed in.", _DONE),
        "logout": ("You signed out.", _DONE),
        "connect": ("You connected Google Drive.", Badge("ok", "Connected", "✓")),
        "disconnect": ("You disconnected Google Drive.", Badge("", "Disconnected", "–")),
        "grant": (f"You allowed {item} for your assistant.", _ALLOWED),
        "revoke": (
            f"You removed {item} from your assistant’s list.",
            Badge("", "Removed", "–"),
        ),
        "share_external": (
            f"You shared {item} with people you are paired with.",
            Badge("ok", "Shared", "✓"),
        ),
        "unshare_external": (
            f"You stopped sharing {item}.",
            Badge("", "Stopped sharing", "–"),
        ),
        "approve_request": (
            f"You approved a request for {item}.",
            Badge("ok", "Approved", "✓"),
        ),
        "deny_request": (f"You denied a request for {item}.", Badge("bad", "Denied", "✕")),
        "oauth_approve": (f"You connected {client}.", Badge("ok", "Connected", "✓")),
        "oauth_deny": (f"You declined to connect {client}.", Badge("bad", "Declined", "✕")),
        "oauth_revoke": ("You disconnected an app.", Badge("", "Disconnected", "–")),
        "share_all": ("You shared your allowed items with the bot account.", _DONE),
    }
    group = "you"
    if decision == "deny":
        group = "security"
        refused = {
            "login": "A sign-in was refused: that Google account isn’t allowed here.",
            "connect": (
                "Connecting Google Drive was refused: Google returned a different account."
            ),
            "csrf": "A form was refused because it didn’t come from this site.",
        }
        text = refused.get(action, f"Refused: {action.replace('_', ' ')}.")
        badge = _BLOCKED
    elif decision == "error":
        failed = {
            "grant": f"Allowing {item} failed: Google Drive returned an error.",
            "revoke": f"Removing {item} only partly worked: Google Drive returned an error.",
        }
        text = failed.get(action, f"Something failed: {action.replace('_', ' ')}.")
        badge = _FAILED
    else:
        text, badge = texts.get(action, (f"You: {action.replace('_', ' ')}.", _DONE))
    item_id = _item_id(record)
    detail = " · ".join(
        part for part in (action, f"id {item_id}" if item_id else "", reason) if part
    )
    return ActivityRow(
        ts=str(record.get("ts") or ""),
        who="You",
        text=text,
        badge=badge,
        group=group,
        attention=decision in ("deny", "error"),
        polling=False,
        detail=detail,
    )


def describe(
    record: Mapping[str, Any],
    names: Mapping[str, str] | None = None,
    request_names: Mapping[str, str] | None = None,
    apps: Mapping[str, str] | None = None,
) -> ActivityRow:
    """One audit record as a sentence a person can read."""
    names = names or {}
    request_names = request_names or {}
    event = record.get("event")
    if event == "tool_call":
        return _tool_row(record, names, request_names, apps or {})
    if event == "owner":
        return _owner_row(record, names, request_names)
    if event == "auth":
        return ActivityRow(
            ts=str(record.get("ts") or ""),
            who="Unknown app",
            text="An app tried to connect with a missing, wrong or expired key.",
            badge=_BLOCKED,
            group="security",
            attention=True,
            polling=False,
            detail=str(record.get("reason") or ""),
        )
    return ActivityRow(
        ts=str(record.get("ts") or ""),
        who="",
        text="Something happened.",
        badge=_DONE,
        group="you",
        attention=False,
        polling=False,
        detail=str(event or ""),
    )


ACTIVITY_FILTERS: dict[str, str] = {
    "all": "All",
    "attention": "Needs attention",
    "assistant": "Assistants",
    "you": "Your changes",
}


def matches(row: ActivityRow, view: str, show_polling: bool) -> bool:
    if row.polling and not show_polling:
        return False
    if view == "attention":
        return row.attention
    if view == "assistant":
        return row.group in ("assistant", "people")
    if view == "you":
        return row.group == "you"
    return True


def item_ids(records: list[Mapping[str, Any]]) -> list[str]:
    """Ids from the person's own Drive that a page of records mentions (not other people's
    shared items, which carry `owner`)."""
    seen: list[str] = []
    for record in records:
        if record.get("owner"):
            continue
        item = _item_id(record)
        if item and item not in seen:
            seen.append(item)
    return seen

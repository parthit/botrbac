"""Plain-language views for the dashboard: timestamps, assistant names, activity records.

Nothing here reads the store or Drive. The dashboard gathers names (from the person's own
lists and requests) and passes them in, so the audit log itself still holds only ids.
"""

import re
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
    name the person gave it, or else the name they saw when they chose Allow. The key comes
    from the registered name, which a rename does not change."""
    names: dict[str, str] = {}
    for grant in grants or []:
        name = str(getattr(grant, "client_name", "") or "").strip()
        registered = str(getattr(grant, "app_name", "") or "").strip() or name
        if name:
            names.setdefault(principal_name(registered), name)
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
    "request_link": ("started a pairing", "start a pairing"),
    "list_links": ("checked its pairings", "check its pairings"),
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
    "notion_list_pages": ("listed your allowed Notion pages", "list your Notion pages"),
    "notion_read_page": ("read a Notion page", "read a Notion page"),
    "notion_search": ("searched your allowed Notion pages", "search your Notion pages"),
    "create_shared_doc": ("created a doc in {item}", "create a doc in {item}"),
    "create_shared_folder": ("created a folder in {item}", "create a folder in {item}"),
    "upload_shared_file": ("uploaded a file to {item}", "upload a file to {item}"),
    "update_shared_file": ("edited {item}", "edit {item}"),
    "rename_shared_file": ("renamed {item}", "rename {item}"),
    "read_shared_file": ("read {item}", "read {item}"),
    "download_shared_file": ("downloaded {item}", "download {item}"),
}

# The assistant asking "anything new?" on a timer. Hidden unless asked for.
POLLING_TOOLS = frozenset(
    {"check_access_request", "check_messages", "list_inbox", "list_links", "get_webhook"}
)
_FOLDER_TOOLS = frozenset(
    {
        "list_folder",
        "create_folder",
        "create_doc",
        "upload_file",
        "list_shared_folder",
        "create_shared_doc",
        "create_shared_folder",
        "upload_shared_file",
    }
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
    if reason == "not_linked":
        return "they aren’t paired with you"
    if reason == "own_drive":
        return "that is this account’s own Drive (use the normal tools)"
    if reason == "invalid_input":
        return "the request was not valid"
    if reason.startswith("role ") or "may not call" in reason:
        return "that connection isn’t allowed to do that"
    if guest:
        return "it isn’t shared"
    return "it isn’t allowed"


# Error codes from the mailbox and shared-with-me tools (MailboxError / SharedAccessError
# payloads). These are refusals by this server, not Google Drive failures.
_REFUSALS = {
    "link_revoked": "that pairing is off",
    "link_pending": "that pairing isn’t on yet",
    "peer_mail_off": "assistants of different people can’t message each other",
    "link_expired": "that invite has expired",
    "not_linked": "you aren’t paired with that person",
    "not_paired": "you aren’t paired with that person",
    "invite_not_found": "that invite code wasn’t found",
    "invite_taken": "that invite was already used",
    "already_paired": "you’re already paired with that person",
    "waiting_for_peer": "the other person hasn’t joined yet",
    "rate_limited": "it was sending too much, too fast",
    "message_too_large": "the message was too long",
    "not_shared": "it isn’t shared with you",
    "not_found": "it wasn’t found",
    "webhooks_disabled": "wake-ups are turned off on this server",
    "not_allowed": "that Notion page isn’t allowed",
    "notion_not_connected": "Notion isn’t connected",
    "notion_reconnect": "Notion needs to be connected again",
    "notion_error": "Notion returned an error",
}


def _error_why(reason: str) -> str:
    if reason in ("bot_not_connected", "owner_not_signed_in"):
        return "Google Drive isn’t connected"
    if reason in ("invalid_input",) or reason.startswith(("file_id", "folder_id", "parent_id")):
        return "the request was not valid"
    if reason in _REFUSALS:
        return _REFUSALS[reason]
    if re.fullmatch(r"[a-z]+(_[a-z]+)+", reason):
        # Another stable error code from this server: say so instead of blaming Drive.
        return "this server refused it"
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
    if guest and tool == "list_shared_with_me":
        # On the owner's log: the reader listed what this owner shares with them.
        done, attempt = "listed what you share with them", "list what you share with them"
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


_ROLE_WORDS = {
    "viewer": "read only",
    "editor": "read and edit",
    "admin": "full access",
}


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
    role_words = _ROLE_WORDS.get(str(record.get("role")), "its access")
    notion_name = _quoted(str(record.get("name") or "Untitled"))
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
        "oauth_role": (f"You changed what {client} can do: {role_words}.", _DONE),
        "oauth_rename": (
            f"You renamed {client} to {str(record.get('label') or client)}.",
            _DONE,
        ),
        "share_all": ("You shared your allowed items with the bot account.", _DONE),
        "notion_connect": ("You connected Notion.", Badge("ok", "Connected", "✓")),
        "notion_disconnect": ("You disconnected Notion.", Badge("", "Disconnected", "–")),
        "notion_allow": (
            f"You allowed the Notion page {notion_name} for your assistants.",
            _ALLOWED,
        ),
        "notion_remove": (
            f"You removed the Notion page {notion_name} from your assistants’ list.",
            Badge("", "Removed", "–"),
        ),
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
            # Refused already and nothing for the person to do, so it does not count
            # toward "Needs attention" (these come in bursts and drowned out real items).
            attention=False,
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


def group_repeats(rows: list[ActivityRow]) -> list[tuple[ActivityRow, int]]:
    """Fold back-to-back refused connection attempts ("An app tried to connect…" twelve
    times) into one row, with how many there were. The newest one's time is kept. Other
    rows stay one per event."""
    grouped: list[tuple[ActivityRow, int]] = []
    for row in rows:
        if grouped and row.group == "security":
            last, count = grouped[-1]
            if (last.text, last.badge, last.who) == (row.text, row.badge, row.who):
                grouped[-1] = (last, count + 1)
                continue
        grouped.append((row, 1))
    return grouped


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

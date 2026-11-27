"""What is kept in a person's store: the allowlist, encrypted tokens, the activity log, first
reads and hidden files."""

import hashlib
import json
import logging
from collections.abc import Callable
from dataclasses import asdict, dataclass, field, replace
from typing import Any

from ..auth import current_actor
from .backends import (
    KeyValueStore,
    utc_now,
)
from .keys import (
    ACCESS_EDIT,
    ACCESS_READ,
    ACTIVITY_KEY,
    ACTIVITY_MAX,
    ALLOWLIST_KEY,
    BOT_TOKEN_KEY,
    GUEST_ROW_EVERY,
    NOTION_TOKEN_KEY,
    ONEDRIVE_TOKEN_KEY,
    OWNER_TOKEN_KEY,
)

# One logger name for the whole package, the one `store.py` logged under.
logger = logging.getLogger("scoped_drive_mcp.store")

# ---- allowlist -------------------------------------------------------------


@dataclass(frozen=True)
class AllowEntry:
    id: str
    name: str
    mime_type: str
    permission_id: str | None
    granted_at: str = field(default_factory=utc_now)
    request_id: str | None = None
    # The bot address `permission_id` belongs to; None when no Drive share was made.
    shared_with: str | None = None
    # Only set on external entries: who may read it. AUDIENCE_LINKED (or None, from rows
    # written before audiences existed) is every paired person; a tuple names the people.
    audience: str | tuple[str, ...] | None = None
    # Only on external entries: when this share stops working (ISO UTC), or None.
    expires_at: str | None = None
    # Only on external entries: "read" (default), or "edit" to let the people who can see it
    # have their assistants create, edit and rename inside it (never trash or move).
    access: str = "read"

    def to_json(self) -> str:
        data = asdict(self)
        if isinstance(self.audience, tuple):
            data["audience"] = list(self.audience)
        return json.dumps(data, separators=(",", ":"))

    @property
    def for_everyone(self) -> bool:
        return not isinstance(self.audience, tuple)

    def expired(self, now: str | None = None) -> bool:
        return bool(self.expires_at) and str(self.expires_at) <= (now or utc_now())

    def editable_by(self, guest: str | None, now: str | None = None) -> bool:
        return self.access == ACCESS_EDIT and self.readable_by(guest, now)

    def readable_by(self, guest: str | None, now: str | None = None) -> bool:
        """Whether `guest` (a paired person) may read this external entry right now. No
        guest means nobody: a caller that forgot to say who is reading gets nothing."""
        if not guest or self.expired(now):
            return False
        return self.for_everyone or guest.strip().lower() in self.audience  # type: ignore[operator]

    @classmethod
    def from_json(cls, raw: str) -> "AllowEntry":
        data = json.loads(raw)
        return cls(
            id=str(data["id"]),
            name=str(data.get("name", "")),
            mime_type=str(data.get("mime_type", "")),
            permission_id=data.get("permission_id"),
            granted_at=str(data.get("granted_at", "")),
            request_id=data.get("request_id"),
            shared_with=data.get("shared_with"),
            audience=_audience(data.get("audience")),
            expires_at=data.get("expires_at") or None,
            access=ACCESS_EDIT if data.get("access") == ACCESS_EDIT else ACCESS_READ,
        )


def _audience(value: Any) -> str | tuple[str, ...] | None:
    if isinstance(value, list | tuple):
        return tuple(sorted({str(v).strip().lower() for v in value if str(v).strip()}))
    return value if value is None else str(value)


class Allowlist:
    """A hash of AllowEntry records. `key` picks which list: the owner's own-bot list
    (ALLOWLIST_KEY) or the list shared with paired people (EXTERNAL_ALLOWLIST_KEY)."""

    def __init__(self, store: KeyValueStore, key: str = ALLOWLIST_KEY):
        self.store = store
        self.key = key

    def entries(self) -> dict[str, AllowEntry]:
        out: dict[str, AllowEntry] = {}
        for file_id, raw in self.store.hgetall(self.key).items():
            try:
                out[file_id] = AllowEntry.from_json(raw)
            except (ValueError, KeyError, TypeError):
                continue
        return out

    def get(self, file_id: str) -> AllowEntry | None:
        raw = self.store.hget(self.key, file_id)
        return AllowEntry.from_json(raw) if raw else None

    def add(self, entry: AllowEntry) -> None:
        self.store.hset(self.key, entry.id, entry.to_json())

    def remove(self, file_id: str) -> None:
        self.store.hdel(self.key, file_id)

    def mime_map(self) -> dict[str, str]:
        return {fid: e.mime_type for fid, e in self.entries().items()}

    def entries_for(self, guest: str | None) -> dict[str, AllowEntry]:
        """External entries `guest` may read now: shared with everyone paired, or with
        them by name, and not expired."""
        now = utc_now()
        return {fid: e for fid, e in self.entries().items() if e.readable_by(guest, now)}

    def mime_map_for(self, guest: str | None) -> dict[str, str]:
        return {fid: e.mime_type for fid, e in self.entries_for(guest).items()}

    def edit_map_for(self, guest: str | None) -> dict[str, str]:
        """The entries `guest`'s assistant may write into: shared with them and editable."""
        now = utc_now()
        return {fid: e.mime_type for fid, e in self.entries().items() if e.editable_by(guest, now)}

    def forget_person(self, person: str) -> list[str]:
        """Take `person` off every item that names them. Items shared with everyone are
        unchanged. Returns the ids changed; an item that named only them then names
        nobody, and the Sharing page says so."""
        who = person.strip().lower()
        changed: list[str] = []
        swap = getattr(self.store, "hreplace", None) or getattr(self.store, "hswap", None)
        for file_id in list(self.entries()):
            # Each item is changed only if it still says what was just read. The owner
            # may stop sharing it, or change who it names, at the same moment: a plain
            # write here would put the old entry back.
            for _attempt in range(5):
                raw = self.store.hget(self.key, file_id)
                if not raw:
                    break
                try:
                    entry = AllowEntry.from_json(raw)
                except (ValueError, KeyError, TypeError):
                    break
                if entry.for_everyone or who not in entry.audience:  # type: ignore[operator]
                    break
                rest = tuple(a for a in entry.audience if a != who)  # type: ignore[union-attr]
                updated = replace(entry, audience=rest)
                if swap is None:
                    self.add(updated)
                elif not swap(self.key, file_id, raw, updated.to_json()):
                    continue
                changed.append(file_id)
                break
            else:
                # It kept changing, or this store cannot swap. Taking the person off
                # matters more than the race, so write it plainly, as before.
                logger.warning("unpair: entry kept changing; written without a swap")
                # From a fresh read, so what the owner changed meanwhile is kept.
                latest = self.get(file_id)
                if latest is not None and not latest.for_everyone and who in latest.audience:  # type: ignore[operator]
                    rest = tuple(a for a in latest.audience if a != who)  # type: ignore[union-attr]
                    self.add(replace(latest, audience=rest))
                    changed.append(file_id)
        return changed


# ---- encrypted refresh tokens ---------------------------------------------


class TokenVault:
    """Refresh tokens for the owner and the bot, encrypted with Fernet (ENCRYPTION_KEY)."""

    def __init__(
        self,
        store: KeyValueStore,
        encryption_key: str | None,
        expected: Callable[[], str | None] | None = None,
    ):
        self.store = store
        # Whose sign-in this vault should hold. The encrypted record names its account,
        # so one copied into another person's slot in the store is refused.
        self.expected = expected
        self._fernet = None
        if encryption_key:
            from cryptography.fernet import Fernet

            self._fernet = Fernet(encryption_key.strip().encode())

    @property
    def enabled(self) -> bool:
        return self._fernet is not None

    def _put(self, key: str, token: str, email: str, scopes: str | None = None) -> None:
        if self._fernet is None:
            raise RuntimeError("ENCRYPTION_KEY is not set")
        payload: dict[str, str] = {"t": token, "email": email, "at": utc_now()}
        if scopes:
            payload["scopes"] = scopes
        self.store.set(key, self._fernet.encrypt(json.dumps(payload).encode()).decode())

    def _take(self, key: str) -> dict[str, str] | None:
        if self._fernet is None:
            return None
        raw = self.store.get(key)
        if not raw:
            return None
        from cryptography.fernet import InvalidToken

        try:
            return json.loads(self._fernet.decrypt(raw.encode()))
        except (InvalidToken, ValueError):
            return None

    def set_owner(self, token: str, email: str, scopes: str | None = None) -> None:
        self._put(OWNER_TOKEN_KEY, token, email, scopes)

    def owner(self) -> dict[str, str] | None:
        """The stored Drive sign-in, only if it is limited to drive.file.

        An older record that carries the full Drive scope, or has no scope stamp, is not
        returned: the person counts as not connected until they reconnect. Use
        `legacy_owner()` to find such a record so it can be revoked.
        """
        from ..drive_client import scopes_acceptable

        record = self._owner_any()
        if record and not scopes_acceptable(record.get("scopes")):
            return None
        return record

    def legacy_owner(self) -> dict[str, str] | None:
        """A stored sign-in this server no longer uses (full Drive or unstamped), if any."""
        from ..drive_client import scopes_acceptable

        record = self._owner_any()
        if record and record.get("t") and not scopes_acceptable(record.get("scopes")):
            return record
        return None

    def _owner_any(self) -> dict[str, str] | None:
        record = self._take(OWNER_TOKEN_KEY)
        want = self.expected() if self.expected is not None else None
        have = record.get("email") if record else None
        # A record saved before the account was written into it has no email and is
        # accepted. Every record written since has one, so a copied one is caught.
        if want and have and str(have).strip().lower() != want.strip().lower():
            logger.warning("stored Drive sign-in belongs to a different account; ignored")
            return None
        return record

    def set_notion(
        self,
        access_token: str,
        refresh_token: str | None,
        email: str,
        workspace_id: str = "",
        workspace_name: str = "",
    ) -> None:
        """This person's Notion connection. Encrypted like the Drive token, and naming the
        account it belongs to, so a record copied into another person's slot is refused."""
        if self._fernet is None:
            raise RuntimeError("ENCRYPTION_KEY is not set")
        payload = {
            "t": access_token,
            "email": email,
            "at": utc_now(),
            "workspace_id": workspace_id,
            "workspace_name": workspace_name,
        }
        if refresh_token:
            payload["r"] = refresh_token
        self.store.set(
            NOTION_TOKEN_KEY, self._fernet.encrypt(json.dumps(payload).encode()).decode()
        )

    def notion(self) -> dict[str, str] | None:
        """The stored Notion connection for the current person, or None."""
        record = self._take(NOTION_TOKEN_KEY)
        if not record or not record.get("t"):
            return None
        want = self.expected() if self.expected is not None else None
        have = record.get("email")
        if want and (not have or str(have).strip().lower() != want.strip().lower()):
            logger.warning("stored Notion connection belongs to a different account; ignored")
            return None
        return record

    def clear_notion(self) -> None:
        self.store.delete(NOTION_TOKEN_KEY)

    def set_onedrive(
        self,
        access_token: str,
        refresh_token: str | None,
        email: str,
        expires_at: float,
        drive_id: str = "",
        account: str = "",
        drive_type: str = "",
        scopes: str = "",
    ) -> None:
        """This person's OneDrive connection. Encrypted like the Drive token, and naming
        the account it belongs to, so a record copied into another person's slot is
        refused. `scopes` is what Microsoft granted (space-separated); a record without
        it was made before writing existed and is read-only."""
        if self._fernet is None:
            raise RuntimeError("ENCRYPTION_KEY is not set")
        payload = {
            "t": access_token,
            "email": email,
            "at": utc_now(),
            "exp": str(int(expires_at)),
            "drive_id": drive_id,
            "account": account,
            "drive_type": drive_type,
        }
        if scopes:
            payload["scp"] = scopes
        if refresh_token:
            payload["r"] = refresh_token
        self.store.set(
            ONEDRIVE_TOKEN_KEY, self._fernet.encrypt(json.dumps(payload).encode()).decode()
        )

    def onedrive(self) -> dict[str, str] | None:
        """The stored OneDrive connection for the current person, or None."""
        record = self._take(ONEDRIVE_TOKEN_KEY)
        if not record or not record.get("t"):
            return None
        want = self.expected() if self.expected is not None else None
        have = record.get("email")
        if want and (not have or str(have).strip().lower() != want.strip().lower()):
            logger.warning("stored OneDrive connection belongs to a different account; ignored")
            return None
        return record

    def clear_onedrive(self) -> None:
        self.store.delete(ONEDRIVE_TOKEN_KEY)

    def bot(self) -> dict[str, str] | None:
        """A bot-account token from before sign-in became per person. Nothing writes
        one any more; this only reads what an old store may still hold."""
        return self._take(BOT_TOKEN_KEY)

    def clear_owner(self) -> None:
        self.store.delete(OWNER_TOKEN_KEY)


# ---- activity log -----------------------------------------------------------


# At most this many rows an hour from one connected app (see ActivityLog._own_app_row).
APP_ROWS_PER_HOUR = 120
# The fields that name what a call was about, most specific first.
_TARGET_FIELDS = (
    "file_id",
    "folder_id",
    "page_id",
    "item_id",
    "parent_id",
    "request_id",
    "upload_id",
    "link_id",
    "msg_id",
    "drop_id",
)


class ActivityLog:
    """The last ACTIVITY_MAX audit records, newest first."""

    def __init__(self, store: KeyValueStore, max_items: int = ACTIVITY_MAX):
        self.store = store
        self.max_items = max_items

    def __call__(self, record: dict[str, Any]) -> None:
        if not self._worth_keeping(record):
            return
        self.store.lpush(ACTIVITY_KEY, json.dumps(record, separators=(",", ":")))
        self.store.ltrim(ACTIVITY_KEY, 0, self.max_items - 1)

    def _worth_keeping(self, record: dict[str, Any]) -> bool:
        """The list holds ACTIVITY_MAX rows, so rows anyone can produce in bulk must not
        be able to push the others out. Every record still goes to the server log.

        A rejected bearer token is kept once an hour per reason. A paired person's call
        is kept once an hour per tool and outcome (and per file when it was allowed), so
        repeating a call does not bury the record of an earlier one.

        A chunked upload sends hundreds of pieces. Each accepted piece goes to the server
        log only; its start, its finish and any refused piece are kept here."""
        if record.get("tool") == "append_chunk" and record.get("decision") == "allow":
            return False
        guest = record.get("guest")
        if record.get("event") == "auth":
            parts = ["auth", str(record.get("reason"))]
        elif (
            record.get("event") == "owner"
            and record.get("decision") == "deny"
            and current_actor.get() is None
        ):
            # A refusal with nobody signed in (a sign-in by an account that is not let in)
            # lands in the admin's list, and anyone can cause one: once an hour per kind.
            parts = [
                "nobody",
                str(record.get("action")),
                str(record.get("decision")),
                str(record.get("reason")),
            ]
        elif record.get("event") == "owner" and record.get("decision") == "deny":
            # Refusals the server noticed for a signed-in person (a reused token, a form
            # from another site): a burst of them is kept once an hour per kind and app.
            parts = [
                "refused",
                str(record.get("action")),
                str(record.get("reason")),
                str(record.get("app") or record.get("terminal") or ""),
            ]
        elif guest:
            allowed = record.get("decision") == "allow"
            parts = [
                str(guest),
                str(record.get("tool")),
                str(record.get("decision")),
                str(record.get("reason")),
                str(record.get("file_id") or record.get("folder_id") or "") if allowed else "",
            ]
        elif record.get("event") == "tool_call":
            # One of the person's own apps. Each app may put at most APP_ROWS_PER_HOUR
            # rows here an hour, and a repeat of the same call on the same item is kept
            # once an hour, so a steered bot cannot push the record of what it did
            # earlier off the list by calling list_folder 500 times. The server log
            # still has every call; one row says when an app's rows were cut short.
            return self._own_app_row(record)
        else:
            return True
        return self._first_this_hour(parts)

    def _first_this_hour(self, parts: list[str]) -> bool:
        digest = hashlib.sha256("\x00".join(parts).encode()).hexdigest()[:32]
        try:
            return self.store.set_if_absent(f"activity_seen:{digest}", "1", ex=GUEST_ROW_EVERY)
        except Exception:
            # Not knowing whether it is a repeat is no reason to lose the record.
            logger.warning("activity repeat check failed; keeping the row", exc_info=True)
            return True

    def _own_app_row(self, record: dict[str, Any]) -> bool:
        app = str(record.get("app") or record.get("token_name") or "")
        target = next(
            (str(record[k]) for k in _TARGET_FIELDS if isinstance(record.get(k), str)), ""
        )
        if not self._first_this_hour(
            [
                "app",
                app,
                str(record.get("tool")),
                str(record.get("decision")),
                str(record.get("reason")),
                target,
            ]
        ):
            return False
        digest = hashlib.sha256(app.encode()).hexdigest()[:32]
        try:
            count = self.store.incr(f"activity_app:{digest}", ex=GUEST_ROW_EVERY)
        except Exception:
            logger.warning("activity budget check failed; keeping the row", exc_info=True)
            return True
        if count <= APP_ROWS_PER_HOUR:
            return True
        if count == APP_ROWS_PER_HOUR + 1:
            marker = {
                "ts": record.get("ts"),
                "event": "owner",
                "action": "activity_limited",
                "token_name": record.get("token_name"),
                "app": record.get("app"),
                "decision": "deny",
                "reason": "too_many_calls",
            }
            self.store.lpush(ACTIVITY_KEY, json.dumps(marker, separators=(",", ":")))
            self.store.ltrim(ACTIVITY_KEY, 0, self.max_items - 1)
        return False

    def recent(self, limit: int = ACTIVITY_MAX) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for raw in self.store.lrange(ACTIVITY_KEY, 0, limit - 1):
            try:
                out.append(json.loads(raw))
            except ValueError:
                continue
        return out


FIRST_READS_KEY = "first_reads"
FIRST_READS_MAX = 20
# How long a person's first read stays "first": after this, the next read is news again.
FIRST_READ_EVERY = 365 * 24 * 3600


class FirstReads:
    """Newest first: the first time each paired person's assistant read something this
    person shares. Shown on Overview so a new reader does not go unnoticed."""

    def __init__(self, store: KeyValueStore, max_items: int = FIRST_READS_MAX):
        self.store = store
        self.max_items = max_items

    def add(self, guest: str, tool: str, file_id: str | None) -> bool:
        """Record `guest`'s first read. Returns False if they were already seen. The seen
        mark is claimed first so two reads at once give one notice; if writing the notice
        then fails, the mark is released so the next read tries again."""
        seen = f"first_read_seen:{guest}"
        if not self.store.set_if_absent(seen, "1", ex=FIRST_READ_EVERY):
            return False
        try:
            row = {"at": utc_now(), "guest": guest, "tool": tool, "file_id": file_id}
            self.store.lpush(FIRST_READS_KEY, json.dumps(row, separators=(",", ":")))
            self.store.ltrim(FIRST_READS_KEY, 0, self.max_items - 1)
        except Exception:
            self.store.delete(seen)
            raise
        return True

    def recent(self, limit: int = 5) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for raw in self.store.lrange(FIRST_READS_KEY, 0, limit - 1):
            try:
                row = json.loads(raw)
            except ValueError:
                continue
            if isinstance(row, dict) and row.get("guest"):
                out.append(row)
        return out

    def clear(self) -> None:
        self.store.delete(FIRST_READS_KEY)


HIDDEN_FILES_KEY = "files_hidden"


class HiddenFiles:
    """Items this person removed from Bot RBAC on Files.

    Google gives an app no way to hand back one file picked in its file picker, so
    "Remove from Bot RBAC" takes the item off both lists and hides it here. The page says
    that Google still lists the app as able to open it. Picking it again brings it back.
    """

    def __init__(self, store: KeyValueStore):
        self.store = store

    def hide(self, file_id: str) -> None:
        self.store.hset(HIDDEN_FILES_KEY, file_id, utc_now())

    def unhide(self, file_id: str) -> None:
        self.store.hdel(HIDDEN_FILES_KEY, file_id)

    def ids(self) -> set[str]:
        return set(self.store.hgetall(HIDDEN_FILES_KEY))

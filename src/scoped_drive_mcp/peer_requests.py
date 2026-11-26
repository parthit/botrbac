"""Requests from one person to another, for people only.

A paired person can ask, from their dashboard, for something the other person has not
shared with them (described in their own words), or for more on an item they can already
see: edit access, or more time before a share ends. The request shows up on the other
person's Requests page. No MCP tool reads or writes these records, so the text never
reaches an assistant on either side; nothing in server.py, tools/, service.py or access.py
imports this module.

A request never names a file the requester cannot already see. A described request
carries text only, and the answer to sending one is the same whatever happened, so it
cannot be used to find out what is in the other person's Drive.

Storage, in the store of the person being asked (each record expires after 14 days):
- `peerreq:<id>`            the request as JSON (signed: it names who would get access;
                            the words are encrypted when ENCRYPTION_KEY is set)
- `peer_requests:index`     newest-first list of request ids (capped)
- `peer_requests:pending`   ids still waiting, for the nav count
- `peer_requests:open:<kind>:<item>:<requester hash>`  the waiting request of that kind
                            for that item from that person, so it is not filed twice
- `peer_requests:rate:<requester hash>:<day>`  requests that person filed that day
- `peer_requests:lock:<id>` held while a decision is applied, so two cannot run at once

And in the requester's own store: `peer_requests:sent`, a short list of what they asked
and whom, so their page can show whether each was answered.
"""

import hashlib
import json
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from .access import APPROVED, DENIED, PENDING, clean_text, new_request_id, validate_request_id
from .audit import audit_owner
from .drive_client import SHORTCUT_MIME
from .external import acting_as
from .grants import KEEP, GrantError, GrantService
from .scope import InvalidInputError, validate_drive_id
from .store import (
    ACCESS_EDIT,
    AUDIENCE_LINKED,
    EXTERNAL_ALLOWLIST_KEY,
    AllowEntry,
    Allowlist,
    KeyValueStore,
    purpose_fernet,
    usable_email,
    utc_now,
)

PEER_TTL = 14 * 24 * 3600
# Requests one person may send to one other person in a day (a fixed window).
PER_DAY = 3
DAY = 24 * 3600
INDEX_KEY = "peer_requests:index"
PENDING_KEY = "peer_requests:pending"
SENT_KEY = "peer_requests:sent"
INDEX_MAX = 200
SENT_MAX = 30
MORE_TIME_DAYS = 7
LOCK_SECONDS = 30
# Marks words stored encrypted, under a key used for nothing else.
_SEALED = "enc1."

DESCRIBE = "describe"
EDIT = "edit"
MORE_TIME = "more_time"
KINDS = (DESCRIBE, EDIT, MORE_TIME)


@dataclass
class PeerRequest:
    id: str
    kind: str
    requester: str
    # The requester's own words (DESCRIBE only). Shown to the person asked, as text.
    text: str | None = None
    # The item on the Sharing list the request is about (EDIT and MORE_TIME only).
    item_id: str | None = None
    item_name: str | None = None
    status: str = PENDING
    created_at: str = field(default_factory=utc_now)
    decided_at: str | None = None
    granted_id: str | None = None
    granted_name: str | None = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> "PeerRequest":
        data = json.loads(raw)
        known = set(cls.__dataclass_fields__)
        req = cls(**{k: v for k, v in data.items() if k in known})
        if req.kind not in KINDS or not usable_email(req.requester):
            raise ValueError("not a peer request")
        return req


def _who(email: str) -> str:
    return hashlib.sha256(email.encode()).hexdigest()[:24]


def _open_key(kind: str, item_id: str, requester: str) -> str:
    return f"peer_requests:open:{kind}:{item_id}:{_who(requester)}"


def _email(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    email = value.strip().lower()
    return email if usable_email(email) else None


class PeerRequests:
    """The requests filed with one person (`store` is that person's store)."""

    def __init__(
        self,
        store: KeyValueStore,
        clock: Callable[[], float] = time.time,
        fernet: Any = None,
    ):
        self.store = store
        self.clock = clock
        self._fernet = fernet

    def _seal(self, req: PeerRequest) -> str:
        if req.text is None or self._fernet is None:
            return req.to_json()
        data = asdict(req)
        data["text"] = _SEALED + self._fernet.encrypt(req.text.encode()).decode()
        return json.dumps(data, separators=(",", ":"))

    def _open(self, raw: str) -> PeerRequest:
        req = PeerRequest.from_json(raw)
        if isinstance(req.text, str) and req.text.startswith(_SEALED):
            if self._fernet is None:
                raise ValueError("encrypted words, and no key")
            try:
                req.text = self._fernet.decrypt(req.text[len(_SEALED) :].encode()).decode()
            except Exception:
                raise ValueError("words do not decrypt") from None
        return req

    def get(self, request_id: Any) -> PeerRequest | None:
        try:
            validate_request_id(request_id)
        except InvalidInputError:
            return None
        raw = self.store.get(f"peerreq:{request_id}")
        if not raw:
            return None
        try:
            return self._open(raw)
        except (ValueError, TypeError):
            return None

    def save(self, req: PeerRequest) -> None:
        self.store.set(f"peerreq:{req.id}", self._seal(req), ex=PEER_TTL)

    def open_for(self, kind: str, item_id: str, requester: str) -> PeerRequest | None:
        rid = self.store.get(_open_key(kind, item_id, requester))
        req = self.get(rid) if rid else None
        return req if req is not None and req.status == PENDING else None

    def within_limit(self, requester: str) -> bool:
        """Count one more request from `requester` today. A store failure is an error for
        the caller, not a free pass."""
        day = int(self.clock() // DAY)
        count = self.store.incr(f"peer_requests:rate:{_who(requester)}:{day}", ex=DAY + 60)
        return int(count) <= PER_DAY

    def create(
        self,
        *,
        kind: str,
        requester: str,
        text: str | None = None,
        item_id: str | None = None,
        item_name: str | None = None,
    ) -> PeerRequest:
        req = PeerRequest(
            id=new_request_id(),
            kind=kind,
            requester=requester,
            text=text,
            item_id=item_id,
            item_name=item_name,
        )
        self.save(req)
        if item_id is not None:
            self.store.set(_open_key(kind, item_id, requester), req.id, ex=PEER_TTL)
        for key in (INDEX_KEY, PENDING_KEY):
            self.store.lpush(key, req.id)
            self.store.ltrim(key, 0, INDEX_MAX - 1)
        return req

    def decide(
        self,
        req: PeerRequest,
        status: str,
        *,
        granted_id: str | None = None,
        granted_name: str | None = None,
    ) -> PeerRequest:
        req.status = status
        req.decided_at = utc_now()
        req.granted_id = granted_id
        req.granted_name = granted_name
        self.save(req)
        self.store.lrem(PENDING_KEY, req.id)
        if req.item_id is not None:
            key = _open_key(req.kind, req.item_id, req.requester)
            if self.store.get(key) == req.id:
                self.store.delete(key)
        return req

    def recent(self, limit: int = 100) -> list[PeerRequest]:
        """Newest first. A request that has expired is simply no longer there."""
        out: list[PeerRequest] = []
        for rid in dict.fromkeys(self.store.lrange(INDEX_KEY, 0, INDEX_MAX - 1)):
            req = self.get(rid)
            if req is not None:
                out.append(req)
            if len(out) >= limit:
                break
        return out

    def pending_count(self) -> int:
        count = 0
        for rid in dict.fromkeys(self.store.lrange(PENDING_KEY, 0, -1)):
            req = self.get(rid)
            if req is None or req.status != PENDING:
                self.store.lrem(PENDING_KEY, rid)
                continue
            count += 1
        return count


def share_with_person(grants: GrantService, file_id: str, person: str) -> AllowEntry:
    """Let `person` read an item on the Sharing list, leaving everyone who already can.

    A new item is shared with that person only. An item already on the list keeps its
    audience, end date and access, and gains them. Same checks as any share: the item
    must be in the signed-in person's Drive, not trashed and not My Drive itself."""
    validate_drive_id(file_id)
    meta = grants.owner_meta(file_id)
    if meta is None:
        raise GrantError("That item was not found in your Drive.")
    if meta.get("mimeType") == SHORTCUT_MIME:
        target = (meta.get("shortcutDetails") or {}).get("targetId")
        meta = grants.owner_meta(str(target)) if target else None
        if meta is None:
            raise GrantError("The shortcut's target was not found in your Drive.")
    if meta.get("trashed"):
        raise GrantError("That item is in the trash.")
    item_id = str(meta["id"])
    existing = grants.allowlist.get(item_id)
    if existing is None:
        return grants.grant(item_id, audience=(person,))
    if existing.expired():
        raise GrantError(
            f"Sharing of “{existing.name}” has ended. Give it a new end date on "
            "Shared by me first, then approve this request."
        )
    if existing.for_everyone or person in (existing.audience or ()):
        return existing
    return grants.set_audience(item_id, (*(existing.audience or ()), person), KEEP)


def _audience_of(entry: AllowEntry) -> str | tuple[str, ...]:
    return entry.audience if isinstance(entry.audience, tuple) else AUDIENCE_LINKED


class PeerRequestService:
    """Sending, listing and deciding requests between paired people (dashboard only)."""

    def __init__(self, directory: Any, mailbox: Any, clock: Callable[[], float] = time.time):
        self.directory = directory
        self.mailbox = mailbox
        self.clock = clock
        key = getattr(directory, "encryption_key", None)
        self._fernet = purpose_fernet(key, "peer request text") if key else None

    def box(self, owner: str) -> PeerRequests:
        return PeerRequests(self.directory.store_for(owner), self.clock, self._fernet)

    def _shared(self, owner: str) -> Allowlist:
        return Allowlist(self.directory.store_for(owner), EXTERNAL_ALLOWLIST_KEY)

    # ---- the person asking ---------------------------------------------

    def askable(self, requester: str, owner: str) -> dict[str, set[str]]:
        """Per item `owner` shares with `requester`: which of EDIT and MORE_TIME can be
        asked for. Only items the requester can already see are in it."""
        you, them = _email(requester), _email(owner)
        if not you or not them or you == them or not self.mailbox.is_linked(you, them):
            return {}
        out: dict[str, set[str]] = {}
        for item_id, entry in self._shared(them).entries_for(you).items():
            kinds = set()
            if entry.access != ACCESS_EDIT:
                kinds.add(EDIT)
            if entry.expires_at:
                kinds.add(MORE_TIME)
            if kinds:
                out[item_id] = kinds
        return out

    def send(
        self,
        requester: str,
        owner: str,
        kind: str,
        *,
        text: Any = None,
        item_id: Any = None,
    ) -> bool:
        """File a request with `owner`. Returns whether one was stored, which the caller
        must not show: the person asking is told the same thing either way.

        Raises InvalidInputError only for the requester's own text (empty or too long),
        which says nothing about the other person."""
        if kind not in KINDS:
            return False
        words = clean_text(text, "Your request", required=True) if kind == DESCRIBE else None
        you, them = _email(requester), _email(owner)
        if not you or not them or you == them or not self.mailbox.is_linked(you, them):
            return False
        box = self.box(them)
        name = None
        item = None
        if kind != DESCRIBE:
            try:
                item = validate_drive_id(item_id)
            except InvalidInputError:
                return False
            entry = self._shared(them).get(item)
            # Only an item this person can see right now, and only when there is
            # something to ask for. Anything else is dropped without a different answer.
            if entry is None or not entry.readable_by(you):
                return False
            if kind == EDIT and entry.access == ACCESS_EDIT:
                return False
            if kind == MORE_TIME and not entry.expires_at:
                return False
            if box.open_for(kind, item, you) is not None:
                return False
            name = entry.name
        if not box.within_limit(you):
            return False
        req = box.create(kind=kind, requester=you, text=words, item_id=item, item_name=name)
        mine = self.directory.store_for(you)
        mine.lpush(SENT_KEY, json.dumps({"o": them, "id": req.id}, separators=(",", ":")))
        mine.ltrim(SENT_KEY, 0, SENT_MAX - 1)
        # Ids and addresses only: the words themselves are never logged.
        with acting_as(them):
            audit_owner("peer_request", request_id=req.id, person=you, kind=kind)
        with acting_as(you):
            audit_owner("peer_request_sent", person=them, kind=kind)
        return True

    def sent(self, requester: str) -> list[dict[str, Any]]:
        """What `requester` asked for and whether it was answered. Only their own words
        and the names of items they could already see come back."""
        you = _email(requester)
        if not you:
            return []
        out: list[dict[str, Any]] = []
        for raw in self.directory.store_for(you).lrange(SENT_KEY, 0, SENT_MAX - 1):
            try:
                row = json.loads(raw)
                owner, rid = _email(row["o"]), str(row["id"])
            except (ValueError, KeyError, TypeError):
                continue
            if not owner:
                continue
            req = self.box(owner).get(rid)
            if req is None or req.requester != you:
                continue
            out.append(
                {
                    "to": owner,
                    "kind": req.kind,
                    "text": req.text,
                    "item_name": req.item_name,
                    "status": req.status,
                    "created_at": req.created_at,
                }
            )
        return out

    # ---- the person asked ----------------------------------------------

    def pending_count(self, owner: str) -> int:
        return self.box(owner).pending_count()

    def inbox(self, owner: str) -> tuple[list[PeerRequest], list[PeerRequest]]:
        reqs = self.box(owner).recent(100)
        return (
            [r for r in reqs if r.status == PENDING],
            [r for r in reqs if r.status != PENDING],
        )

    def get(self, owner: str, request_id: str) -> PeerRequest | None:
        return self.box(owner).get(request_id)

    def details(self, owner: str, req: PeerRequest) -> dict[str, Any]:
        """What the person deciding should see next to the request."""
        entry = self._shared(owner).get(req.item_id) if req.item_id else None
        return {
            "paired": self.mailbox.is_linked(owner, req.requester),
            "entry": entry,
            "more_time_days": MORE_TIME_DAYS,
        }

    def _pending(self, owner: str, request_id: str, expect: str | None) -> PeerRequest:
        req = self.get(owner, request_id)
        if req is None:
            raise GrantError("This request doesn’t exist or has expired.")
        if req.status != PENDING:
            raise GrantError(f"This request was already {req.status}.")
        # The form names the person the page showed. If the request is from someone
        # else, the page was not showing this request.
        if not expect or _email(expect) != req.requester:
            raise GrantError("Reload the page and check who is asking before you decide.")
        return req

    def _locked(self, owner: str, request_id: str) -> Callable[[], None]:
        store = self.directory.store_for(owner)
        key = f"peer_requests:lock:{request_id}"
        if not store.set_if_absent(key, "1", ex=LOCK_SECONDS):
            raise GrantError("This request is being decided right now. Reload the page.")
        return lambda: store.delete(key)

    def approve(
        self,
        owner: str,
        request_id: str,
        grants: GrantService,
        *,
        expect: str | None,
        target_id: str | None = None,
        expires_at: str | None = None,
    ) -> tuple[PeerRequest, AllowEntry]:
        """Approve as `owner` (the signed-in person; `grants` is their Sharing list).

        DESCRIBE shares `target_id`, one item `owner` picked from their own Drive, with
        the requester. EDIT and MORE_TIME change the item the request names. Refused
        when the two are no longer paired."""
        self._pending(owner, request_id, expect)
        unlock = self._locked(owner, request_id)
        try:
            # Read again under the lock, so a second approval sees the first one's result.
            req = self._pending(owner, request_id, expect)
            if not self.mailbox.is_linked(owner, req.requester):
                raise GrantError(
                    f"You are no longer paired with {req.requester}, so nothing can be "
                    "shared with them. Decline this request."
                )
            if req.kind == DESCRIBE:
                if not target_id:
                    raise GrantError("Pick the item to share first.")
                entry = share_with_person(grants, target_id, req.requester)
            else:
                entry = self._change_item(req, grants, expires_at)
            self.box(owner).decide(req, APPROVED, granted_id=entry.id, granted_name=entry.name)
            audit_owner(
                "approve_peer_request",
                request_id=req.id,
                file_id=entry.id,
                person=req.requester,
                kind=req.kind,
            )
            return req, entry
        finally:
            unlock()

    def _change_item(
        self, req: PeerRequest, grants: GrantService, expires_at: str | None
    ) -> AllowEntry:
        entry = grants.allowlist.get(req.item_id or "")
        named = entry is not None and (
            entry.for_everyone or req.requester in (entry.audience or ())
        )
        if entry is None or not named:
            raise GrantError(
                f"“{req.item_name or 'That item'}” is no longer shared with "
                f"{req.requester}, so there is nothing to change. Decline this request."
            )
        audience = _audience_of(entry)
        if req.kind == EDIT:
            if entry.expired():
                raise GrantError(
                    f"Sharing of “{entry.name}” has ended. Decline this request, "
                    "or give the item a new end date on Shared by me first."
                )
            if entry.access == ACCESS_EDIT:
                return entry
            return grants.set_audience(entry.id, audience, KEEP, ACCESS_EDIT)
        now = datetime.fromtimestamp(self.clock(), UTC)
        if expires_at is None:
            if not entry.expires_at:
                return entry  # the end date was removed meanwhile: nothing left to extend
            try:
                ends = datetime.fromisoformat(entry.expires_at)
            except ValueError:
                ends = now
            until = (max(ends, now) + timedelta(days=MORE_TIME_DAYS)).isoformat(timespec="seconds")
        else:
            until = expires_at
            if until <= now.isoformat(timespec="seconds"):
                raise GrantError("Pick an end date in the future.")
        return grants.set_audience(entry.id, audience, until)

    def deny(self, owner: str, request_id: str, *, expect: str | None) -> PeerRequest:
        req = self._pending(owner, request_id, expect)
        unlock = self._locked(owner, request_id)
        try:
            req = self._pending(owner, request_id, expect)
            self.box(owner).decide(req, DENIED)
            audit_owner("deny_peer_request", request_id=req.id, person=req.requester, kind=req.kind)
            return req
        finally:
            unlock()

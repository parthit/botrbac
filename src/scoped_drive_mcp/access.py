"""Access requests: created when a tool is denied because of scope (never because of role),
or explicitly through the `request_access` tool. The owner approves or denies them on the
dashboard at APP_BASE_URL/requests/<id>.

Storage (all keys expire after 7 days):
- `req:<id>`           the request as JSON
- `req:pending:<file>` id of the pending request for that file (dedupe)
- `requests:index`     newest-first list of request ids (capped)
- `requests:pending`   ids that are still pending, so the nav count is not a scan of the history
- `req:denied:<file>:<assistant>`  "<request id> <unix time>" of that assistant's last denied
                       request for that file; expires after DENIAL_WINDOW
- `req:denied-cleared:<file>`  unix time the owner last changed that file's access; a denial
                       older than this no longer holds; expires after DENIAL_WINDOW

A denial holds for DENIAL_WINDOW (24 hours) for the same file and the same assistant (the
token or connection name on the request): asking again in that time returns the denied
request instead of opening a new one, so a "no" does not come straight back to the owner
as a fresh request. The hold ends early when the owner changes that file's entry on Access
(Allow or Remove), and another assistant asking for the same file is still a new request.
"""

import hashlib
import json
import logging
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

from .scope import InvalidInputError, validate_drive_id
from .store import KeyValueStore, utc_now

logger = logging.getLogger(__name__)

REQUEST_TTL = 7 * 24 * 3600
DENIAL_WINDOW = 24 * 3600
INDEX_KEY = "requests:index"
PENDING_INDEX = "requests:pending"
PENDING_READY = "requests:pending_ready"
INDEX_MAX = 300
# Requests one connected app may have waiting at once (MAX_PENDING_REQUESTS).
MAX_PENDING_PER_APP = 50
# Whole-server keys (not per person): request id -> the account it belongs to, and when
# this index started. They let "this link is for a different account" be answered with one
# read instead of looking through every account.
OWNER_INDEX = "reqowner:"
OWNER_INDEX_SINCE = "reqowner_since"
MAX_TEXT = 500

PENDING = "pending"
APPROVED = "approved"
DENIED = "denied"

_REQUEST_ID = re.compile(r"^[A-Za-z0-9_-]{22,64}$")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def new_request_id() -> str:
    return secrets.token_urlsafe(24)  # 192 bits


def validate_request_id(value: Any) -> str:
    if not isinstance(value, str) or not _REQUEST_ID.fullmatch(value):
        raise InvalidInputError("request_id is not a valid access request id")
    return value


def clean_text(value: Any, what: str, *, required: bool) -> str | None:
    if value is None or (isinstance(value, str) and not value.strip()):
        if required:
            raise InvalidInputError(f"{what} must not be empty")
        return None
    if not isinstance(value, str):
        raise InvalidInputError(f"{what} must be a string")
    value = _CONTROL_CHARS.sub(" ", value).strip()
    if len(value) > MAX_TEXT:
        raise InvalidInputError(f"{what} must be at most {MAX_TEXT} characters")
    return value


@dataclass
class AccessRequest:
    id: str
    file_id: str | None
    file_name: str | None
    description: str | None
    tool: str
    token_name: str | None
    reason: str | None
    status: str = PENDING
    created_at: str = field(default_factory=utc_now)
    decided_at: str | None = None
    granted_id: str | None = None
    granted_name: str | None = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> "AccessRequest":
        data = json.loads(raw)
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})


def _denied_key(file_id: str, token_name: str | None) -> str:
    # An assistant with no name (rare) still gets its own slot, apart from named ones. The
    # name is hashed so any characters in it are safe inside a key.
    actor = hashlib.sha256((token_name or "-").encode()).hexdigest()[:24]
    return f"req:denied:{file_id}:{actor}"


def _cleared_key(file_id: str) -> str:
    return f"req:denied-cleared:{file_id}"


class AccessRequests:
    def __init__(
        self,
        store: KeyValueStore,
        clock: Callable[[], float] = time.time,
        on_create: Callable[[str], None] | None = None,
    ):
        self.store = store
        self.clock = clock
        # Told each new request id, so the server can note whose it is (see OWNER_INDEX).
        self.on_create = on_create

    def recent_denial(self, file_id: str, token_name: str | None) -> AccessRequest | None:
        """The request the owner denied for this file and assistant within DENIAL_WINDOW."""
        key = _denied_key(file_id, token_name)
        raw = self.store.get(key)
        if not raw:
            return None
        rid, _, when = raw.partition(" ")
        try:
            denied_at = float(when)
            fresh = self.clock() - denied_at < DENIAL_WINDOW
            cleared = self.store.get(_cleared_key(file_id))
            if fresh and cleared is not None and float(cleared) >= denied_at:
                fresh = False
        except ValueError:
            fresh = False
        req = self.get(rid) if fresh else None
        if req is None or req.status != DENIED:
            self.store.delete(key)
            return None
        return req

    def clear_denials(self, file_id: str) -> None:
        """The owner changed this file's access, so earlier denials no longer hold."""
        self.store.set(_cleared_key(file_id), f"{self.clock():.3f}", ex=DENIAL_WINDOW)

    def get(self, request_id: str) -> AccessRequest | None:
        try:
            validate_request_id(request_id)
        except InvalidInputError:
            return None
        raw = self.store.get(f"req:{request_id}")
        if not raw:
            return None
        try:
            return AccessRequest.from_json(raw)
        except (ValueError, TypeError):
            return None

    def save(self, req: AccessRequest) -> None:
        self.store.set(f"req:{req.id}", req.to_json(), ex=REQUEST_TTL)

    def pending_for(self, file_id: str) -> AccessRequest | None:
        rid = self.store.get(f"req:pending:{file_id}")
        if not rid:
            return None
        req = self.get(rid)
        if req is None or req.status != PENDING:
            return None
        return req

    def create(
        self,
        *,
        tool: str,
        token_name: str | None,
        reason: str | None,
        file_id: str | None = None,
        file_name: str | None = None,
        description: str | None = None,
        max_pending: int | None = None,
    ) -> tuple[AccessRequest, bool]:
        """Create a pending request, or return the existing pending one for `file_id`.
        Returns (request, created). Raises TooManyPending when `max_pending` requests
        from this app are already waiting: nothing is saved then."""
        if file_id is not None:
            existing = self.pending_for(file_id)
            if existing is not None:
                return existing, False
        if max_pending is not None and self.pending_from(token_name) >= max_pending:
            raise TooManyPending(max_pending)
        req = AccessRequest(
            id=new_request_id(),
            file_id=file_id,
            file_name=file_name,
            description=description,
            tool=tool,
            token_name=token_name,
            reason=reason,
        )
        self.save(req)
        if file_id is not None:
            self.store.set(f"req:pending:{file_id}", req.id, ex=REQUEST_TTL)
        self.store.lpush(INDEX_KEY, req.id)
        self.store.ltrim(INDEX_KEY, 0, INDEX_MAX - 1)
        self.store.lpush(PENDING_INDEX, req.id)
        # Same cap as the history list, so the nav badge never counts (and re-reads on
        # every page) more requests than the Requests page can show.
        self.store.ltrim(PENDING_INDEX, 0, INDEX_MAX - 1)
        if self.on_create is not None:
            try:
                self.on_create(req.id)
            except Exception:  # the request itself is saved; only the hint is missing
                logger.warning("request owner index not written", exc_info=True)
        return req, True

    def decide(
        self,
        req: AccessRequest,
        status: str,
        *,
        granted_id: str | None = None,
        granted_name: str | None = None,
    ) -> AccessRequest:
        req.status = status
        req.decided_at = utc_now()
        req.granted_id = granted_id
        req.granted_name = granted_name
        self.save(req)
        if req.file_id is not None and self.store.get(f"req:pending:{req.file_id}") == req.id:
            self.store.delete(f"req:pending:{req.file_id}")
        if status != PENDING:
            self.store.lrem(PENDING_INDEX, req.id)
        if status == DENIED and req.file_id is not None:
            self.store.set(
                _denied_key(req.file_id, req.token_name),
                f"{req.id} {self.clock():.3f}",
                ex=DENIAL_WINDOW,
            )
        return req

    def pending_from(self, token_name: str | None) -> int:
        """How many waiting requests this app filed. Read only when it files another."""
        count = 0
        for rid in dict.fromkeys(self.store.lrange(PENDING_INDEX, 0, -1)):
            req = self.get(rid)
            if req is not None and req.status == PENDING and req.token_name == token_name:
                count += 1
        return count

    def pending_count(self) -> int:
        """How many requests are still waiting. One list read, then one read per waiting id.

        The whole history list (up to INDEX_MAX) is walked once per tenant, the first time
        this is asked, so a waiting request saved before that list existed is still counted.
        Later calls do not walk it.
        """
        if self.store.get(PENDING_READY) is None:
            seen = set(self.store.lrange(PENDING_INDEX, 0, -1))
            for rid in self.store.lrange(INDEX_KEY, 0, INDEX_MAX - 1):
                if rid in seen:
                    continue
                req = self.get(rid)
                if req is not None and req.status == PENDING:
                    self.store.lpush(PENDING_INDEX, rid)
                    seen.add(rid)
            self.store.set(PENDING_READY, "1")
        count = 0
        seen_ids: set[str] = set()
        for rid in self.store.lrange(PENDING_INDEX, 0, -1):
            if rid in seen_ids:
                continue
            seen_ids.add(rid)
            req = self.get(rid)
            if req is None or req.status != PENDING:
                self.store.lrem(PENDING_INDEX, rid)
                continue
            count += 1
        return count

    def recent(self, limit: int = 100) -> list[AccessRequest]:
        out: list[AccessRequest] = []
        seen: set[str] = set()
        for rid in self.store.lrange(INDEX_KEY, 0, INDEX_MAX - 1):
            if rid in seen:
                continue
            seen.add(rid)
            req = self.get(rid)
            if req is not None:
                out.append(req)
            if len(out) >= limit:
                break
        return out


class TooManyPending(Exception):
    """An app already has as many requests waiting as it is allowed."""

    def __init__(self, limit: int):
        super().__init__(f"{limit} requests are already waiting")
        self.limit = limit


class AccessService:
    """What the MCP tools see: build `access_required` payloads and the two request tools."""

    def __init__(
        self,
        requests: AccessRequests,
        app_base_url: str,
        guard: Any,
        peek_name: Any,
        *,
        probe: Callable[[str], tuple[str, str | None]] | None = None,
        sharer_of: Callable[[str], str | None] | None = None,
        limited_sign_in: Callable[[], bool] | None = None,
        max_pending: int | None = MAX_PENDING_PER_APP,
    ):
        # One app's waiting requests are capped, so it cannot bury the Requests page.
        self.max_pending = max_pending
        self.requests = requests
        self.app_base_url = app_base_url.rstrip("/")
        self.guard = guard
        self.peek_name = peek_name
        # probe(file_id) -> ("found", name) | ("missing", None) | ("unknown", None).
        # Without it every denial files a request, as before.
        self.probe = probe
        # The paired person who shares file_id with this caller, if any (external.py).
        self.sharer_of = sharer_of
        # True when the stored sign-in only covers some files (drive.file): a file this
        # app cannot see may still exist, and the approval page can pick it.
        self.limited_sign_in = limited_sign_in

    def approval_url(self, request_id: str) -> str:
        return f"{self.app_base_url}/requests/{request_id}"

    def _payload(self, req: AccessRequest) -> dict[str, Any]:
        return {
            "error": "access_required",
            "request_id": req.id,
            "approval_url": self.approval_url(req.id),
            "file_id": req.file_id,
            "message": (
                "This item has not been shared with you. Show the user this approval link "
                f"and ask them to approve access: {self.approval_url(req.id)} . After they "
                "approve, retry the same call (or check with check_access_request using "
                "request_id)."
            ),
        }

    def _denied_payload(self, req: AccessRequest) -> dict[str, Any]:
        return {
            "error": "access_denied",
            "status": DENIED,
            "request_id": req.id,
            "file_id": req.file_id,
            "message": (
                "The owner denied access to this item. Do not retry it or ask again. "
                "Tell the user you cannot open it. If they change their mind, they can "
                "allow it themselves on the dashboard."
            ),
        }

    def _lookup(self, file_id: str) -> tuple[dict[str, Any] | None, str | None]:
        """(payload, name). A payload means no request should be filed for this id: the
        person cannot approve something that is not in their Drive."""
        if self.probe is None:
            return None, self.peek_name(file_id)
        state, name = self.probe(file_id)
        if state != "missing":
            return None, name
        owner = None
        if self.sharer_of is not None:
            try:
                owner = self.sharer_of(file_id)
            except Exception:
                owner = None
        if owner:
            return {
                "error": "shared_with_you",
                "file_id": file_id,
                "owner": owner,
                "message": (
                    f"This file is not in the user's own Drive. {owner} shares it with them "
                    f'through a pairing. Use read_shared_file(owner="{owner}", '
                    f'file_id="{file_id}") or download_shared_file with the same owner. '
                    "No approval is needed, and none was requested."
                ),
            }, None
        if self.limited_sign_in is not None and self.limited_sign_in():
            return None, None
        return {
            "error": "not_found",
            "file_id": file_id,
            "message": (
                "No file with this id is in the user's Google Drive, or their account cannot "
                "open it, so there is nothing to approve and no approval link was created. "
                "Check the id with search_files or list_folder, or call request_access "
                "without file_id and describe what you need."
            ),
        }, None

    def handle_denial(self, file_id: str, tool: str, token_name: str | None) -> dict[str, Any]:
        """Called by the policy wrapper when a tool is denied because of scope.

        A recent denial for the same file and assistant is returned as is: no new
        request is opened (see DENIAL_WINDOW). Ids that cannot be approved here (not in
        the person's Drive, or shared by a paired person) file no request either."""
        denied = self.requests.recent_denial(file_id, token_name)
        if denied is not None:
            return self._denied_payload(denied)
        unreachable, name = self._lookup(file_id)
        if unreachable is not None:
            return unreachable
        try:
            req, _created = self.requests.create(
                tool=tool,
                token_name=token_name,
                reason=f"{tool} was refused because the item is not shared with the assistant",
                file_id=file_id,
                file_name=name,
                max_pending=self.max_pending,
            )
        except TooManyPending as exc:
            return self._too_many(exc.limit, file_id)
        return self._payload(req)

    def _too_many(self, limit: int, file_id: str | None) -> dict[str, Any]:
        out: dict[str, Any] = {
            "error": "too_many_requests",
            "message": (
                f"This app already has {limit} access requests waiting for the user, so no "
                "new one was created and there is no approval link. Ask the user to approve "
                "or deny the waiting requests on the dashboard's Requests page, then try again."
            ),
        }
        if file_id:
            out["file_id"] = file_id
        return out

    def request_access(
        self,
        description: str,
        reason: str,
        file_id: str | None,
        *,
        token_name: str | None,
    ) -> dict[str, Any]:
        description_clean = clean_text(description, "description", required=True)
        reason_clean = clean_text(reason, "reason", required=True)
        if file_id is not None and file_id != "":
            validate_drive_id(file_id)
            if self.guard.is_in_scope(file_id):
                return {
                    "status": "already_allowed",
                    "file_id": file_id,
                    "message": "You already have access to this item.",
                }
            denied = self.requests.recent_denial(file_id, token_name)
            if denied is not None:
                return self._denied_payload(denied)
        else:
            file_id = None
        name = None
        if file_id is not None:
            unreachable, name = self._lookup(file_id)
            if unreachable is not None:
                return {"status": unreachable.pop("error"), **unreachable}
        try:
            req, _created = self.requests.create(
                tool="request_access",
                token_name=token_name,
                reason=reason_clean,
                file_id=file_id,
                file_name=name,
                description=description_clean,
                max_pending=self.max_pending,
            )
        except TooManyPending as exc:
            refused = self._too_many(exc.limit, file_id)
            return {"status": refused.pop("error"), **refused}
        return {
            "status": req.status,
            "request_id": req.id,
            "approval_url": self.approval_url(req.id),
            "message": (
                "Show the user this link so they can approve or deny the request: "
                f"{self.approval_url(req.id)} . Then call check_access_request with request_id."
            ),
        }

    def check_access_request(self, request_id: str) -> dict[str, Any]:
        validate_request_id(request_id)
        req = self.requests.get(request_id)
        if req is None:
            return {"request_id": request_id, "status": "not_found"}
        out: dict[str, Any] = {"request_id": req.id, "status": req.status, "file_id": req.file_id}
        if req.status == APPROVED:
            out["granted_id"] = req.granted_id
            out["granted_name"] = req.granted_name
            if req.granted_id:
                label = f"\u201c{req.granted_name}\u201d" if req.granted_name else "the item"
                out["message"] = (
                    f"Approved. The user shared {label} (id {req.granted_id}) with you. "
                    "Retry your call; if they shared a folder, use list_folder with that id."
                )
            else:
                out["message"] = "Approved. Retry your call."
        elif req.status == DENIED:
            out["message"] = "The user denied this request. Do not retry it."
        else:
            out["message"] = "Still waiting for the user. Remind them of the approval link."
            out["approval_url"] = self.approval_url(req.id)
        return out

"""Terminals and their login: the OAuth device flow (RFC 8628) and opaque tokens.

`botrbac login` asks for a device code, the person approves the short user code on
/device while signed in, and the CLI's polling then receives an access token (1 hour)
and a refresh token (90 days). Only `term:` keys are used, and these tokens are
accepted only on /api/terminal/*: /mcp never looks them up.
"""

import hashlib
import json
import secrets
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field, replace
from typing import Any

from .roles import DEFAULT_ROLE, TerminalRoles

DEVICE_TTL = 600
POLL_INTERVAL = 5
ACCESS_TTL = 3600
REFRESH_TTL = 90 * 24 * 3600
MAX_TERMINALS = 50
_USER_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ"  # no vowels: codes never spell words
_META_MAX = 80


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _clean(value: Any, limit: int = _META_MAX) -> str:
    text = "".join(ch if ch.isprintable() else " " for ch in str(value or ""))
    return " ".join(text.split())[:limit]


def normalize_user_code(code: str) -> str:
    letters = "".join(ch for ch in code.upper() if ch in _USER_ALPHABET)
    return f"{letters[:4]}-{letters[4:8]}" if len(letters) == 8 else ""


@dataclass(frozen=True)
class Terminal:
    id: str
    email: str
    name: str
    hostname: str = ""
    os: str = ""
    version: str = ""
    role_id: str = DEFAULT_ROLE
    created_at: float = 0.0
    last_seen: float = 0.0
    queued: int = 0
    unguarded: list[str] = field(default_factory=list)


class DeviceError(Exception):
    """An RFC 8628 error code (authorization_pending, slow_down, access_denied, ...)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass
class Terminals:
    store: Any
    roles: TerminalRoles
    # Whether this email may still use the app (ALLOWED_EMAILS, account not deleted).
    signed_in: Callable[[str], bool] = lambda _email: True
    clock: Callable[[], float] = field(default=time.time)

    # ---- device flow -----------------------------------------------------------

    def start(self, meta: dict[str, Any]) -> dict[str, Any]:
        device_code = secrets.token_urlsafe(32)
        letters = "".join(secrets.choice(_USER_ALPHABET) for _ in range(8))
        user_code = f"{letters[:4]}-{letters[4:]}"
        record = {
            "user_code": user_code,
            "status": "pending",
            "hostname": _clean(meta.get("hostname")),
            "os": _clean(meta.get("os")),
            "version": _clean(meta.get("version"), 20),
            "created": self.clock(),
            "last_poll": 0.0,
        }
        digest = _sha(device_code)
        self.store.set(f"term:device:{digest}", json.dumps(record), ex=DEVICE_TTL)
        self.store.set(f"term:usercode:{user_code}", digest, ex=DEVICE_TTL)
        return {
            "device_code": device_code,
            "user_code": user_code,
            "expires_in": DEVICE_TTL,
            "interval": POLL_INTERVAL,
        }

    def pending(self, user_code: str) -> tuple[str, dict[str, Any]] | None:
        code = normalize_user_code(user_code)
        digest = self.store.get(f"term:usercode:{code}") if code else None
        if not digest:
            return None
        raw = self.store.get(f"term:device:{digest}")
        if not raw:
            return None
        record = json.loads(raw)
        if record.get("user_code") != code or self.store.get(f"term:device:{digest}:decision"):
            return None
        return digest, record

    def _decide(self, digest: str, code: str, decision: dict[str, Any]) -> bool:
        """Record approve or refuse, once per code: two people (or two tabs) deciding at
        the same moment can't both win. The device record itself is never rewritten, so
        a poll in flight can't undo the decision."""
        # The decision itself is the claim (SET NX), so there is no moment between
        # claiming and deciding in which a crash could leave the code stuck.
        key = f"term:device:{digest}:decision"
        if not self.store.set_if_absent(key, json.dumps(decision), ex=DEVICE_TTL):
            return False
        self.store.delete(f"term:usercode:{code}")
        return True

    def approve(self, email: str, user_code: str, role_id: str, name: str) -> Terminal | None:
        found = self.pending(user_code)
        if found is None:
            return None
        digest, record = found
        if not self.signed_in(email):
            return None
        role = self.roles.get(email, role_id)
        if role is None:
            raise ValueError("Pick one of your roles for this terminal.")
        if len(self.for_person(email)) >= MAX_TERMINALS:
            raise ValueError(f"You can connect at most {MAX_TERMINALS} terminals.")
        terminal = Terminal(
            id="t_" + secrets.token_hex(8),
            email=email,
            name=_clean(name) or record.get("hostname") or "Terminal",
            hostname=record.get("hostname", ""),
            os=record.get("os", ""),
            version=record.get("version", ""),
            role_id=role.id,
            created_at=self.clock(),
        )
        # Saved and listed before the decision, so a poll that sees "approved" always
        # finds a terminal the person can see and disconnect.
        self._save(terminal)
        self.store.hset(f"term:terminals:{email}", terminal.id, "1")
        decision = {"status": "approved", "terminal_id": terminal.id}
        if not self._decide(digest, record["user_code"], decision):
            # Someone else decided first: this terminal never existed.
            self.store.hdel(f"term:terminals:{email}", terminal.id)
            self.store.delete(f"term:terminal:{terminal.id}")
            return None
        return terminal

    def deny(self, user_code: str) -> bool:
        found = self.pending(user_code)
        if found is None:
            return False
        digest, record = found
        return self._decide(digest, record["user_code"], {"status": "denied"})

    def poll(self, device_code: str) -> dict[str, Any]:
        """Tokens once approved; otherwise raises DeviceError with the RFC 8628 code."""
        key = f"term:device:{_sha(device_code)}" if device_code else ""
        raw = self.store.get(key) if key else None
        if not raw:
            raise DeviceError("expired_token")
        record = json.loads(raw)
        decided = self.store.get(f"{key}:decision")
        decision = json.loads(decided) if decided else {}
        if decision.get("status") == "denied":
            self.store.delete(key)
            raise DeviceError("access_denied")
        if decision.get("status") == "approved":
            # One use, even when two polls arrive together: the first to claim wins.
            if not self.store.set_if_absent(f"{key}:claimed", "1", ex=DEVICE_TTL):
                raise DeviceError("expired_token")
            self.store.delete(key)
            terminal = self.get(str(decision.get("terminal_id")))
            if terminal is None or not self._live(terminal):
                raise DeviceError("access_denied")
            return self._issue(terminal)
        # The last poll time has its own key, so polling never rewrites the record.
        now = self.clock()
        last = float(self.store.get(f"{key}:poll") or 0)
        # A second of slack: a client polling every 5 seconds lands a little early now
        # and then, and slow_down would make it wait 5 seconds longer from then on.
        too_soon = now - last < POLL_INTERVAL - 1
        remaining = max(1, int(DEVICE_TTL - (now - float(record.get("created") or now))))
        self.store.set(f"{key}:poll", str(now), ex=remaining)
        raise DeviceError("slow_down" if too_soon else "authorization_pending")

    # ---- tokens ----------------------------------------------------------------

    def _issue(self, terminal: Terminal) -> dict[str, Any]:
        access = "brt_at_" + secrets.token_urlsafe(32)
        refresh = "brt_rt_" + secrets.token_urlsafe(32)
        self.store.set(
            f"term:at:{_sha(access)}",
            json.dumps({"terminal_id": terminal.id}),
            ex=ACCESS_TTL,
        )
        self.store.set(f"term:rt:{_sha(refresh)}", terminal.id, ex=REFRESH_TTL)
        # The live refresh token is kept apart from the terminal record, so issuing
        # tokens never rewrites (and so never undoes) a role change or a rename.
        previous = self.store.get(self._rt_key(terminal.id))
        self.store.set(self._rt_key(terminal.id), _sha(refresh), ex=REFRESH_TTL)
        if previous and previous != _sha(refresh):
            self.store.delete(f"term:rt:{previous}")
        return {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "Bearer",
            "expires_in": ACCESS_TTL,
            "terminal_id": terminal.id,
        }

    def refresh(self, refresh_token: str) -> dict[str, Any] | None:
        if not refresh_token.startswith("brt_rt_"):
            return None
        digest = _sha(refresh_token)
        terminal_id = self.store.get(f"term:rt:{digest}")
        terminal = self.get(terminal_id) if terminal_id else None
        if terminal is None or not self._live(terminal):
            return None
        if self.store.get(self._rt_key(terminal.id)) != digest:
            return None
        if not self.signed_in(terminal.email):
            return None
        # Each refresh token works once, even for two requests at the same moment.
        if not self.store.set_if_absent(f"term:rt:{digest}:used", "1", ex=REFRESH_TTL):
            return None
        self.store.delete(f"term:rt:{digest}")
        return self._issue(terminal)

    def resolve(self, access_token: str) -> Terminal | None:
        if not access_token.startswith("brt_at_"):
            return None
        raw = self.store.get(f"term:at:{_sha(access_token)}")
        if not raw:
            return None
        try:
            terminal = self.get(str(json.loads(raw).get("terminal_id")))
        except ValueError:
            return None
        if terminal is None or not self._live(terminal) or not self.signed_in(terminal.email):
            return None
        return terminal

    def _live(self, terminal: Terminal) -> bool:
        """Still on the person's list. Disconnecting removes it from the list first, so
        a record written back by an edit racing the disconnect still grants nothing."""
        return self.store.hget(f"term:terminals:{terminal.email}", terminal.id) is not None

    # ---- terminal records ------------------------------------------------------

    @staticmethod
    def _rt_key(terminal_id: str) -> str:
        return f"term:terminal:{terminal_id}:rt"

    def _save(self, terminal: Terminal) -> None:
        self.store.set(f"term:terminal:{terminal.id}", json.dumps(asdict(terminal)))

    def touch(self, terminal_id: str, **seen: Any) -> None:
        """What the terminal itself reports (last_seen, queued, unguarded). Kept apart from
        the record the person edits, so a terminal checking in can never undo a role
        change or a rename made on the website at the same moment."""
        allowed = {k: v for k, v in seen.items() if k in ("last_seen", "queued", "unguarded")}
        if self.store.get(f"term:terminal:{terminal_id}") is None:
            return  # disconnected meanwhile: write nothing
        raw = self.store.get(f"term:terminal:{terminal_id}:seen")
        current = json.loads(raw) if raw else {}
        current.update(allowed)
        # Expires on its own, so a check-in racing a disconnect leaves nothing behind.
        self.store.set(f"term:terminal:{terminal_id}:seen", json.dumps(current), ex=REFRESH_TTL)

    def get(self, terminal_id: str | None) -> Terminal | None:
        if not terminal_id or not terminal_id.startswith("t_") or ":" in terminal_id:
            return None
        raw = self.store.get(f"term:terminal:{terminal_id}")
        if not raw:
            return None
        try:
            data = json.loads(raw)
            seen = self.store.get(f"term:terminal:{terminal_id}:seen")
            if seen:
                data.update(json.loads(seen))
            return Terminal(**{k: v for k, v in data.items() if k in Terminal.__dataclass_fields__})
        except (ValueError, TypeError):
            return None

    def owned(self, email: str, terminal_id: str) -> Terminal | None:
        terminal = self.get(terminal_id)
        return terminal if terminal is not None and terminal.email == email else None

    def for_person(self, email: str) -> list[Terminal]:
        out = [t for tid in self.store.hgetall(f"term:terminals:{email}") if (t := self.get(tid))]
        out.sort(key=lambda t: t.created_at, reverse=True)
        return out

    def update(self, email: str, terminal_id: str, **changes: Any) -> Terminal | None:
        terminal = self.owned(email, terminal_id)
        if terminal is None:
            return None
        updated = replace(terminal, **changes)
        self._save(updated)
        if not self._live(updated):
            # Disconnected while this edit was in flight: don't leave the record behind.
            self.store.delete(f"term:terminal:{terminal_id}")
            return None
        return updated

    def revoke(self, email: str, terminal_id: str) -> bool:
        terminal = self.owned(email, terminal_id)
        if terminal is None:
            return False
        # Off the list first: from this moment no token for it resolves (see _live).
        self.store.hdel(f"term:terminals:{email}", terminal_id)
        live = self.store.get(self._rt_key(terminal_id))
        if live:
            self.store.delete(f"term:rt:{live}")
        self.store.delete(self._rt_key(terminal_id))
        self.store.delete(f"term:terminal:{terminal_id}:seen")
        self.store.delete(f"term:terminal:{terminal_id}")
        return True

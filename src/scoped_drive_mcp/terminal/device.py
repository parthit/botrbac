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
        if record.get("status") != "pending" or record.get("user_code") != code:
            return None
        return digest, record

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
        self._save(terminal)
        self.store.hset(f"term:terminals:{email}", terminal.id, "1")
        record.update(status="approved", terminal_id=terminal.id)
        self.store.set(f"term:device:{digest}", json.dumps(record), ex=DEVICE_TTL)
        self.store.delete(f"term:usercode:{record['user_code']}")
        return terminal

    def deny(self, user_code: str) -> bool:
        found = self.pending(user_code)
        if found is None:
            return False
        digest, record = found
        record["status"] = "denied"
        self.store.set(f"term:device:{digest}", json.dumps(record), ex=DEVICE_TTL)
        self.store.delete(f"term:usercode:{record['user_code']}")
        return True

    def poll(self, device_code: str) -> dict[str, Any]:
        """Tokens once approved; otherwise raises DeviceError with the RFC 8628 code."""
        key = f"term:device:{_sha(device_code)}" if device_code else ""
        raw = self.store.get(key) if key else None
        if not raw:
            raise DeviceError("expired_token")
        record = json.loads(raw)
        status = record.get("status")
        if status == "denied":
            self.store.delete(key)
            raise DeviceError("access_denied")
        if status == "approved":
            # One use, even when two polls arrive together: the first to claim wins.
            if not self.store.set_if_absent(f"{key}:claimed", "1", ex=DEVICE_TTL):
                raise DeviceError("expired_token")
            self.store.delete(key)
            terminal = self.get(str(record.get("terminal_id")))
            if terminal is None:
                raise DeviceError("access_denied")
            return self._issue(terminal)
        now = self.clock()
        too_soon = now - float(record.get("last_poll") or 0) < POLL_INTERVAL
        record["last_poll"] = now
        remaining = max(1, int(DEVICE_TTL - (now - float(record.get("created") or now))))
        self.store.set(key, json.dumps(record), ex=remaining)
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
        if terminal is None or self.store.get(self._rt_key(terminal.id)) != digest:
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
        if terminal is None or not self.signed_in(terminal.email):
            return None
        return terminal

    # ---- terminal records ------------------------------------------------------

    @staticmethod
    def _rt_key(terminal_id: str) -> str:
        return f"term:terminal:{terminal_id}:rt"

    def _save(self, terminal: Terminal) -> None:
        self.store.set(f"term:terminal:{terminal.id}", json.dumps(asdict(terminal)))

    def get(self, terminal_id: str | None) -> Terminal | None:
        if not terminal_id or not terminal_id.startswith("t_"):
            return None
        raw = self.store.get(f"term:terminal:{terminal_id}")
        if not raw:
            return None
        try:
            data = json.loads(raw)
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
        return updated

    def revoke(self, email: str, terminal_id: str) -> bool:
        terminal = self.owned(email, terminal_id)
        if terminal is None:
            return False
        live = self.store.get(self._rt_key(terminal_id))
        if live:
            self.store.delete(f"term:rt:{live}")
        self.store.delete(self._rt_key(terminal_id))
        self.store.delete(f"term:terminal:{terminal_id}")
        self.store.hdel(f"term:terminals:{email}", terminal_id)
        return True

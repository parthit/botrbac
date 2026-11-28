"""The outgoing audit webhook: accepted Terminal rows, posted to the owner's URL.

The owner sets an https URL on Terminal → Activity. Saving it makes a secret, shown
once. After each audit batch is stored, the rows it added are posted there as JSON,
signed with HMAC-SHA256 over `<timestamp>.<body>`:

    X-Botrbac-Signature: sha256=<hex>
    X-Botrbac-Timestamp: <unix seconds>

Delivery is best effort: one try, a short timeout, and it never fails the upload. A row
that is not delivered is never resent; after MAX_FAILURES failures in a row, delivery
pauses for PAUSE seconds.

The URL is checked like a mailbox wake-up URL (wake.py): https on port 443, no user,
query or fragment, a name rather than an IP address, and every address it resolves to
must be public. It is checked again at each delivery and the connection goes to the
address that was checked, so a name that later points inside the network gets nothing.

Sealed fields (the command, the session task) are left out unless the owner ticks
"Include recorded commands"; then they are sent opened, as text.
"""

import contextlib
import hashlib
import hmac
import json
import logging
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from botrbac_cli import sealing

from .. import wake
from .provenance import DROPPED_FIELDS

logger = logging.getLogger(__name__)

WEBHOOK_KEY = "term:webhook:{email}"
LAST_KEY = "term:webhooklast:{email}"
TIMEOUT = 2.0
# After this many failed deliveries in a row, pause for PAUSE seconds: a dead receiver
# must not add the timeout to every upload. Saving the webhook again resets it.
MAX_FAILURES = 5
PAUSE = 15 * 60
MAX_URL = 512
# Stored sealed; the AAD is the event id for `command`, `<event id>:<name>` for others.
SEALED = ("command", "task")
_KEK_CONTEXT = b"botrbac terminal audit webhook v1"


class WebhookError(ValueError):
    pass


def check_url(raw: str, lookup: wake.Lookup | None = None) -> tuple[str, str, str]:
    """(host, path, address) for a URL that may receive rows, or WebhookError."""
    raw = (raw or "").strip()
    if not raw or len(raw) > MAX_URL:
        raise WebhookError("invalid_webhook_url")
    parts = urlsplit(raw)
    host = parts.hostname.lower().rstrip(".") if parts.hostname else ""
    try:
        port = parts.port
    except ValueError:
        raise WebhookError("invalid_webhook_url") from None
    if (
        parts.scheme != "https"
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or port not in (None, 443)
        or not host
        or wake._is_ip(host)
        or "." not in host
    ):
        raise WebhookError("invalid_webhook_url")
    try:
        addresses = (lookup or wake._lookup)(host)
    except OSError:
        raise WebhookError("webhook_host_unknown") from None
    if not addresses or any(not wake._public(a) for a in addresses):
        raise WebhookError("webhook_host_not_public")
    return host, parts.path or "/", addresses[0]


def sign(secret: str, ts: str, body: bytes) -> str:
    mac = hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def outgoing(row: dict[str, Any], command_key: Any, include_commands: bool) -> dict[str, Any]:
    """A row as it is posted: sealed fields dropped, or opened when the owner chose to
    include them (and recording is on, so the key is passed)."""
    out = {
        k: v
        for k, v in row.items()
        if k not in SEALED and k != "command_unreadable" and k not in DROPPED_FIELDS
    }
    if not include_commands or command_key is None:
        return out
    for name in SEALED:
        value = row.get(name)
        if not isinstance(value, str):
            continue
        aad = row["event_id"] if name == "command" else f"{row['event_id']}:{name}"
        try:
            out[name] = sealing.open_sealed(command_key, aad, value)
        except sealing.SealError:
            continue
    return out


@dataclass
class AuditWebhook:
    store: Any
    # From ENCRYPTION_KEY: the secret is stored encrypted. None: no webhook.
    signing_secret: str | None = None
    lookup: wake.Lookup | None = None
    poster: wake.Poster | None = None
    timeout: float = TIMEOUT
    clock: Callable[[], float] = field(default=time.time)

    @property
    def ready(self) -> bool:
        return bool(self.signing_secret)

    def _kek(self) -> bytes:
        assert self.signing_secret
        return hmac.new(self.signing_secret.encode(), _KEK_CONTEXT, hashlib.sha256).digest()

    @staticmethod
    def _slot(email: str) -> str:
        return f"terminal-audit:{email}"

    def get(self, email: str) -> dict[str, Any] | None:
        raw = self.store.get(WEBHOOK_KEY.format(email=email))
        if not raw:
            return None
        try:
            record = json.loads(raw)
        except ValueError:
            return None
        last = self.store.get(LAST_KEY.format(email=email))
        if last:
            with contextlib.suppress(ValueError):
                record["last"] = json.loads(last)
        return record

    def save(
        self, email: str, url: str, include_commands: bool, rotate: bool = False
    ) -> str | None:
        """Save the URL. Returns a new secret (to show once) when the URL changed, there
        was none, or `rotate`; None when the old secret still holds."""
        if not self.ready:
            raise WebhookError("webhook_disabled")
        check_url(url, self.lookup)
        current = self.get(email) or {}
        secret = None
        record = {
            "url": url.strip(),
            "include_commands": bool(include_commands),
            "updated": self.clock(),
        }
        if rotate or not current.get("ciphertext") or current.get("url") != record["url"]:
            secret = "whsec_" + secrets.token_urlsafe(32)
            ciphertext, nonce = wake.seal(secret, self._kek(), self._slot(email))
            record.update(ciphertext=ciphertext, nonce=nonce, hint=wake.hint(secret))
        else:
            record.update({k: current[k] for k in ("ciphertext", "nonce", "hint")})
        self.store.set(WEBHOOK_KEY.format(email=email), json.dumps(record))
        self.store.delete(LAST_KEY.format(email=email))
        return secret

    def clear(self, email: str) -> bool:
        had = self.get(email) is not None
        self.store.delete(WEBHOOK_KEY.format(email=email))
        self.store.delete(LAST_KEY.format(email=email))
        return had

    def deliver(
        self, email: str, rows: list[dict[str, Any]], command_key: Any = None
    ) -> int | None:
        """Post `rows` once. The HTTP status, or None when nothing was sent. Never raises."""
        if not rows or not self.ready:
            return None
        record = self.get(email)
        if not record:
            return None
        last = record.get("last") if isinstance(record.get("last"), dict) else {}
        failures = int(last.get("failures") or 0)
        if failures >= MAX_FAILURES and self.clock() - float(last.get("at") or 0) < PAUSE:
            return None  # paused: these rows are not sent, now or later
        status: int | None = None
        error = ""
        try:
            host, path, address = check_url(str(record["url"]), self.lookup)
            secret = wake.open_secret(
                str(record["ciphertext"]), str(record["nonce"]), self._kek(), self._slot(email)
            )
            include = bool(record.get("include_commands"))
            body = json.dumps(
                {
                    "v": 1,
                    "type": "botrbac.terminal.audit",
                    "rows": [outgoing(r, command_key, include) for r in rows],
                },
                separators=(",", ":"),
            ).encode()
            ts = str(int(self.clock()))
            request = {
                "hostname": host,
                "path": path,
                "address": address,
                "body": body.decode(),  # ASCII: json.dumps escapes the rest
                "content-type": "application/json",
                "user-agent": "botrbac-audit-webhook/1",
                "x-botrbac-event": "terminal.audit",
                "x-botrbac-timestamp": ts,
                "x-botrbac-signature": sign(secret, ts, body),
            }
            if self.poster is not None:
                status = self.poster(request)
            else:
                status = wake._post(request, self.timeout)
        except Exception as exc:  # noqa: BLE001 - delivery never fails the upload
            error = str(exc) if isinstance(exc, WebhookError) else type(exc).__name__
            logger.warning("terminal audit webhook not delivered: %s", error)
        with contextlib.suppress(Exception):  # only shown on the page
            self.store.set(
                LAST_KEY.format(email=email),
                json.dumps(
                    {
                        "at": self.clock(),
                        "status": status,
                        "error": error,
                        "failures": 0
                        if status is not None and 200 <= status < 300
                        else failures + 1,
                    }
                ),
                ex=30 * 24 * 3600,
            )
        return status

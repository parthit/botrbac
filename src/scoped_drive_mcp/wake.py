"""Wake a paired assistant with a small HTTPS ping. The message text stays in the mailbox."""

from __future__ import annotations

import base64
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from http.client import HTTPSConnection
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

SCHEMES = ("bearer", "bearer_and_x_automation_key", "claude_routine")
Lookup = Callable[[str], list[str]]
Poster = Callable[[dict[str, str]], int]

# Claude Code routine API trigger:
# POST https://api.anthropic.com/v1/claude_code/routines/<routine_id>/fire
# Bearer is a per-routine token (sk-ant-oat01-...) that can only start that one routine.
CLAUDE_ROUTINE_HOST = "api.anthropic.com"
CLAUDE_ROUTINE_PATH = re.compile(r"^/v1/claude_code/routines/[A-Za-z0-9_-]{1,128}/fire$")
CLAUDE_API_VERSION = "2023-06-01"
CLAUDE_ROUTINE_BETA = "experimental-cc-routine-2026-04-01"
DEFAULT_ALLOWLIST = ("api2.cursor.sh", CLAUDE_ROUTINE_HOST)


@dataclass(frozen=True)
class WakeSettings:
    enabled: bool = False
    kek: bytes | None = None
    allowlist: tuple[str, ...] = DEFAULT_ALLOWLIST
    timeout: float = 4.0
    lookup: Lookup | None = None
    poster: Poster | None = None

    @property
    def ready(self) -> bool:
        return self.enabled and self.kek is not None


def decode_kek(value: str | None) -> bytes | None:
    if value is None or not value.strip():
        return None
    try:
        raw = base64.b64decode(value.strip(), validate=True)
    except Exception:
        return None
    return raw if len(raw) == 32 else None


def _slot_tag(slot: str | None) -> bytes | None:
    return f"bridge:hook:{slot}".encode() if slot else None


def seal(secret: str, kek: bytes, slot: str | None = None) -> tuple[str, str]:
    """Encrypt a sender key. With `slot` (whose wake-up it is), it only opens for that
    slot, so a record copied to another person's or app's slot in the store is useless."""
    nonce = os.urandom(12)
    ciphertext = AESGCM(kek).encrypt(nonce, secret.encode(), _slot_tag(slot))
    return base64.b64encode(ciphertext).decode(), base64.b64encode(nonce).decode()


def open_secret(ciphertext: str, nonce: str, kek: bytes, slot: str | None = None) -> str:
    return (
        AESGCM(kek)
        .decrypt(base64.b64decode(nonce), base64.b64decode(ciphertext), _slot_tag(slot))
        .decode()
    )


def record_slot(record: dict[str, Any], slot: str | None) -> str | None:
    """The slot a saved record's key was sealed for: `slot` once the record says it is
    bound, None for one saved before keys were bound (opened as it was sealed)."""
    if not record.get("bound"):
        return None
    if not slot:
        raise ValueError("webhook_slot_unknown")
    return slot


def hint(secret: str) -> str:
    return secret[-4:]


def inspect_url(raw: str, allowlist: tuple[str, ...]) -> tuple[str, str]:
    parts = urlsplit(raw.strip())
    host = parts.hostname.lower().rstrip(".") if parts.hostname else ""
    if (
        parts.scheme != "https"
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or (parts.port not in (None, 443))
        or not host
        or _is_ip(host)
    ):
        raise ValueError("invalid_webhook_url")
    allowed = {item.lower() for item in allowlist}
    if host not in allowed:
        raise ValueError("webhook_host_not_allowed")
    return host, parts.path or "/"


def approve_url(
    raw: str, allowlist: tuple[str, ...], lookup: Lookup | None = None
) -> tuple[str, str, str]:
    host, path = inspect_url(raw, allowlist)
    addresses = (lookup or _lookup)(host)
    if not addresses or any(not _public(address) for address in addresses):
        raise ValueError("invalid_webhook_url")
    return host, path, addresses[0]


def payload(message: dict[str, Any]) -> dict[str, Any]:
    return {
        "v": 1,
        "type": "bot_bridge.message_available",
        "link_id": message["link_id"],
        "thread_id": message["thread_id"],
        "msg_id": message["msg_id"],
        "created_at": message["created_at"],
    }


def check_scheme_target(scheme: str, host: str, path: str) -> None:
    """A claude_routine wake may only go to a routine fire URL on api.anthropic.com,
    and that host only takes claude_routine wakes."""
    is_claude = host == CLAUDE_ROUTINE_HOST
    if scheme == "claude_routine" and not (is_claude and CLAUDE_ROUTINE_PATH.match(path)):
        raise ValueError("invalid_webhook_url")
    if is_claude and scheme != "claude_routine":
        raise ValueError("invalid_webhook_url")


def body_for(scheme: str, message: dict[str, Any]) -> str:
    """The ping body. Still ids and a timestamp only, never message text.

    A Claude routine reads only the `text` field (as a literal string) and ignores
    the rest, so the same JSON goes there as a string."""
    event = json.dumps(payload(message), separators=(",", ":"))
    if scheme == "claude_routine":
        return json.dumps({"text": event}, separators=(",", ":"))
    return event


def headers_for(scheme: str, secret: str) -> dict[str, str]:
    headers = {
        "content-type": "application/json",
        "accept": "application/json",
        "user-agent": "scoped-drive-mailbox/1",
    }
    if scheme == "bearer":
        headers["authorization"] = f"Bearer {secret}"
    elif scheme == "bearer_and_x_automation_key":
        headers["authorization"] = f"Bearer {secret}"
        headers["x-automation-key"] = secret
    elif scheme == "claude_routine":
        headers["authorization"] = f"Bearer {secret}"
        headers["anthropic-version"] = CLAUDE_API_VERSION
        headers["anthropic-beta"] = CLAUDE_ROUTINE_BETA
    else:
        raise ValueError("invalid_input")
    return headers


def deliver(
    settings: WakeSettings,
    record: dict[str, Any],
    message: dict[str, Any],
    slot: str | None = None,
) -> int:
    if not settings.kek:
        raise ValueError("webhook_disabled")
    scheme = str(record.get("scheme") or "bearer")
    host, path, address = approve_url(str(record["url"]), settings.allowlist, settings.lookup)
    check_scheme_target(scheme, host, path)
    secret = open_secret(
        str(record["ciphertext"]), str(record["nonce"]), settings.kek, record_slot(record, slot)
    )
    request = {
        "hostname": host,
        "path": path,
        "address": address,
        "body": body_for(scheme, message),
        **headers_for(scheme, secret),
    }
    if settings.poster is not None:
        status = settings.poster(request)
    else:
        status = _post(request, settings.timeout)
    # 202 and 204 are how many webhook receivers acknowledge a ping.
    if not 200 <= status < 300:
        raise ValueError(f"http_{status}")
    return status


def _post(request: dict[str, str], timeout: float = 4.0) -> int:
    class Pinned(HTTPSConnection):
        def connect(self) -> None:
            raw = socket.create_connection((request["address"], 443), self.timeout)
            context = self._context or ssl.create_default_context()
            self.sock = context.wrap_socket(raw, server_hostname=self.host)

    conn = Pinned(request["hostname"], timeout=timeout)
    try:
        conn.request(
            "POST",
            request["path"],
            body=request["body"],
            headers={
                key: value
                for key, value in request.items()
                if key not in {"hostname", "path", "address", "body"}
            },
        )
        response = conn.getresponse()
        response.read(512)
        return response.status
    finally:
        conn.close()


def _lookup(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _public(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    if parsed.version == 6 and getattr(parsed, "ipv4_mapped", None) is not None:
        parsed = parsed.ipv4_mapped
    if any(
        (
            parsed.is_private,
            parsed.is_loopback,
            parsed.is_link_local,
            parsed.is_multicast,
            parsed.is_reserved,
            parsed.is_unspecified,
        )
    ):
        return False
    carrier = ipaddress.ip_network("100.64.0.0/10")
    return not (isinstance(parsed, ipaddress.IPv4Address) and parsed in carrier)

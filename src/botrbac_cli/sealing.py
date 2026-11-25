"""Sealing what an agent ran, so only the website can read it.

When the person turns on "Record commands", the signed policy carries the server's
X25519 public key. The CLI seals each call's command (a shell command, or a tool's
arguments) to that key before the row is written to the queue on disk, so nothing on
the computer, the agent included, can read it back: not the queue, not `botrbac log`.
The website opens it with the private key, which is derived from its ENCRYPTION_KEY
and never leaves the server.

Format: "v1." + base64(ephemeral public key | nonce | AES-GCM ciphertext). The key is
HKDF-SHA256 over the X25519 shared secret, bound to both public keys; the row's
event_id is the associated data, so a sealed command cannot be moved onto another row.
"""

import base64
import hashlib
import hmac
import json
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_CONTEXT = b"botrbac terminal command sealing v1"
_INFO = b"botrbac sealed command v1"
PREFIX = "v1."
# Longest command kept, in characters. Longer ones (a Write with a whole file in it)
# are cut, and say so.
MAX_CHARS = 8000
# Longest sealed value the server accepts: MAX_CHARS of 4-byte UTF-8, plus the marker,
# key, nonce and tag, in base64.
MAX_SEALED = len(PREFIX) + 4 * ((32 + 12 + 16 + 4 * MAX_CHARS + 200 + 2) // 3)


class SealError(ValueError):
    pass


def key_from_secret(secret: str) -> X25519PrivateKey:
    seed = hmac.new(secret.strip().encode(), _CONTEXT, hashlib.sha256).digest()
    return X25519PrivateKey.from_private_bytes(seed)


def public_key_text(key: X25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def _raw(key: X25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _aead(shared: bytes, ephemeral: bytes, recipient: bytes) -> AESGCM:
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=ephemeral + recipient, info=_INFO).derive(
        shared
    )
    return AESGCM(key)


def clip(text: str) -> str:
    if len(text) <= MAX_CHARS:
        return text
    return text[:MAX_CHARS] + f" … [cut: {len(text) - MAX_CHARS} more characters]"


def describe(value: Any) -> str:
    """A tool call's input as text: a string as is, anything else as compact JSON."""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        return str(value)


def seal(public_key: str, event_id: str, text: str) -> str:
    try:
        recipient = X25519PublicKey.from_public_bytes(base64.b64decode(public_key))
    except (ValueError, TypeError) as exc:
        raise SealError("bad public key") from exc
    ephemeral = X25519PrivateKey.generate()
    eph_raw, rec_raw = _raw(ephemeral.public_key()), _raw(recipient)
    nonce = os.urandom(12)
    sealed = _aead(ephemeral.exchange(recipient), eph_raw, rec_raw).encrypt(
        # A lone surrogate (from JSON "\ud800", or argv that was not UTF-8) becomes "?":
        # the command is still recorded, and sealing never raises on its text.
        nonce,
        clip(text).encode("utf-8", errors="replace"),
        event_id.encode(),
    )
    return PREFIX + base64.b64encode(eph_raw + nonce + sealed).decode()


def open_sealed(key: X25519PrivateKey, event_id: str, value: str) -> str:
    if not isinstance(value, str) or not value.startswith(PREFIX) or len(value) > MAX_SEALED:
        raise SealError("not a sealed command")
    try:
        blob = base64.b64decode(value[len(PREFIX) :], validate=True)
    except (ValueError, TypeError) as exc:
        raise SealError("not base64") from exc
    if len(blob) < 32 + 12 + 16:
        raise SealError("too short")
    eph_raw, nonce, sealed = blob[:32], blob[32:44], blob[44:]
    try:
        shared = key.exchange(X25519PublicKey.from_public_bytes(eph_raw))
        plain = _aead(shared, eph_raw, _raw(key.public_key())).decrypt(
            nonce, sealed, event_id.encode()
        )
    except (InvalidTag, ValueError) as exc:
        raise SealError("cannot be opened") from exc
    return plain.decode("utf-8", errors="replace")

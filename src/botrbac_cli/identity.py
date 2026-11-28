"""This terminal's own key: proof that an audit batch came from this computer.

`botrbac login` makes an Ed25519 key pair. The private half stays in
`terminal_key.json` (mode 0600, next to credentials.json); the public half goes to the
website with the device-code token exchange, which stores it on the terminal. A terminal
that logged in before keys existed makes one and registers it at its next token refresh.

Each `POST /api/terminal/audit` is signed. It is a simplified HTTP Message Signatures
(RFC 9421): the signature covers the method, the path, the sha256 of the exact body, a
timestamp, a one-time nonce and the key id, and travels in these headers:

    X-Botrbac-Signature: ed25519=<base64>
    X-Botrbac-Key-Id:    k_<16 hex>
    X-Botrbac-Timestamp: <unix seconds>
    X-Botrbac-Nonce:     <random>

The server accepts a signature for 5 minutes and each nonce once. The same module
verifies on the server (scoped_drive_mcp.terminal.identity).
"""

import base64
import contextlib
import hashlib
import json
import os
import re
import secrets
import tempfile
import time
from collections.abc import Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from . import state

KEY_FILE = "terminal_key.json"
PENDING_FILE = "terminal_key.pending.json"
AUDIT_PATH = "/api/terminal/audit"
WINDOW = 300  # seconds a signature is good for, either side of the server's clock
SIGNATURE = "x-botrbac-signature"
KEY_ID = "x-botrbac-key-id"
TIMESTAMP = "x-botrbac-timestamp"
NONCE = "x-botrbac-nonce"
# 401 codes the server answers for a signature problem (not a token problem).
SIGNATURE_ERRORS = frozenset(
    {"signature_required", "invalid_signature", "signature_expired", "replayed_signature"}
)
_NONCE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
_VERSION = re.compile(r"^[A-Za-z0-9]{1,32}$")


class SignatureError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


# ---- keys ----------------------------------------------------------------------------


def public_text(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def parse_public(text: Any) -> Ed25519PublicKey | None:
    """A public key as the CLI sends it (base64 of 32 bytes), or None."""
    if not isinstance(text, str) or len(text) > 64:
        return None
    try:
        raw = base64.b64decode(text, validate=True)
        return Ed25519PublicKey.from_public_bytes(raw) if len(raw) == 32 else None
    except ValueError:
        return None


def key_id(public_key: str) -> str:
    raw = base64.b64decode(public_key)
    return "k_" + hashlib.sha256(raw).hexdigest()[:16]


def _record(key: Ed25519PrivateKey) -> dict[str, Any]:
    seed = key.private_bytes_raw()
    public = public_text(key)
    return {
        "private_key": base64.b64encode(seed).decode(),
        "public_key": public,
        "key_id": key_id(public),
        "created": time.time(),
    }


def _load(name: str) -> tuple[Ed25519PrivateKey, dict[str, Any]] | None:
    data = state.read_json(name)
    if not isinstance(data, dict):
        return None
    try:
        key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(data["private_key"]))
    except (KeyError, TypeError, ValueError):
        return None
    return key, {**data, "public_key": public_text(key), "key_id": key_id(public_text(key))}


def _write_new(name: str, *, replace: bool) -> None:
    """A fresh key in `name`, readable by this user only. Without `replace`, a key that
    another process wrote first wins (several gateways can start at once)."""
    record = _record(Ed25519PrivateKey.generate())
    target = state.home() / name
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".tmp-key-")
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(record, handle)
        os.chmod(tmp, 0o600)
        if replace:
            os.replace(tmp, target)
        else:
            with contextlib.suppress(FileExistsError):
                os.link(tmp, target)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)


def ensure() -> dict[str, Any]:
    """This terminal's key record (public_key, key_id), made now if there is none."""
    found = _load(KEY_FILE)
    if found is None:
        _write_new(KEY_FILE, replace=(state.home() / KEY_FILE).exists())
        found = _load(KEY_FILE)
    if found is None:
        raise OSError("could not write the terminal key")
    return {"public_key": found[1]["public_key"], "key_id": found[1]["key_id"]}


def new_pending() -> str:
    """A fresh key for a login in progress. It replaces the terminal's key only once the
    login succeeds, so a login that fails leaves the current terminal working."""
    _write_new(PENDING_FILE, replace=True)
    found = _load(PENDING_FILE)
    assert found is not None
    return found[1]["public_key"]


def pending_public() -> str | None:
    found = _load(PENDING_FILE)
    return found[1]["public_key"] if found else None


def promote_pending() -> None:
    source = state.home() / PENDING_FILE
    if source.exists():
        os.replace(source, state.home() / KEY_FILE)


def forget() -> None:
    state.remove(KEY_FILE)
    state.remove(PENDING_FILE)


# ---- signing -------------------------------------------------------------------------


def canonical(method: str, path: str, body: bytes, ts: str, nonce: str, kid: str) -> bytes:
    """What the signature covers, one line per component (RFC 9421's signature base,
    simplified)."""
    lines = [
        "botrbac-request-v1",
        f'"@method": {method.upper()}',
        f'"@path": {path}',
        f'"content-digest": sha-256={hashlib.sha256(body).hexdigest()}',
        f'"x-botrbac-timestamp": {ts}',
        f'"x-botrbac-nonce": {nonce}',
        f'"keyid": {kid}',
    ]
    return "\n".join(lines).encode()


def sign_request(method: str, path: str, body: bytes) -> dict[str, str]:
    """The signature headers for one request, or none when this computer cannot make a
    key (the server then takes the batch as unsigned, if this terminal has no key)."""
    try:
        ensure()
        found = _load(KEY_FILE)
    except OSError:
        return {}
    if found is None:
        return {}
    key, record = found
    ts = str(int(time.time()))
    nonce = secrets.token_urlsafe(18)
    kid = record["key_id"]
    signature = key.sign(canonical(method, path, body, ts, nonce, kid))
    return {
        "X-Botrbac-Signature": "ed25519=" + base64.b64encode(signature).decode(),
        "X-Botrbac-Key-Id": kid,
        "X-Botrbac-Timestamp": ts,
        "X-Botrbac-Nonce": nonce,
    }


def verify(
    public_key: str,
    method: str,
    path: str,
    body: bytes,
    headers: Mapping[str, str],
    now: float,
) -> str:
    """The nonce of a good signature (the caller makes sure it is used once). Raises
    SignatureError with the code to answer otherwise."""
    h = {str(k).lower(): str(v) for k, v in headers.items()}
    value = h.get(SIGNATURE, "")
    if not value:
        raise SignatureError("signature_required")
    scheme, _, b64 = value.partition("=")
    kid, ts, nonce = h.get(KEY_ID, ""), h.get(TIMESTAMP, ""), h.get(NONCE, "")
    if scheme.strip().lower() != "ed25519" or not _NONCE.match(nonce) or not ts.isdigit():
        raise SignatureError("invalid_signature")
    if kid != key_id(public_key):
        raise SignatureError("invalid_signature")
    if abs(now - int(ts)) > WINDOW:
        raise SignatureError("signature_expired")
    key = parse_public(public_key)
    try:
        if key is None:
            raise ValueError("bad key")
        key.verify(
            base64.b64decode(b64, validate=True), canonical(method, path, body, ts, nonce, kid)
        )
    except (InvalidSignature, ValueError):
        raise SignatureError("invalid_signature") from None
    return nonce


# ---- what a row carries ----------------------------------------------------------------


def policy_version() -> str | None:
    """The version of the cached policy the row was decided under, if there is one."""
    cached = state.read_json("policy.json")
    pol = cached.get("policy") if isinstance(cached, dict) else None
    version = pol.get("version") if isinstance(pol, dict) else None
    return version if isinstance(version, str) and _VERSION.match(version) else None

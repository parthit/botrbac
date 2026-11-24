"""The server signs each policy it hands out; the CLI checks the signature before using it.

The public key is pinned at login (it comes with the tokens, over HTTPS). After that, a
cached policy whose signature does not match blocks every tool, so editing
~/.config/botrbac/policy.json cannot widen a role. The private key is derived from the
server's ENCRYPTION_KEY and never leaves the server.
"""

import base64
import hashlib
import hmac
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_CONTEXT = b"botrbac terminal policy signing v1"


def canonical(body: dict[str, Any]) -> bytes:
    unsigned = {k: v for k, v in body.items() if k != "signature"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()


def key_from_secret(secret: str) -> Ed25519PrivateKey:
    seed = hmac.new(secret.strip().encode(), _CONTEXT, hashlib.sha256).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key_text(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def sign(key: Ed25519PrivateKey, body: dict[str, Any]) -> str:
    return base64.b64encode(key.sign(canonical(body))).decode()


def verify(public_key: str, body: dict[str, Any]) -> bool:
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key))
        key.verify(base64.b64decode(str(body.get("signature") or "")), canonical(body))
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True

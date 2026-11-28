"""Views over a store: the key prefix, signed records and the per-person (actor) view."""

import base64
import hashlib
import hmac
import json
import logging
import re
import time
from typing import Any

from ..auth import current_actor
from .backends import (
    KeyValueStore,
)
from .keys import (
    AGENT_ROLES_KEY,
    ALLOWLIST_KEY,
    EXTERNAL_ALLOWLIST_KEY,
    KEY_PREFIX,
    NOTION_ALLOWLIST_KEY,
    ONEDRIVE_ALLOWLIST_KEY,
    TWITTER_ALLOWLIST_KEY,
)

# One logger name for the whole package, the one `store.py` logged under.
logger = logging.getLogger("scoped_drive_mcp.store")


class PrefixedStore:
    """Namespaces every key so the Redis database can be shared safely."""

    def __init__(self, inner: KeyValueStore, prefix: str = KEY_PREFIX):
        self.inner = inner
        self.prefix = prefix
        self.kind = getattr(inner, "kind", "custom")

    def __getattr__(self, name: str) -> Any:
        method = getattr(self.inner, name)

        def call(key: str, *args: Any, **kwargs: Any) -> Any:
            return method(self.prefix + key, *args, **kwargs)

        return call


# ---- signed records ---------------------------------------------------------
#
# The records that decide who may reach what: allowlist and Sharing entries, connected
# apps (grants, roles, access and refresh tokens, codes) and pairings. Each is stored
# with an HMAC over its key, its hash field and its value, made with a key derived from
# ENCRYPTION_KEY. Someone who can write to the store but does not have that key cannot
# add one or move one to another person's keys. It does not stop them deleting a
# record, or putting back an older value they copied from the same place, so the code
# that reads these records must not treat a missing one as permission.
SIGNED_MARK = "s1."
_MAC_LENGTH = 43  # urlsafe base64 of 32 bytes, without padding
_MAC_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_SIGNED_HASHES = frozenset(
    {
        ALLOWLIST_KEY,
        EXTERNAL_ALLOWLIST_KEY,
        NOTION_ALLOWLIST_KEY,
        ONEDRIVE_ALLOWLIST_KEY,
        TWITTER_ALLOWLIST_KEY,
        AGENT_ROLES_KEY,
    }
)
# Single records signed like the hashes above. `drops:folder` is the one folder a saved
# held file may be written into: the whole allowlist of the save guard.
_SIGNED_KEYS = frozenset({"drops:folder"})
# Mail and held files: who a message is for, and which pieces are a held file. The text
# and the pieces are encrypted, but the server decrypts them for whoever the record
# names, so the record itself must be one a store writer cannot rewrite or copy to
# another person's keys.
_SIGNED_CONTENT_HASHES = frozenset({"drops:index"})
_SIGNED_CONTENT_PREFIXES = ("bridge:msg:", "drops:part:")
# Records of those kinds (and `drops:folder`) written before they were signed are read
# until this moment even when REQUIRE_SIGNED_RECORDS is on, so mail and held files in
# flight at the upgrade are not lost. Mail lives 14 days and a held file DROP_HOLD_HOURS,
# so every such record has expired well before it. 2027-01-15T00:00:00Z.
UNSIGNED_CONTENT_UNTIL = 1799971200
_SIGNED_PREFIXES = (
    *_SIGNED_CONTENT_PREFIXES,
    "oauth:",
    "bridge:link:",
    "bridge:appr:",
    "bridge:peer:",
    "bridge:user:",
    "bridge:invite:",
    "bridge:selfclaim:",
    # Bot RBAC Terminal: roles, terminals, their tokens, revoked sessions, settings.
    "term:roles:",
    "term:terminal:",
    "term:terminals:",
    "term:device:",
    "term:usercode:",
    "term:at:",
    "term:rt:",
    "term:revoked:",
    # Whether commands are recorded: a store writer must not be able to switch it on.
    "term:settings:",
    # Where audit rows are posted, and whether commands go with them.
    "term:webhook:",
    # A request from a paired person (peer_requests.py): it names who would get access.
    "peerreq:",
)
_TENANT_PREFIX = re.compile(r"^u:[^:]+:")
# A tenant email becomes part of `u:{email}:`, so it may not hold the ':' delimiter (the
# prefix would end early and `signs()` would read the rest as the record name), nor
# whitespace, control characters or Redis glob characters.
_TENANT_EMAIL = re.compile(r"^[^@:\s\x00-\x1f\x7f*?\[\]\\]+@[^@:\s\x00-\x1f\x7f*?\[\]\\]+$")


def usable_email(email: object) -> bool:
    """Whether `email` can name one person's records (see `tenant_prefix`)."""
    return isinstance(email, str) and bool(_TENANT_EMAIL.fullmatch(email))


def tenant_prefix(email: str) -> str:
    """`u:{email}:` for one person's keys. Refuses an address that could break the prefix."""
    if not isinstance(email, str) or not _TENANT_EMAIL.fullmatch(email):
        raise ValueError("not a usable account address")
    return f"u:{email}:"


def signs(key: str) -> bool:
    """Whether `key` (as seen below the `sdm:` prefix) holds a signed record."""
    name = _TENANT_PREFIX.sub("", key, count=1)
    return (
        name in _SIGNED_HASHES
        or name in _SIGNED_KEYS
        or name in _SIGNED_CONTENT_HASHES
        or name.startswith(_SIGNED_PREFIXES)
    )


def _unsigned_still_read(key: str, now: float) -> bool:
    """Whether an unsigned `key` is one of the kinds signed only since mail and held
    files were, and the time for reading those unsigned has not run out."""
    if now >= UNSIGNED_CONTENT_UNTIL:
        return False
    name = _TENANT_PREFIX.sub("", key, count=1)
    return (
        name in _SIGNED_KEYS
        or name in _SIGNED_CONTENT_HASHES
        or name.startswith(_SIGNED_CONTENT_PREFIXES)
    )


def signing_key(encryption_key: str) -> bytes:
    return hmac.new(
        encryption_key.strip().encode(), b"botrbac record signing v1", hashlib.sha256
    ).digest()


def purpose_fernet(encryption_key: str, purpose: str) -> Any:
    """A Fernet made from ENCRYPTION_KEY for one use only (`purpose` names it).

    The Drive sign-in vault uses ENCRYPTION_KEY itself. Everything else that encrypts
    gets its own derived key, so no other feature can be made to decrypt a vault record,
    or to produce one, for someone who can write to the store.
    """
    from cryptography.fernet import Fernet

    digest = hmac.new(
        encryption_key.strip().encode(),
        f"botrbac {purpose} encryption v1".encode(),
        hashlib.sha256,
    ).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def _looks_signed(raw: str) -> bool:
    """`s1.<43 characters>.<value>`. A value from before signing that merely starts with
    `s1.` (an address such as s1.smith@example.com) is not mistaken for a signed one."""
    head = len(SIGNED_MARK) + _MAC_LENGTH
    return (
        raw.startswith(SIGNED_MARK)
        and len(raw) > head
        and raw[head] == "."
        and all(ch in _MAC_CHARS for ch in raw[len(SIGNED_MARK) : head])
    )


class SignedStore:
    """Signs the records `signs()` names on the way in and checks them on the way out.

    A record whose signature does not match is treated as missing. An unsigned record is
    accepted until `require` is on (REQUIRE_SIGNED_RECORDS), and is treated as missing
    after that. Reading never writes: records from before signing are signed by
    `sign_existing_records`, one compare-and-swap each, so a change made at the same
    moment is never undone. Every other key passes straight through."""

    def __init__(self, inner: KeyValueStore, key: bytes, *, require: bool = False):
        self.inner = inner
        self.kind = getattr(inner, "kind", "custom")
        self.require = require
        self._key = key
        self.refused = 0

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def _mac(self, key: str, field: str | None, value: str) -> str:
        message = "\x00".join((key, field or "", value)).encode()
        digest = hmac.new(self._key, message, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    def _seal(self, key: str, field: str | None, value: str) -> str:
        return f"{SIGNED_MARK}{self._mac(key, field, value)}.{value}"

    def _open(self, key: str, field: str | None, raw: Any) -> str | None:
        """The value, or None when the record is refused."""
        if not isinstance(raw, str):
            return raw
        if _looks_signed(raw):
            mac, _, value = raw[len(SIGNED_MARK) :].partition(".")
            if hmac.compare_digest(mac.encode(), self._mac(key, field, value).encode()):
                return value
            self.refused += 1
            logger.warning("stored record failed its signature check and was ignored")
            return None
        if self.require and not _unsigned_still_read(key, time.time()):
            self.refused += 1
            logger.warning("unsigned stored record ignored (REQUIRE_SIGNED_RECORDS is on)")
            return None
        return raw

    def get(self, key: str) -> str | None:
        raw = self.inner.get(key)
        if raw is None or not signs(key):
            return raw
        return self._open(key, None, raw)

    def getdel(self, key: str) -> str | None:
        if not signs(key):
            consume = getattr(self.inner, "getdel", None)
            if consume is not None:
                return consume(key)
            raw = self.inner.get(key)
            if raw is not None:
                self.inner.delete(key)
            return raw
        # Checked before it is taken, so a record that is refused is left where it is.
        raw = self.inner.get(key)
        if raw is None or self._open(key, None, raw) is None:
            return None
        consume = getattr(self.inner, "getdel", None)
        if consume is not None:
            taken = consume(key)
        else:
            taken = self.inner.get(key)
            if taken is not None:
                self.inner.delete(key)
        if taken is None:
            return None  # someone else took it first
        return self._open(key, None, taken)

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        stored = self._seal(key, None, value) if signs(key) else value
        if ex is None:
            self.inner.set(key, stored)
        else:
            self.inner.set(key, stored, ex=ex)

    def set_if_absent(self, key: str, value: str, ex: int) -> bool:
        stored = self._seal(key, None, value) if signs(key) else value
        return self.inner.set_if_absent(key, stored, ex=ex)

    def hset(self, key: str, field: str, value: str) -> None:
        self.inner.hset(key, field, self._seal(key, field, value) if signs(key) else value)

    def hget(self, key: str, field: str) -> str | None:
        raw = self.inner.hget(key, field)
        if raw is None or not signs(key):
            return raw
        return self._open(key, field, raw)

    def hgetall(self, key: str) -> dict[str, str]:
        rows = self.inner.hgetall(key)
        if not signs(key):
            return rows
        out: dict[str, str] = {}
        for name, raw in rows.items():
            value = self._open(key, name, raw)
            if value is not None:
                out[name] = value
        return out

    def replace(self, key: str, old: str, new: str) -> bool:
        """Change a string from `old` to `new` only if it still says `old`. Keeps its expiry.
        False both when it changed meanwhile and when the store below cannot swap; a
        caller that retries ends with a plain write either way."""
        raw = self.inner.get(key)
        swap = getattr(self.inner, "swap", None)
        if raw is None or swap is None or self._open(key, None, raw) != old:
            return False
        return bool(swap(key, raw, self._seal(key, None, new) if signs(key) else new))

    def hreplace(self, key: str, field: str, old: str, new: str) -> bool:
        """Change one hash field from `old` to `new` only if it still says `old`."""
        raw = self.inner.hget(key, field)
        swap = getattr(self.inner, "hswap", None)
        if raw is None or swap is None or self._open(key, field, raw) != old:
            return False
        stored = self._seal(key, field, new) if signs(key) else new
        return bool(swap(key, field, raw, stored))

    def sign_in_place(self, key: str, field: str | None = None) -> str:
        """Sign one record from before signing. "signed", "already", "missing", or
        "failed" when it changed at that moment or this store cannot swap."""
        raw = self.inner.get(key) if field is None else self.inner.hget(key, field)
        if raw is None:
            return "missing"
        if _looks_signed(raw):
            return "already"
        sealed = self._seal(key, field, raw)
        try:
            if field is None:
                swap = getattr(self.inner, "swap", None)
                done = swap is not None and swap(key, raw, sealed)
            else:
                swap = getattr(self.inner, "hswap", None)
                done = swap is not None and swap(key, field, raw, sealed)
        except Exception:
            logger.warning("could not sign a stored record in place", exc_info=True)
            done = False
        return "signed" if done else "failed"


def sign_existing_records(
    store: Any, people: list[str], admin_email: str | None
) -> tuple[int, int]:
    """Sign every record from before signing. Returns (signed, could not be signed).

    Run from the admin page before REQUIRE_SIGNED_RECORDS is turned on, and again until
    the second number is 0: a record that changed at the moment it was being signed is
    left for the next run. Authorization codes and other records that live for minutes
    are left out."""
    if not isinstance(store, SignedStore):
        return 0, 0
    tally = {"signed": 0, "failed": 0}

    def sign(key: str, field: str | None = None) -> None:
        outcome = store.sign_in_place(key, field)
        if outcome in tally:
            tally[outcome] += 1

    def sign_hash(key: str) -> list[str]:
        fields = list(store.inner.hgetall(key))
        for name in fields:
            sign(key, name)
        return fields

    for email in dict.fromkeys([*people, *([admin_email] if admin_email else [])]):
        if email != admin_email and not _TENANT_EMAIL.fullmatch(email):
            continue
        prefix = "" if email == admin_email else tenant_prefix(email)
        sign_hash(prefix + ALLOWLIST_KEY)
        sign_hash(prefix + EXTERNAL_ALLOWLIST_KEY)
        for name in _SIGNED_KEYS:
            sign(prefix + name)
        for link_id in sign_hash(f"bridge:user:{email}"):
            sign(f"bridge:link:{link_id}")
            sign_hash(f"bridge:appr:{link_id}")
            sign(f"bridge:peer:{link_id}")
            sign(f"bridge:selfclaim:{link_id}")
            try:
                code = json.loads(store.get(f"bridge:link:{link_id}") or "{}").get("invite_code")
            except (ValueError, AttributeError):
                code = None
            if isinstance(code, str) and code:
                sign(f"bridge:invite:{code}")
    sign_hash("oauth:clients")
    for grant_id in sign_hash("oauth:grants"):
        for name in ("role", "rolechosen", "seen", "revoked"):
            sign(f"oauth:{name}:{grant_id}")
        try:
            grant = json.loads(store.hget("oauth:grants", grant_id) or "{}")
        except ValueError:
            continue
        for digest in grant.get("access_hashes") or []:
            sign(f"oauth:at:{digest}")
        if grant.get("refresh_hash"):
            sign(f"oauth:rt:{grant['refresh_hash']}")
    return tally["signed"], tally["failed"]


class ActorStore:
    """Routes each call to the admin's legacy keys or to `u:{email}:`.

    The actor comes from `current_actor`. When it is unset, or it is the admin, keys stay
    where they are today (`allowlist`, `vault:...`). Other people get a prefix on this
    already-prefixed store, so the full key is `sdm:u:eve@example.com:allowlist`.
    """

    def __init__(self, inner: KeyValueStore, admin_email: str | None):
        self.inner = inner
        self.admin_email = admin_email
        self.kind = getattr(inner, "kind", "custom")

    def _key(self, key: str) -> str:
        actor = current_actor.get()
        if not actor or actor == self.admin_email:
            return key
        return tenant_prefix(actor) + key

    def hreplace(self, key: str, field: str, old: str, new: str) -> bool:
        """Change one hash field from `old` to `new` only if it still says `old`. False
        when it changed meanwhile, or the store below cannot do that in one step."""
        # `hreplace` first: on a signing store it checks and signs, `hswap` would not.
        for name in ("hreplace", "hswap"):
            swap = getattr(self.inner, name, None)
            if swap is not None:
                return bool(swap(self._key(key), field, old, new))
        return False

    def get(self, key: str) -> str | None:
        return self.inner.get(self._key(key))

    def getdel(self, key: str) -> str | None:
        full = self._key(key)
        consume = getattr(self.inner, "getdel", None)
        if consume is None:
            value = self.inner.get(full)
            if value is not None:
                self.inner.delete(full)
            return value
        return consume(full)

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.inner.set(self._key(key), value, ex=ex)

    def delete(self, key: str) -> None:
        self.inner.delete(self._key(key))

    def hset(self, key: str, field: str, value: str) -> None:
        self.inner.hset(self._key(key), field, value)

    def hget(self, key: str, field: str) -> str | None:
        return self.inner.hget(self._key(key), field)

    def hgetall(self, key: str) -> dict[str, str]:
        return self.inner.hgetall(self._key(key))

    def hdel(self, key: str, field: str) -> None:
        self.inner.hdel(self._key(key), field)

    def lpush(self, key: str, value: str) -> None:
        self.inner.lpush(self._key(key), value)

    def ltrim(self, key: str, start: int, stop: int) -> None:
        self.inner.ltrim(self._key(key), start, stop)

    def lrange(self, key: str, start: int, stop: int) -> list[str]:
        return self.inner.lrange(self._key(key), start, stop)

    def lrem(self, key: str, value: str) -> int:
        return int(self.inner.lrem(self._key(key), value))

    def lreplace(self, key: str, old: str, new: str) -> int:
        return int(self.inner.lreplace(self._key(key), old, new))

    def ldrop_expired(self, key: str, now: int) -> int:
        return int(self.inner.ldrop_expired(self._key(key), now))

    def incr(self, key: str, ex: int) -> int:
        return int(self.inner.incr(self._key(key), ex))

    def set_if_absent(self, key: str, value: str, ex: int) -> bool:
        return bool(self.inner.set_if_absent(self._key(key), value, ex))

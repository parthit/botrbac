"""Persistent state: the allowlist, access requests' storage, encrypted OAuth tokens and the
activity log.

Everything sits behind the small `KeyValueStore` protocol so tests (and local development
without Redis) can use `MemoryStore`. In production `RedisStore` talks to Upstash Redis over
its REST API, and `PostgresStore` talks to Neon when `DATABASE_URL` or `POSTGRES_URL` is set.
All keys are prefixed with `sdm:`. The admin keeps the original key names. Every other person
is stored under `u:{email}:` on that same prefixed store.
"""

import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, Protocol

from .auth import current_actor

logger = logging.getLogger(__name__)

KEY_PREFIX = "sdm:"
ALLOWLIST_KEY = "allowlist"
# Items this person lets other people's assistants read (see external.py). Kept apart from
# ALLOWLIST_KEY so an item can be shared with paired people without the owner's own bot
# seeing it, and the reverse.
EXTERNAL_ALLOWLIST_KEY = "ext_allowlist"
# Who may read an external entry: AUDIENCE_LINKED is anyone with an active pairing with
# the owner; otherwise the entry names the people (a tuple of emails) who may read it.
AUDIENCE_LINKED = "linked"
# What the people who can see an external entry may do with it.
ACCESS_READ = "read"
ACCESS_EDIT = "edit"
# What this person's assistants may read in Notion (chosen on Files, "From Notion").
NOTION_ALLOWLIST_KEY = "notion_allowlist"
# What this person's assistants may read in OneDrive (chosen on Files, "From OneDrive").
ONEDRIVE_ALLOWLIST_KEY = "onedrive_allowlist"
ACTIVITY_KEY = "activity"
ACTIVITY_MAX = 500
# A paired person's repeated call is written to the owner's Activity this often.
GUEST_ROW_EVERY = 3600
OWNER_TOKEN_KEY = "vault:owner_refresh_token"  # noqa: S105 - a key name
BOT_TOKEN_KEY = "vault:bot_refresh_token"  # noqa: S105 - a key name
NOTION_TOKEN_KEY = "vault:notion_token"  # noqa: S105 - a key name
ONEDRIVE_TOKEN_KEY = "vault:onedrive_token"  # noqa: S105 - a key name
USERS_INDEX = "users:index"
REDIS_IMPORT_FLAG = "sdm:meta:redis_admin_imported"  # on the raw store, not the sdm: view
REDIS_IMPORT_LOCK = "sdm:meta:redis_admin_import_lock"  # same raw store; expires if a copy dies
REDIS_IMPORT_LOCK_TTL = 120

_REPLACE_LIST_SCRIPT = """
redis.call('DEL', KEYS[1])
for i = #ARGV, 1, -1 do
    redis.call('LPUSH', KEYS[1], ARGV[i])
end
return #ARGV
"""

_INCR_SCRIPT = """
local n = redis.call('INCR', KEYS[1])
if tonumber(n) == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return n
"""

# Inbox rows are msg_id|link_id|created_epoch|expires_epoch|unread. Anything else is dropped.
_INBOX_TOKEN = re.compile(r"^([^|]+)\|([^|]+)\|([0-9]+)\|([0-9]+)\|([01])$")

_LDROP_EXPIRED_SCRIPT = """
local now = tonumber(ARGV[1])
local removed = 0
for _, value in ipairs(redis.call('LRANGE', KEYS[1], 0, -1)) do
    local expires = string.match(value, '^[^|]+|[^|]+|[0-9]+|([0-9]+)|[01]$')
    if (not expires) or (tonumber(expires) <= now) then
        redis.call('LREM', KEYS[1], 0, value)
        removed = removed + 1
    end
end
return removed
"""

_SWAP_SCRIPT = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
    redis.call('SET', KEYS[1], ARGV[2], 'KEEPTTL')
    return 1
end
return 0
"""

_HSWAP_SCRIPT = """
if redis.call('HGET', KEYS[1], ARGV[1]) == ARGV[2] then
    redis.call('HSET', KEYS[1], ARGV[1], ARGV[3])
    return 1
end
return 0
"""

_LREPLACE_SCRIPT = """
local replaced = 0
local index = 0
while true do
    local value = redis.call('LINDEX', KEYS[1], index)
    if not value then
        break
    end
    if value == ARGV[1] then
        redis.call('LSET', KEYS[1], index, ARGV[2])
        replaced = replaced + 1
    end
    index = index + 1
end
return replaced
"""


def parse_inbox_token(value: str) -> tuple[str, str, int, int, bool] | None:
    """Return msg_id, link_id, created epoch, expires epoch, and unread. None if malformed."""
    match = _INBOX_TOKEN.fullmatch(value)
    if match is None:
        return None
    return (
        match.group(1),
        match.group(2),
        int(match.group(3)),
        int(match.group(4)),
        match.group(5) == "1",
    )


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class KeyValueStore(Protocol):
    def get(self, key: str) -> str | None: ...
    def set(self, key: str, value: str, ex: int | None = None) -> None: ...
    def delete(self, key: str) -> None: ...
    def hset(self, key: str, field: str, value: str) -> None: ...
    def hget(self, key: str, field: str) -> str | None: ...
    def hgetall(self, key: str) -> dict[str, str]: ...
    def hdel(self, key: str, field: str) -> None: ...
    def lpush(self, key: str, value: str) -> None: ...
    def ltrim(self, key: str, start: int, stop: int) -> None: ...
    def lrange(self, key: str, start: int, stop: int) -> list[str]: ...
    def lrem(self, key: str, value: str) -> int: ...
    def lreplace(self, key: str, old: str, new: str) -> int: ...
    def ldrop_expired(self, key: str, now: int) -> int: ...
    def incr(self, key: str, ex: int) -> int: ...
    def set_if_absent(self, key: str, value: str, ex: int) -> bool: ...


class MemoryStore:
    """Thread-safe in-memory store with expiring keys. Per process only."""

    kind = "memory"

    def __init__(self, clock: Callable[[], float] = time.time):
        self._clock = clock
        self._lock = threading.Lock()
        self._values: dict[str, tuple[float | None, Any]] = {}

    def _live(self, key: str) -> Any:
        item = self._values.get(key)
        if item is None:
            return None
        expires, value = item
        if expires is not None and expires <= self._clock():
            del self._values[key]
            return None
        return value

    def get(self, key: str) -> str | None:
        with self._lock:
            value = self._live(key)
            return value if isinstance(value, str) else None

    def getdel(self, key: str) -> str | None:
        """Return a string value and delete it. Expired keys disappear."""
        with self._lock:
            value = self._live(key)
            self._values.pop(key, None)
            return value if isinstance(value, str) else None

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        with self._lock:
            expires = self._clock() + ex if ex else None
            self._values[key] = (expires, value)

    def swap(self, key: str, old: str, new: str) -> bool:
        """Replace a string with `new` only if it still says `old`. Keeps its expiry."""
        with self._lock:
            if self._live(key) != old:
                return False
            self._values[key] = (self._values[key][0], new)
            return True

    def hswap(self, key: str, field: str, old: str, new: str) -> bool:
        """Replace one hash field with `new` only if it still says `old`."""
        with self._lock:
            current = self._live(key)
            if not isinstance(current, dict) or current.get(field) != old:
                return False
            current[field] = new
            return True

    def delete(self, key: str) -> None:
        with self._lock:
            self._values.pop(key, None)

    def hset(self, key: str, field: str, value: str) -> None:
        with self._lock:
            current = self._live(key)
            if not isinstance(current, dict):
                current = {}
                self._values[key] = (None, current)
            current[field] = value

    def hget(self, key: str, field: str) -> str | None:
        with self._lock:
            current = self._live(key)
            return current.get(field) if isinstance(current, dict) else None

    def hgetall(self, key: str) -> dict[str, str]:
        with self._lock:
            current = self._live(key)
            return dict(current) if isinstance(current, dict) else {}

    def hdel(self, key: str, field: str) -> None:
        with self._lock:
            current = self._live(key)
            if isinstance(current, dict):
                current.pop(field, None)

    def lpush(self, key: str, value: str) -> None:
        with self._lock:
            current = self._live(key)
            if not isinstance(current, list):
                current = []
                self._values[key] = (None, current)
            current.insert(0, value)

    def ltrim(self, key: str, start: int, stop: int) -> None:
        with self._lock:
            current = self._live(key)
            if isinstance(current, list):
                end = None if stop == -1 else stop + 1
                current[:] = current[start:end]

    def lrange(self, key: str, start: int, stop: int) -> list[str]:
        with self._lock:
            current = self._live(key)
            if not isinstance(current, list):
                return []
            end = None if stop == -1 else stop + 1
            return list(current[start:end])

    def lrem(self, key: str, value: str) -> int:
        with self._lock:
            current = self._live(key)
            if not isinstance(current, list):
                return 0
            kept = [item for item in current if item != value]
            removed = len(current) - len(kept)
            current[:] = kept
            return removed

    def lreplace(self, key: str, old: str, new: str) -> int:
        with self._lock:
            current = self._live(key)
            if not isinstance(current, list):
                return 0
            replaced = 0
            for index, item in enumerate(current):
                if item == old:
                    current[index] = new
                    replaced += 1
            return replaced

    def ldrop_expired(self, key: str, now: int) -> int:
        """Remove expired or malformed inbox rows. A concurrent push of a new row stays."""
        with self._lock:
            current = self._live(key)
            if not isinstance(current, list):
                return 0
            kept = []
            removed = 0
            for item in current:
                parsed = parse_inbox_token(item)
                if parsed is not None and parsed[3] > now:
                    kept.append(item)
                else:
                    removed += 1
            current[:] = kept
            return removed

    def incr(self, key: str, ex: int) -> int:
        """Add one and return the new value. An expired key starts again at 1."""
        with self._lock:
            current = self._live(key)
            if isinstance(current, str) and current.isdigit():
                # A fixed window, like Redis: the first hit sets the expiry, later ones keep it.
                expires = self._values[key][0]
                count = int(current) + 1
            else:
                expires = self._clock() + ex if ex else None
                count = 1
            self._values[key] = (expires, str(count))
            return count

    def set_if_absent(self, key: str, value: str, ex: int) -> bool:
        """Set `key` only when it is missing or expired. True when this caller won."""
        with self._lock:
            if self._live(key) is not None:
                return False
            expires = self._clock() + ex if ex else None
            self._values[key] = (expires, value)
            return True

    def replace_list(self, key: str, items: list[str]) -> None:
        """Replace a list in one step. `items` is newest-first, the same order as `lrange`."""
        with self._lock:
            self._values[key] = (None, list(items))


class RedisStore:
    """Upstash Redis over its REST API (`upstash-redis`)."""

    kind = "redis"

    def __init__(self, url: str, token: str):
        from upstash_redis import Redis

        self._redis = Redis(url=url, token=token, allow_telemetry=False, rest_retries=1)

    def get(self, key: str) -> str | None:
        value = self._redis.get(key)
        return None if value is None else str(value)

    def getdel(self, key: str) -> str | None:
        value = self._redis.getdel(key)
        return None if value is None else str(value)

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        self._redis.set(key, value, ex=ex)

    def delete(self, key: str) -> None:
        self._redis.delete(key)

    def hset(self, key: str, field: str, value: str) -> None:
        self._redis.hset(key, field, value)

    def hget(self, key: str, field: str) -> str | None:
        value = self._redis.hget(key, field)
        return None if value is None else str(value)

    def hgetall(self, key: str) -> dict[str, str]:
        return {str(k): str(v) for k, v in (self._redis.hgetall(key) or {}).items()}

    def hdel(self, key: str, field: str) -> None:
        self._redis.hdel(key, field)

    def lpush(self, key: str, value: str) -> None:
        self._redis.lpush(key, value)

    def ltrim(self, key: str, start: int, stop: int) -> None:
        self._redis.ltrim(key, start, stop)

    def lrange(self, key: str, start: int, stop: int) -> list[str]:
        return [str(v) for v in self._redis.lrange(key, start, stop) or []]

    def lrem(self, key: str, value: str) -> int:
        removed = self._redis.lrem(key, 0, value)
        return int(removed or 0)

    def swap(self, key: str, old: str, new: str) -> bool:
        return bool(self._redis.eval(_SWAP_SCRIPT, keys=[key], args=[old, new]))

    def hswap(self, key: str, field: str, old: str, new: str) -> bool:
        return bool(self._redis.eval(_HSWAP_SCRIPT, keys=[key], args=[field, old, new]))

    def lreplace(self, key: str, old: str, new: str) -> int:
        value = self._redis.eval(_LREPLACE_SCRIPT, keys=[key], args=[old, new])
        return int(value or 0)

    def ldrop_expired(self, key: str, now: int) -> int:
        """Remove expired or malformed inbox rows inside one script. New pushes stay."""
        value = self._redis.eval(_LDROP_EXPIRED_SCRIPT, keys=[key], args=[now])
        return int(value or 0)

    def incr(self, key: str, ex: int) -> int:
        """INCR and, on the first hit, EXPIRE. One script so the TTL cannot be skipped."""
        value = self._redis.eval(_INCR_SCRIPT, keys=[key], args=[ex])
        return int(value)

    def set_if_absent(self, key: str, value: str, ex: int) -> bool:
        """SET NX with a TTL. True only when this caller created the key."""
        result = self._redis.set(key, value, nx=True, ex=ex)
        return result is True or result == "OK"

    def replace_list(self, key: str, items: list[str]) -> None:
        """Replace a list in one Redis script so two copies cannot interleave item by item."""
        self._redis.eval(_REPLACE_LIST_SCRIPT, keys=[key], args=list(items))


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
    {ALLOWLIST_KEY, EXTERNAL_ALLOWLIST_KEY, NOTION_ALLOWLIST_KEY, ONEDRIVE_ALLOWLIST_KEY}
)
_SIGNED_PREFIXES = (
    "oauth:",
    "bridge:link:",
    "bridge:appr:",
    "bridge:peer:",
    "bridge:user:",
    "bridge:invite:",
    "bridge:selfclaim:",
    # Bot RBAC Terminal: roles, terminals, their tokens and revoked sessions.
    "term:roles:",
    "term:terminal:",
    "term:terminals:",
    "term:device:",
    "term:usercode:",
    "term:at:",
    "term:rt:",
    "term:revoked:",
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
    return name in _SIGNED_HASHES or name.startswith(_SIGNED_PREFIXES)


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
        if self.require:
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


# A fixed window, like Redis and MemoryStore: the expiry is set when the counter starts
# (a new row, an expired one, or one that did not hold a number) and kept on later hits,
# so steady traffic cannot keep pushing the window out.
_PG_INCR_SQL = """
INSERT INTO sdm_kv (key, value, expires_at)
VALUES (%s, '1', NOW() + (%s * INTERVAL '1 second'))
ON CONFLICT (key) DO UPDATE
SET value = (
    CASE
        WHEN sdm_kv.expires_at IS NOT NULL AND sdm_kv.expires_at <= NOW() THEN 1
        WHEN sdm_kv.value ~ '^[0-9]+$' THEN sdm_kv.value::bigint + 1
        ELSE 1
    END
)::text,
expires_at = (
    CASE
        WHEN sdm_kv.expires_at IS NOT NULL AND sdm_kv.expires_at <= NOW()
            THEN EXCLUDED.expires_at
        WHEN sdm_kv.value ~ '^[0-9]+$' THEN sdm_kv.expires_at
        ELSE EXCLUDED.expires_at
    END
)
RETURNING value
"""


class PostgresStore:
    """One short Postgres connection per call. No pool (serverless-friendly)."""

    kind = "postgres"

    def __init__(self, url: str):
        self._url = url
        self._ready = False
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return "PostgresStore(kind='postgres')"

    def _connect(self) -> Any:
        import psycopg

        # Neon’s pooled URL is PgBouncer in transaction mode, which rejects
        # psycopg’s automatic prepared statements.
        conn = psycopg.connect(
            self._url, autocommit=True, connect_timeout=5, prepare_threshold=None
        )
        self._ensure(conn)
        return conn

    def _ensure(self, conn: Any) -> None:
        if self._ready:
            return
        with self._lock:
            if self._ready:
                return
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sdm_kv (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    expires_at TIMESTAMPTZ
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sdm_hash (
                    key TEXT NOT NULL,
                    field TEXT NOT NULL,
                    value TEXT NOT NULL,
                    PRIMARY KEY (key, field)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sdm_list (
                    pos BIGSERIAL PRIMARY KEY,
                    key TEXT NOT NULL,
                    value TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS sdm_list_key_pos ON sdm_list (key, pos DESC)")
            self._ready = True

    def _run(self, fn: Callable[[Any], Any]) -> Any:
        with self._connect() as conn:
            return fn(conn)

    def get(self, key: str) -> str | None:
        def read(conn: Any) -> str | None:
            conn.execute(
                """
                DELETE FROM sdm_kv
                WHERE key = %s AND expires_at IS NOT NULL AND expires_at <= NOW()
                """,
                (key,),
            )
            found = conn.execute(
                """
                SELECT value FROM sdm_kv
                WHERE key = %s AND (expires_at IS NULL OR expires_at > NOW())
                """,
                (key,),
            ).fetchone()
            return None if found is None else str(found[0])

        return self._run(read)

    def getdel(self, key: str) -> str | None:
        def take(conn: Any) -> str | None:
            conn.execute(
                """
                DELETE FROM sdm_kv
                WHERE key = %s AND expires_at IS NOT NULL AND expires_at <= NOW()
                """,
                (key,),
            )
            row = conn.execute(
                """
                DELETE FROM sdm_kv
                WHERE key = %s AND (expires_at IS NULL OR expires_at > NOW())
                RETURNING value
                """,
                (key,),
            ).fetchone()
            return None if row is None else str(row[0])

        return self._run(take)

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        def write(conn: Any) -> None:
            if ex:
                conn.execute(
                    """
                    INSERT INTO sdm_kv (key, value, expires_at)
                    VALUES (%s, %s, NOW() + (%s * INTERVAL '1 second'))
                    ON CONFLICT (key) DO UPDATE
                    SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at
                    """,
                    (key, value, ex),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO sdm_kv (key, value, expires_at)
                    VALUES (%s, %s, NULL)
                    ON CONFLICT (key) DO UPDATE
                    SET value = EXCLUDED.value, expires_at = NULL
                    """,
                    (key, value),
                )

        self._run(write)

    def delete(self, key: str) -> None:
        def wipe(conn: Any) -> None:
            conn.execute("DELETE FROM sdm_kv WHERE key = %s", (key,))
            conn.execute("DELETE FROM sdm_hash WHERE key = %s", (key,))
            conn.execute("DELETE FROM sdm_list WHERE key = %s", (key,))

        self._run(wipe)

    def hset(self, key: str, field: str, value: str) -> None:
        def write(conn: Any) -> None:
            conn.execute(
                """
                INSERT INTO sdm_hash (key, field, value) VALUES (%s, %s, %s)
                ON CONFLICT (key, field) DO UPDATE SET value = EXCLUDED.value
                """,
                (key, field, value),
            )

        self._run(write)

    def swap(self, key: str, old: str, new: str) -> bool:
        def write(conn: Any) -> bool:
            row = conn.execute(
                """
                UPDATE sdm_kv SET value = %s
                WHERE key = %s AND value = %s AND (expires_at IS NULL OR expires_at > NOW())
                RETURNING 1
                """,
                (new, key, old),
            ).fetchone()
            return row is not None

        return bool(self._run(write))

    def hswap(self, key: str, field: str, old: str, new: str) -> bool:
        def write(conn: Any) -> bool:
            row = conn.execute(
                """
                UPDATE sdm_hash SET value = %s
                WHERE key = %s AND field = %s AND value = %s
                RETURNING 1
                """,
                (new, key, field, old),
            ).fetchone()
            return row is not None

        return bool(self._run(write))

    def hget(self, key: str, field: str) -> str | None:
        def read(conn: Any) -> str | None:
            row = conn.execute(
                "SELECT value FROM sdm_hash WHERE key = %s AND field = %s", (key, field)
            ).fetchone()
            return None if row is None else str(row[0])

        return self._run(read)

    def hgetall(self, key: str) -> dict[str, str]:
        def read(conn: Any) -> dict[str, str]:
            rows = conn.execute(
                "SELECT field, value FROM sdm_hash WHERE key = %s", (key,)
            ).fetchall()
            return {str(field): str(value) for field, value in rows}

        return self._run(read)

    def hdel(self, key: str, field: str) -> None:
        self._run(
            lambda conn: conn.execute(
                "DELETE FROM sdm_hash WHERE key = %s AND field = %s", (key, field)
            )
        )

    def lpush(self, key: str, value: str) -> None:
        self._run(
            lambda conn: conn.execute(
                "INSERT INTO sdm_list (key, value) VALUES (%s, %s)", (key, value)
            )
        )

    def ltrim(self, key: str, start: int, stop: int) -> None:
        def trim(conn: Any) -> None:
            if stop != -1 and stop < start:
                conn.execute("DELETE FROM sdm_list WHERE key = %s", (key,))
                return
            offset = max(start, 0)
            limit = 1_000_000 if stop == -1 else stop - offset + 1
            conn.execute(
                """
                DELETE FROM sdm_list WHERE key = %s AND pos NOT IN (
                    SELECT pos FROM sdm_list WHERE key = %s
                    ORDER BY pos DESC OFFSET %s LIMIT %s
                )
                """,
                (key, key, offset, limit),
            )

        self._run(trim)

    def lrange(self, key: str, start: int, stop: int) -> list[str]:
        def read(conn: Any) -> list[str]:
            if stop != -1 and stop < start:
                return []
            offset = max(start, 0)
            limit = 1_000_000 if stop == -1 else stop - offset + 1
            rows = conn.execute(
                """
                SELECT value FROM sdm_list WHERE key = %s
                ORDER BY pos DESC OFFSET %s LIMIT %s
                """,
                (key, offset, limit),
            ).fetchall()
            return [str(row[0]) for row in rows]

        return self._run(read)

    def lrem(self, key: str, value: str) -> int:
        def remove(conn: Any) -> int:
            result = conn.execute(
                "DELETE FROM sdm_list WHERE key = %s AND value = %s",
                (key, value),
            )
            return int(result.rowcount or 0)

        return int(self._run(remove))

    def lreplace(self, key: str, old: str, new: str) -> int:
        def swap(conn: Any) -> int:
            result = conn.execute(
                "UPDATE sdm_list SET value = %s WHERE key = %s AND value = %s",
                (new, key, old),
            )
            return int(result.rowcount or 0)

        return int(self._run(swap))

    def ldrop_expired(self, key: str, now: int) -> int:
        """Remove expired or malformed inbox rows. A row inserted concurrently stays."""

        def drop(conn: Any) -> int:
            malformed = conn.execute(
                """
                DELETE FROM sdm_list
                WHERE key = %s
                  AND value !~ '^[^|]+\\|[^|]+\\|[0-9]+\\|[0-9]+\\|[01]$'
                """,
                (key,),
            )
            expired = conn.execute(
                """
                DELETE FROM sdm_list
                WHERE key = %s
                  AND value ~ '^[^|]+\\|[^|]+\\|[0-9]+\\|[0-9]+\\|[01]$'
                  AND split_part(value, '|', 4)::bigint <= %s
                """,
                (key, now),
            )
            return int(malformed.rowcount or 0) + int(expired.rowcount or 0)

        return int(self._run(drop))

    def incr(self, key: str, ex: int) -> int:
        """Add one in a single statement. An expired row starts again at 1."""

        def bump(conn: Any) -> int:
            row = conn.execute(_PG_INCR_SQL, (key, ex)).fetchone()
            return int(row[0])

        return int(self._run(bump))

    def set_if_absent(self, key: str, value: str, ex: int) -> bool:
        """Insert a row only when the key is missing. An expired row is cleared first."""

        def claim(conn: Any) -> bool:
            with conn.transaction():
                conn.execute(
                    """
                    DELETE FROM sdm_kv
                    WHERE key = %s AND expires_at IS NOT NULL AND expires_at <= NOW()
                    """,
                    (key,),
                )
                row = conn.execute(
                    """
                    INSERT INTO sdm_kv (key, value, expires_at)
                    VALUES (%s, %s, NOW() + (%s * INTERVAL '1 second'))
                    ON CONFLICT (key) DO NOTHING
                    RETURNING key
                    """,
                    (key, value, ex),
                ).fetchone()
                return row is not None

        return bool(self._run(claim))

    def replace_list(self, key: str, items: list[str]) -> None:
        """Delete and rewrite a list in one transaction. `items` is newest-first."""

        def write(conn: Any) -> None:
            with conn.transaction():
                conn.execute("DELETE FROM sdm_list WHERE key = %s", (key,))
                for item in reversed(items):
                    conn.execute(
                        "INSERT INTO sdm_list (key, value) VALUES (%s, %s)",
                        (key, item),
                    )

        self._run(write)


# ---- allowlist -------------------------------------------------------------


@dataclass(frozen=True)
class AllowEntry:
    id: str
    name: str
    mime_type: str
    permission_id: str | None
    granted_at: str = field(default_factory=utc_now)
    request_id: str | None = None
    # The bot address `permission_id` belongs to; None when no Drive share was made.
    shared_with: str | None = None
    # Only set on external entries: who may read it. AUDIENCE_LINKED (or None, from rows
    # written before audiences existed) is every paired person; a tuple names the people.
    audience: str | tuple[str, ...] | None = None
    # Only on external entries: when this share stops working (ISO UTC), or None.
    expires_at: str | None = None
    # Only on external entries: "read" (default), or "edit" to let the people who can see it
    # have their assistants create, edit and rename inside it (never trash or move).
    access: str = "read"

    def to_json(self) -> str:
        data = asdict(self)
        if isinstance(self.audience, tuple):
            data["audience"] = list(self.audience)
        return json.dumps(data, separators=(",", ":"))

    @property
    def for_everyone(self) -> bool:
        return not isinstance(self.audience, tuple)

    def expired(self, now: str | None = None) -> bool:
        return bool(self.expires_at) and str(self.expires_at) <= (now or utc_now())

    def editable_by(self, guest: str | None, now: str | None = None) -> bool:
        return self.access == ACCESS_EDIT and self.readable_by(guest, now)

    def readable_by(self, guest: str | None, now: str | None = None) -> bool:
        """Whether `guest` (a paired person) may read this external entry right now. No
        guest means nobody: a caller that forgot to say who is reading gets nothing."""
        if not guest or self.expired(now):
            return False
        return self.for_everyone or guest.strip().lower() in self.audience  # type: ignore[operator]

    @classmethod
    def from_json(cls, raw: str) -> "AllowEntry":
        data = json.loads(raw)
        return cls(
            id=str(data["id"]),
            name=str(data.get("name", "")),
            mime_type=str(data.get("mime_type", "")),
            permission_id=data.get("permission_id"),
            granted_at=str(data.get("granted_at", "")),
            request_id=data.get("request_id"),
            shared_with=data.get("shared_with"),
            audience=_audience(data.get("audience")),
            expires_at=data.get("expires_at") or None,
            access=ACCESS_EDIT if data.get("access") == ACCESS_EDIT else ACCESS_READ,
        )


def _audience(value: Any) -> str | tuple[str, ...] | None:
    if isinstance(value, list | tuple):
        return tuple(sorted({str(v).strip().lower() for v in value if str(v).strip()}))
    return value if value is None else str(value)


class Allowlist:
    """A hash of AllowEntry records. `key` picks which list: the owner's own-bot list
    (ALLOWLIST_KEY) or the list shared with paired people (EXTERNAL_ALLOWLIST_KEY)."""

    def __init__(self, store: KeyValueStore, key: str = ALLOWLIST_KEY):
        self.store = store
        self.key = key

    def entries(self) -> dict[str, AllowEntry]:
        out: dict[str, AllowEntry] = {}
        for file_id, raw in self.store.hgetall(self.key).items():
            try:
                out[file_id] = AllowEntry.from_json(raw)
            except (ValueError, KeyError, TypeError):
                continue
        return out

    def get(self, file_id: str) -> AllowEntry | None:
        raw = self.store.hget(self.key, file_id)
        return AllowEntry.from_json(raw) if raw else None

    def add(self, entry: AllowEntry) -> None:
        self.store.hset(self.key, entry.id, entry.to_json())

    def remove(self, file_id: str) -> None:
        self.store.hdel(self.key, file_id)

    def mime_map(self) -> dict[str, str]:
        return {fid: e.mime_type for fid, e in self.entries().items()}

    def entries_for(self, guest: str | None) -> dict[str, AllowEntry]:
        """External entries `guest` may read now: shared with everyone paired, or with
        them by name, and not expired."""
        now = utc_now()
        return {fid: e for fid, e in self.entries().items() if e.readable_by(guest, now)}

    def mime_map_for(self, guest: str | None) -> dict[str, str]:
        return {fid: e.mime_type for fid, e in self.entries_for(guest).items()}

    def edit_map_for(self, guest: str | None) -> dict[str, str]:
        """The entries `guest`'s assistant may write into: shared with them and editable."""
        now = utc_now()
        return {fid: e.mime_type for fid, e in self.entries().items() if e.editable_by(guest, now)}

    def forget_person(self, person: str) -> list[str]:
        """Take `person` off every item that names them. Items shared with everyone are
        unchanged. Returns the ids changed; an item that named only them then names
        nobody, and the Sharing page says so."""
        who = person.strip().lower()
        changed: list[str] = []
        swap = getattr(self.store, "hreplace", None) or getattr(self.store, "hswap", None)
        for file_id in list(self.entries()):
            # Each item is changed only if it still says what was just read. The owner
            # may stop sharing it, or change who it names, at the same moment: a plain
            # write here would put the old entry back.
            for _attempt in range(5):
                raw = self.store.hget(self.key, file_id)
                if not raw:
                    break
                try:
                    entry = AllowEntry.from_json(raw)
                except (ValueError, KeyError, TypeError):
                    break
                if entry.for_everyone or who not in entry.audience:  # type: ignore[operator]
                    break
                rest = tuple(a for a in entry.audience if a != who)  # type: ignore[union-attr]
                updated = replace(entry, audience=rest)
                if swap is None:
                    self.add(updated)
                elif not swap(self.key, file_id, raw, updated.to_json()):
                    continue
                changed.append(file_id)
                break
            else:
                # It kept changing, or this store cannot swap. Taking the person off
                # matters more than the race, so write it plainly, as before.
                logger.warning("unpair: entry kept changing; written without a swap")
                # From a fresh read, so what the owner changed meanwhile is kept.
                latest = self.get(file_id)
                if latest is not None and not latest.for_everyone and who in latest.audience:  # type: ignore[operator]
                    rest = tuple(a for a in latest.audience if a != who)  # type: ignore[union-attr]
                    self.add(replace(latest, audience=rest))
                    changed.append(file_id)
        return changed


# ---- encrypted refresh tokens ---------------------------------------------


class TokenVault:
    """Refresh tokens for the owner and the bot, encrypted with Fernet (ENCRYPTION_KEY)."""

    def __init__(
        self,
        store: KeyValueStore,
        encryption_key: str | None,
        expected: Callable[[], str | None] | None = None,
    ):
        self.store = store
        # Whose sign-in this vault should hold. The encrypted record names its account,
        # so one copied into another person's slot in the store is refused.
        self.expected = expected
        self._fernet = None
        if encryption_key:
            from cryptography.fernet import Fernet

            self._fernet = Fernet(encryption_key.strip().encode())

    @property
    def enabled(self) -> bool:
        return self._fernet is not None

    def _put(self, key: str, token: str, email: str, scopes: str | None = None) -> None:
        if self._fernet is None:
            raise RuntimeError("ENCRYPTION_KEY is not set")
        payload: dict[str, str] = {"t": token, "email": email, "at": utc_now()}
        if scopes:
            payload["scopes"] = scopes
        self.store.set(key, self._fernet.encrypt(json.dumps(payload).encode()).decode())

    def _take(self, key: str) -> dict[str, str] | None:
        if self._fernet is None:
            return None
        raw = self.store.get(key)
        if not raw:
            return None
        from cryptography.fernet import InvalidToken

        try:
            return json.loads(self._fernet.decrypt(raw.encode()))
        except (InvalidToken, ValueError):
            return None

    def set_owner(self, token: str, email: str, scopes: str | None = None) -> None:
        self._put(OWNER_TOKEN_KEY, token, email, scopes)

    def owner(self) -> dict[str, str] | None:
        """The stored Drive sign-in, only if it is limited to drive.file.

        An older record that carries the full Drive scope, or has no scope stamp, is not
        returned: the person counts as not connected until they reconnect. Use
        `legacy_owner()` to find such a record so it can be revoked.
        """
        from .drive_client import scopes_acceptable

        record = self._owner_any()
        if record and not scopes_acceptable(record.get("scopes")):
            return None
        return record

    def legacy_owner(self) -> dict[str, str] | None:
        """A stored sign-in this server no longer uses (full Drive or unstamped), if any."""
        from .drive_client import scopes_acceptable

        record = self._owner_any()
        if record and record.get("t") and not scopes_acceptable(record.get("scopes")):
            return record
        return None

    def _owner_any(self) -> dict[str, str] | None:
        record = self._take(OWNER_TOKEN_KEY)
        want = self.expected() if self.expected is not None else None
        have = record.get("email") if record else None
        # A record saved before the account was written into it has no email and is
        # accepted. Every record written since has one, so a copied one is caught.
        if want and have and str(have).strip().lower() != want.strip().lower():
            logger.warning("stored Drive sign-in belongs to a different account; ignored")
            return None
        return record

    def set_notion(
        self,
        access_token: str,
        refresh_token: str | None,
        email: str,
        workspace_id: str = "",
        workspace_name: str = "",
    ) -> None:
        """This person's Notion connection. Encrypted like the Drive token, and naming the
        account it belongs to, so a record copied into another person's slot is refused."""
        if self._fernet is None:
            raise RuntimeError("ENCRYPTION_KEY is not set")
        payload = {
            "t": access_token,
            "email": email,
            "at": utc_now(),
            "workspace_id": workspace_id,
            "workspace_name": workspace_name,
        }
        if refresh_token:
            payload["r"] = refresh_token
        self.store.set(
            NOTION_TOKEN_KEY, self._fernet.encrypt(json.dumps(payload).encode()).decode()
        )

    def notion(self) -> dict[str, str] | None:
        """The stored Notion connection for the current person, or None."""
        record = self._take(NOTION_TOKEN_KEY)
        if not record or not record.get("t"):
            return None
        want = self.expected() if self.expected is not None else None
        have = record.get("email")
        if want and (not have or str(have).strip().lower() != want.strip().lower()):
            logger.warning("stored Notion connection belongs to a different account; ignored")
            return None
        return record

    def clear_notion(self) -> None:
        self.store.delete(NOTION_TOKEN_KEY)

    def set_onedrive(
        self,
        access_token: str,
        refresh_token: str | None,
        email: str,
        expires_at: float,
        drive_id: str = "",
        account: str = "",
        drive_type: str = "",
    ) -> None:
        """This person's OneDrive connection. Encrypted like the Drive token, and naming
        the account it belongs to, so a record copied into another person's slot is
        refused."""
        if self._fernet is None:
            raise RuntimeError("ENCRYPTION_KEY is not set")
        payload = {
            "t": access_token,
            "email": email,
            "at": utc_now(),
            "exp": str(int(expires_at)),
            "drive_id": drive_id,
            "account": account,
            "drive_type": drive_type,
        }
        if refresh_token:
            payload["r"] = refresh_token
        self.store.set(
            ONEDRIVE_TOKEN_KEY, self._fernet.encrypt(json.dumps(payload).encode()).decode()
        )

    def onedrive(self) -> dict[str, str] | None:
        """The stored OneDrive connection for the current person, or None."""
        record = self._take(ONEDRIVE_TOKEN_KEY)
        if not record or not record.get("t"):
            return None
        want = self.expected() if self.expected is not None else None
        have = record.get("email")
        if want and (not have or str(have).strip().lower() != want.strip().lower()):
            logger.warning("stored OneDrive connection belongs to a different account; ignored")
            return None
        return record

    def clear_onedrive(self) -> None:
        self.store.delete(ONEDRIVE_TOKEN_KEY)

    def set_bot(self, token: str, email: str) -> None:
        self._put(BOT_TOKEN_KEY, token, email)

    def bot(self) -> dict[str, str] | None:
        return self._take(BOT_TOKEN_KEY)

    def clear_owner(self) -> None:
        self.store.delete(OWNER_TOKEN_KEY)

    def clear_bot(self) -> None:
        self.store.delete(BOT_TOKEN_KEY)


# ---- activity log -----------------------------------------------------------


class ActivityLog:
    """The last ACTIVITY_MAX audit records, newest first."""

    def __init__(self, store: KeyValueStore, max_items: int = ACTIVITY_MAX):
        self.store = store
        self.max_items = max_items

    def __call__(self, record: dict[str, Any]) -> None:
        if not self._worth_keeping(record):
            return
        self.store.lpush(ACTIVITY_KEY, json.dumps(record, separators=(",", ":")))
        self.store.ltrim(ACTIVITY_KEY, 0, self.max_items - 1)

    def _worth_keeping(self, record: dict[str, Any]) -> bool:
        """The list holds ACTIVITY_MAX rows, so rows anyone can produce in bulk must not
        be able to push the others out. Every record still goes to the server log.

        A rejected bearer token is kept once an hour per reason. A paired person's call
        is kept once an hour per tool and outcome (and per file when it was allowed), so
        repeating a call does not bury the record of an earlier one."""
        guest = record.get("guest")
        if record.get("event") == "auth":
            parts = ["auth", str(record.get("reason"))]
        elif guest:
            allowed = record.get("decision") == "allow"
            parts = [
                str(guest),
                str(record.get("tool")),
                str(record.get("decision")),
                str(record.get("reason")),
                str(record.get("file_id") or record.get("folder_id") or "") if allowed else "",
            ]
        else:
            return True
        digest = hashlib.sha256("\x00".join(parts).encode()).hexdigest()[:32]
        try:
            return self.store.set_if_absent(f"activity_seen:{digest}", "1", ex=GUEST_ROW_EVERY)
        except Exception:
            # Not knowing whether it is a repeat is no reason to lose the record.
            logger.warning("activity repeat check failed; keeping the row", exc_info=True)
            return True

    def recent(self, limit: int = ACTIVITY_MAX) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for raw in self.store.lrange(ACTIVITY_KEY, 0, limit - 1):
            try:
                out.append(json.loads(raw))
            except ValueError:
                continue
        return out


FIRST_READS_KEY = "first_reads"
FIRST_READS_MAX = 20
# How long a person's first read stays "first": after this, the next read is news again.
FIRST_READ_EVERY = 365 * 24 * 3600


class FirstReads:
    """Newest first: the first time each paired person's assistant read something this
    person shares. Shown on Overview so a new reader does not go unnoticed."""

    def __init__(self, store: KeyValueStore, max_items: int = FIRST_READS_MAX):
        self.store = store
        self.max_items = max_items

    def add(self, guest: str, tool: str, file_id: str | None) -> bool:
        """Record `guest`'s first read. Returns False if they were already seen. The seen
        mark is claimed first so two reads at once give one notice; if writing the notice
        then fails, the mark is released so the next read tries again."""
        seen = f"first_read_seen:{guest}"
        if not self.store.set_if_absent(seen, "1", ex=FIRST_READ_EVERY):
            return False
        try:
            row = {"at": utc_now(), "guest": guest, "tool": tool, "file_id": file_id}
            self.store.lpush(FIRST_READS_KEY, json.dumps(row, separators=(",", ":")))
            self.store.ltrim(FIRST_READS_KEY, 0, self.max_items - 1)
        except Exception:
            self.store.delete(seen)
            raise
        return True

    def recent(self, limit: int = 5) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for raw in self.store.lrange(FIRST_READS_KEY, 0, limit - 1):
            try:
                row = json.loads(raw)
            except ValueError:
                continue
            if isinstance(row, dict) and row.get("guest"):
                out.append(row)
        return out

    def clear(self) -> None:
        self.store.delete(FIRST_READS_KEY)


HIDDEN_FILES_KEY = "files_hidden"


class HiddenFiles:
    """Items this person removed from Bot RBAC on Files.

    Google gives an app no way to hand back one file picked in its file picker, so
    "Remove from Bot RBAC" takes the item off both lists and hides it here. The page says
    that Google still lists the app as able to open it. Picking it again brings it back.
    """

    def __init__(self, store: KeyValueStore):
        self.store = store

    def hide(self, file_id: str) -> None:
        self.store.hset(HIDDEN_FILES_KEY, file_id, utc_now())

    def unhide(self, file_id: str) -> None:
        self.store.hdel(HIDDEN_FILES_KEY, file_id)

    def ids(self) -> set[str]:
        return set(self.store.hgetall(HIDDEN_FILES_KEY))


def _copy_string(source: KeyValueStore, dest: KeyValueStore, key: str) -> None:
    value = source.get(key)
    if value is not None:
        dest.set(key, value)


def _copy_hash(source: KeyValueStore, dest: KeyValueStore, key: str) -> None:
    for name, value in source.hgetall(key).items():
        dest.hset(key, name, value)


def _copy_list(source: KeyValueStore, dest: KeyValueStore, key: str) -> None:
    """Replace `key` with the source list in one step when the destination can.

    Pushing one item at a time lets two copies interleave and duplicate the list.
    """
    items = source.lrange(key, 0, -1)
    replace = getattr(dest, "replace_list", None)
    if replace is None:
        dest.delete(key)
        for item in reversed(items):
            dest.lpush(key, item)
        return
    replace(key, items)


class StoreImportError(RuntimeError):
    """The admin store was not copied, so Postgres must not be served."""


def import_admin_keys(source: KeyValueStore, dest: KeyValueStore) -> None:
    """Copy the admin's Redis records into Postgres once.

    Only the legacy admin keys move: allowlist, encrypted tokens, requests and activity.
    OAuth grants and other people's prefixes are left where they are. A flag on the
    destination stops a second copy. The flag is written only after the copy finishes.
    A lock so two serverless instances cannot both copy the activity list and the
    request index. The loser raises `StoreImportError` and must not be served as the
    live store. Lists are replaced in one step so a retry cannot splice duplicates in.
    """
    if dest.get(REDIS_IMPORT_FLAG):
        return
    claim = getattr(dest, "set_if_absent", None)
    if claim is None or not claim(REDIS_IMPORT_LOCK, utc_now(), REDIS_IMPORT_LOCK_TTL):
        raise StoreImportError("admin store copy is already running")
    try:
        if dest.get(REDIS_IMPORT_FLAG):
            return
        _copy_hash(source, dest, KEY_PREFIX + ALLOWLIST_KEY)
        _copy_hash(source, dest, KEY_PREFIX + EXTERNAL_ALLOWLIST_KEY)
        _copy_string(source, dest, KEY_PREFIX + OWNER_TOKEN_KEY)
        _copy_string(source, dest, KEY_PREFIX + BOT_TOKEN_KEY)
        _copy_list(source, dest, KEY_PREFIX + ACTIVITY_KEY)
        index_key = KEY_PREFIX + "requests:index"
        _copy_list(source, dest, index_key)
        for rid in dest.lrange(index_key, 0, -1):
            raw = source.get(f"{KEY_PREFIX}req:{rid}")
            if raw is None:
                continue
            dest.set(f"{KEY_PREFIX}req:{rid}", raw)
            try:
                file_id = json.loads(raw).get("file_id")
            except ValueError:
                file_id = None
            if isinstance(file_id, str) and file_id:
                _copy_string(source, dest, f"{KEY_PREFIX}req:pending:{file_id}")
        _scan_request_keys(source, dest)
        dest.set(REDIS_IMPORT_FLAG, utc_now())
    finally:
        try:
            dest.delete(REDIS_IMPORT_LOCK)
        except Exception as exc:
            # The driver message can contain the connection URL.
            logger.warning(
                "releasing the Redis-to-Postgres import lock failed (%s)",
                type(exc).__name__,
            )


def _scan_request_keys(source: KeyValueStore, dest: KeyValueStore) -> None:
    """Copy any `sdm:req:*` key Redis can scan, including ones missing from the index."""
    client = getattr(source, "_redis", None)
    scan = getattr(client, "scan", None)
    if scan is None:
        return
    cursor: int | str = 0
    while True:
        cursor, keys = scan(cursor, match=f"{KEY_PREFIX}req:*", count=200)
        for key in keys or []:
            full = str(key)
            _copy_string(source, dest, full)
        if cursor in (0, "0"):
            return


def _session_key(sid: str) -> str:
    return "session:" + hashlib.sha256(sid.encode()).hexdigest()


class TenantDirectory:
    """Opens one person's store without changing `current_actor`.

    The admin uses the legacy keys. Everyone else uses `u:{email}:` on the already
    prefixed store. `users:index` records when each address first signed in.
    """

    def __init__(self, store: KeyValueStore, admin_email: str | None, encryption_key: str | None):
        self.store = store
        self.admin_email = admin_email
        self.encryption_key = encryption_key

    def store_for(self, email: str | None) -> KeyValueStore:
        if email is None or email == self.admin_email:
            return self.store
        return PrefixedStore(self.store, tenant_prefix(email))

    def vault_for(self, email: str | None) -> TokenVault:
        return TokenVault(
            self.store_for(email), self.encryption_key, expected=lambda: email or self.admin_email
        )

    # Dashboard sessions. The cookie carries a random id; the id has to be here too, so
    # signing out ends the session and it cannot outlive `ttl` by being re-signed.
    def open_session(self, email: str, ttl: int) -> str:
        sid = secrets.token_urlsafe(32)
        self.store.set(_session_key(sid), email, ex=ttl)
        return sid

    def session_alive(self, sid: Any, email: str) -> bool:
        if not isinstance(sid, str) or not sid:
            return False
        return self.store.get(_session_key(sid)) == email

    def close_session(self, sid: Any) -> None:
        if isinstance(sid, str) and sid:
            self.store.delete(_session_key(sid))

    def actor_store(self) -> ActorStore:
        return ActorStore(self.store, self.admin_email)

    def has_owner_refresh(self, email: str) -> bool:
        """Any stored Drive sign-in, including an old one that is no longer used."""
        vault = self.vault_for(email)
        record = vault.owner() or vault.legacy_owner()
        return bool(record and record.get("t"))

    def is_known_user(self, email: str) -> bool:
        """Signed in at least once (step 1), or has a stored connection from before."""
        return self.store.hget(USERS_INDEX, email) is not None or self.has_owner_refresh(email)

    def remember_user(self, email: str) -> None:
        if self.store.hget(USERS_INDEX, email) is None:
            self.store.hset(USERS_INDEX, email, json.dumps({"created_at": utc_now()}))

    def created_at(self, email: str) -> str | None:
        raw = self.store.hget(USERS_INDEX, email)
        if not raw:
            return None
        try:
            value = json.loads(raw).get("created_at")
        except ValueError:
            return None
        return str(value) if value else None

    def stored_bot_email(self, email: str) -> str | None:
        record = self.vault_for(email).bot()
        if not record or not record.get("t"):
            return None
        bot = record.get("email")
        return str(bot) if bot else None

    def known_users(self) -> list[str]:
        found = set(self.store.hgetall(USERS_INDEX))
        if self.admin_email and self.has_owner_refresh(self.admin_email):
            found.add(self.admin_email)
        return sorted(found, key=lambda email: (self.created_at(email) or "", email))

    def email_in_use(self, candidate: str, *, except_user: str, reserved_bot: str | None) -> bool:
        """True when `candidate` is someone else's dashboard address or bot address."""
        candidate = candidate.lower()
        dashboards = set(self.store.hgetall(USERS_INDEX))
        if self.admin_email:
            dashboards.add(self.admin_email)
        if candidate in dashboards:
            return True
        if reserved_bot and candidate == reserved_bot and except_user != self.admin_email:
            return True
        for user in dashboards:
            if user == except_user:
                continue
            if self.stored_bot_email(user) == candidate:
                return True
        return False


def build_store(settings: Any) -> PrefixedStore:
    if settings.postgres_configured:
        inner: KeyValueStore = PostgresStore(settings.postgres_url)
        if settings.redis_configured:
            redis = RedisStore(
                settings.redis_rest_url, settings.redis_rest_token.get_secret_value().strip()
            )
            try:
                import_admin_keys(redis, inner)
            except StoreImportError:
                raise
            except Exception as exc:
                # The exception text from the driver can contain the connection URL.
                logger.warning(
                    "copying the admin store from Redis to Postgres failed (%s)",
                    type(exc).__name__,
                )
                raise StoreImportError("admin store was not copied from Redis") from None
        return PrefixedStore(inner)
    if settings.redis_configured:
        inner = RedisStore(
            settings.redis_rest_url, settings.redis_rest_token.get_secret_value().strip()
        )
    else:
        inner = MemoryStore()
    return PrefixedStore(inner)

"""Persistent state: the allowlist, access requests' storage, encrypted OAuth tokens and the
activity log.

Everything sits behind the small `KeyValueStore` protocol so tests (and local development
without Redis) can use `MemoryStore`. In production `RedisStore` talks to Upstash Redis over
its REST API, and `PostgresStore` talks to Neon when `DATABASE_URL` or `POSTGRES_URL` is set.
All keys are prefixed with `sdm:`. The admin keeps the original key names. Every other person
is stored under `u:{email}:` on that same prefixed store.

The code is split by layer: `backends` (the protocol and the three stores), `keys` (key
names and limits), `wrappers` (prefixed, signed and per-person views), `records` (allowlist,
token vault, activity) and `tenancy` (each person's store and sessions). Choosing the store
and the one-off Redis-to-Postgres copy live here. Import from `store`, not from the parts.
"""

import json
import logging
import time  # noqa: F401 - kept as an attribute of this module, as it was before the split
from typing import Any

from .backends import (
    _HSWAP_SCRIPT,
    _INBOX_TOKEN,
    _INCR_SCRIPT,
    _LDROP_EXPIRED_SCRIPT,
    _LREPLACE_SCRIPT,
    _PG_INCR_SQL,
    _REPLACE_LIST_SCRIPT,
    _SWAP_SCRIPT,
    KeyValueStore,
    MemoryStore,
    PostgresStore,
    RedisStore,
    parse_inbox_token,
    utc_now,
)
from .keys import (
    ACCESS_EDIT,
    ACCESS_READ,
    ACTIVITY_CHANGES_KEY,
    ACTIVITY_KEY,
    ACTIVITY_MAX,
    AGENT_ROLES_KEY,
    ALLOWLIST_KEY,
    AUDIENCE_LINKED,
    BOT_TOKEN_KEY,
    EXTERNAL_ALLOWLIST_KEY,
    GUEST_ROW_EVERY,
    KEY_PREFIX,
    NOTION_ALLOWLIST_KEY,
    NOTION_TOKEN_KEY,
    ONEDRIVE_ALLOWLIST_KEY,
    ONEDRIVE_TOKEN_KEY,
    OWNER_TOKEN_KEY,
    REDIS_IMPORT_FLAG,
    REDIS_IMPORT_LOCK,
    REDIS_IMPORT_LOCK_TTL,
    TWITTER_ALLOWLIST_KEY,
    TWITTER_TOKEN_KEY,
    USERS_INDEX,
)
from .records import (
    FIRST_READ_EVERY,
    FIRST_READS_KEY,
    FIRST_READS_MAX,
    HIDDEN_FILES_KEY,
    ActivityLog,
    AllowEntry,
    Allowlist,
    FirstReads,
    HiddenFiles,
    TokenVault,
    _audience,
)
from .tenancy import (
    TenantDirectory,
    _session_key,
)
from .wrappers import (
    _MAC_CHARS,
    _MAC_LENGTH,
    _SIGNED_CONTENT_HASHES,
    _SIGNED_CONTENT_PREFIXES,
    _SIGNED_HASHES,
    _SIGNED_KEYS,
    _SIGNED_PREFIXES,
    _TENANT_EMAIL,
    _TENANT_PREFIX,
    SIGNED_MARK,
    UNSIGNED_CONTENT_UNTIL,
    ActorStore,
    PrefixedStore,
    SignedStore,
    _looks_signed,
    _unsigned_still_read,
    purpose_fernet,
    sign_existing_records,
    signing_key,
    signs,
    tenant_prefix,
    usable_email,
)

__all__ = [
    "ACCESS_EDIT",
    "ACCESS_READ",
    "ACTIVITY_CHANGES_KEY",
    "ACTIVITY_KEY",
    "ACTIVITY_MAX",
    "AGENT_ROLES_KEY",
    "ALLOWLIST_KEY",
    "AUDIENCE_LINKED",
    "ActivityLog",
    "ActorStore",
    "AllowEntry",
    "Allowlist",
    "BOT_TOKEN_KEY",
    "EXTERNAL_ALLOWLIST_KEY",
    "FIRST_READS_KEY",
    "FIRST_READS_MAX",
    "FIRST_READ_EVERY",
    "FirstReads",
    "GUEST_ROW_EVERY",
    "HIDDEN_FILES_KEY",
    "HiddenFiles",
    "KEY_PREFIX",
    "KeyValueStore",
    "MemoryStore",
    "NOTION_ALLOWLIST_KEY",
    "NOTION_TOKEN_KEY",
    "ONEDRIVE_ALLOWLIST_KEY",
    "ONEDRIVE_TOKEN_KEY",
    "TWITTER_ALLOWLIST_KEY",
    "TWITTER_TOKEN_KEY",
    "OWNER_TOKEN_KEY",
    "PostgresStore",
    "PrefixedStore",
    "REDIS_IMPORT_FLAG",
    "REDIS_IMPORT_LOCK",
    "REDIS_IMPORT_LOCK_TTL",
    "RedisStore",
    "SIGNED_MARK",
    "SignedStore",
    "StoreImportError",
    "TenantDirectory",
    "TokenVault",
    "UNSIGNED_CONTENT_UNTIL",
    "USERS_INDEX",
    "_HSWAP_SCRIPT",
    "_INBOX_TOKEN",
    "_INCR_SCRIPT",
    "_LDROP_EXPIRED_SCRIPT",
    "_LREPLACE_SCRIPT",
    "_MAC_CHARS",
    "_MAC_LENGTH",
    "_PG_INCR_SQL",
    "_REPLACE_LIST_SCRIPT",
    "_SIGNED_CONTENT_HASHES",
    "_SIGNED_CONTENT_PREFIXES",
    "_SIGNED_HASHES",
    "_SIGNED_KEYS",
    "_SIGNED_PREFIXES",
    "_SWAP_SCRIPT",
    "_TENANT_EMAIL",
    "_TENANT_PREFIX",
    "_audience",
    "_copy_hash",
    "_copy_list",
    "_copy_string",
    "_looks_signed",
    "_scan_request_keys",
    "_session_key",
    "_unsigned_still_read",
    "build_store",
    "import_admin_keys",
    "parse_inbox_token",
    "purpose_fernet",
    "sign_existing_records",
    "signing_key",
    "signs",
    "tenant_prefix",
    "usable_email",
    "utc_now",
]

# One logger name for the whole package, the one `store.py` logged under.
logger = logging.getLogger("scoped_drive_mcp.store")


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
        _copy_list(source, dest, KEY_PREFIX + ACTIVITY_CHANGES_KEY)
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

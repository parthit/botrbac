"""Where the bytes of a held file (a drop, see drops.py) live while it waits to be saved.

Two places:

* **Vercel Blob** (`BlobParts`), when the deployment has a Blob store connected
  (`BLOB_READ_WRITE_TOKEN`). A file is stored as pieces of `PIECE_BYTES`, one private blob
  each, named `drops/<expiry>/<drop id>/<n>`. The free (Hobby) Blob tier is small, and
  going over it turns Blob off for 30 days, so `BlobBudget` keeps uploads under a monthly
  count and the bytes held under a cap, and sweeps expired pieces from time to time.
  The Python SDK cannot put an expiry on a blob, so the expiry is in the name and the
  sweep deletes by it.
* **The key-value store** (`KvParts`): the fallback. Pieces of `KV_PART_BYTES` (an
  Upstash request is capped), each with the store's own expiry.

Both encrypt with a key derived from ENCRYPTION_KEY when it is set.

**Direct uploads** (`BlobSigner`): on Vercel, a small Node function (`api/blob-sign.mjs`)
signs Blob URLs with `@vercel/blob`, which the Python SDK cannot do. Python decides who
may send or read what and asks the function for one presigned URL per piece; the browser
moves the bytes to and from Blob itself. Those pieces never pass through this code, so
they cannot be encrypted with ENCRYPTION_KEY: rows marked `"enc": BLOB_AT_REST` rely on
Blob's own encryption at rest. Without the signer, uploads go through Python as before.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from urllib.parse import urlsplit

from .errors import report_exception
from .store import KeyValueStore, purpose_fernet

logger = logging.getLogger(__name__)

# One upload request from the dashboard carries one piece. Vercel refuses request and
# response bodies over 4.5 MB, so a piece plus its multipart framing stays under that.
PIECE_BYTES = 4 * 1024 * 1024
# A piece in the key-value store is split again into parts this size.
KV_PART_BYTES = 512 * 1024

DROP_PART_PREFIX = "drops:part:"
BLOB_PREFIX = "drops/"
_BLOB_PATH = re.compile(r"drops/(\d{1,12})/([A-Za-z0-9_-]{1,64})/(\d{1,4})")


def _kv_per_piece() -> int:
    """Store parts one piece takes (read at call time, so tests can shrink both sizes)."""
    return max(1, -(-PIECE_BYTES // KV_PART_BYTES))


def piece_count(size: int) -> int:
    """Dashboard pieces in a file of `size` bytes (an empty file is one empty piece)."""
    return max(1, -(-max(0, size) // PIECE_BYTES))


class DropParts(Protocol):
    """Stored pieces of held files. `exp` is the drop's expiry (Unix seconds)."""

    kind: str

    def put_piece(self, drop_id: str, exp: int, n: int, data: bytes) -> None: ...

    def get_piece(self, row: dict[str, Any], n: int) -> bytes | None: ...

    def delete(self, row: dict[str, Any]) -> None: ...


# ---- key-value store ------------------------------------------------------------


class KvParts:
    """Pieces in the key-value store, as `drops:part:<id>:<k>` with an expiry.

    Rows written before pieces existed have `parts` of `KV_PART_BYTES` each under the same
    keys, so they read the same way."""

    kind = "kv"

    def __init__(
        self,
        store: KeyValueStore,
        encryption_key: str | None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ):
        self.store = store
        self._fernet = purpose_fernet(encryption_key, "drops") if encryption_key else None
        self.clock = clock

    def _seal(self, data: bytes) -> str:
        if self._fernet is not None:
            return self._fernet.encrypt(data).decode()
        return base64.b64encode(data).decode()

    def _open(self, raw: str) -> bytes:
        if self._fernet is not None:
            return self._fernet.decrypt(raw.encode())
        return base64.b64decode(raw)

    @staticmethod
    def _key(drop_id: str, k: int) -> str:
        return f"{DROP_PART_PREFIX}{drop_id}:{k}"

    def put_piece(self, drop_id: str, exp: int, n: int, data: bytes) -> None:
        ttl = max(60, exp - int(self.clock().timestamp()) + 60)
        chunks = [data[i : i + KV_PART_BYTES] for i in range(0, len(data), KV_PART_BYTES)]
        first = n * _kv_per_piece()
        for k, chunk in enumerate(chunks or [b""]):
            self.store.set(self._key(drop_id, first + k), self._seal(chunk), ex=ttl)

    def get_piece(self, row: dict[str, Any], n: int) -> bytes | None:
        total = int(row.get("parts") or 0)
        per = _kv_per_piece()
        first = n * per
        out: list[bytes] = []
        for k in range(first, min(first + per, total)):
            raw = self.store.get(self._key(str(row["id"]), k))
            if raw is None:
                return None
            try:
                out.append(self._open(raw))
            except Exception:
                return None
        return b"".join(out) if out or n == 0 else None

    def delete(self, row: dict[str, Any]) -> None:
        for k in range(int(row.get("parts") or 0)):
            self.store.delete(self._key(str(row["id"]), k))

    @staticmethod
    def parts_for(size: int) -> int:
        """Store keys a file of `size` bytes takes: every piece but the last is full."""
        count = piece_count(size)
        last = max(0, size) - PIECE_BYTES * (count - 1)
        return (count - 1) * _kv_per_piece() + max(1, -(-last // KV_PART_BYTES))


# ---- Vercel Blob ----------------------------------------------------------------


class BlobApi(Protocol):
    """The few Vercel Blob calls used here (tests pass a fake)."""

    def put(self, pathname: str, data: bytes) -> None: ...

    def get(self, pathname: str) -> bytes | None: ...

    def delete(self, pathnames: Sequence[str]) -> None: ...

    def list(self, prefix: str) -> Iterable[str]: ...

    def head(self, pathname: str) -> int | None:
        """The blob's size in bytes, or None when there is none."""
        ...


class VercelBlobApi:
    """The Vercel Blob Python SDK (`vercel-blob`), private store. Credentials come from
    BLOB_READ_WRITE_TOKEN (or BLOB_STORE_ID with Vercel's OIDC token)."""

    def __init__(self) -> None:
        from vercel.blob import sync

        self._blob = sync

    def put(self, pathname: str, data: bytes) -> None:
        self._blob.put_blob(
            pathname,
            data,
            access="private",
            content_type="application/octet-stream",
            allow_overwrite=True,
            cache_control_max_age=60,
        )

    def get(self, pathname: str) -> bytes | None:
        try:
            return bytes(self._blob.get_blob(pathname, access="private").body)
        except self._blob.BlobNotFoundError:
            return None

    def delete(self, pathnames: Sequence[str]) -> None:
        if pathnames:
            self._blob.delete_blob(list(pathnames))

    def list(self, prefix: str) -> Iterable[str]:
        for item in self._blob.query_blobs(prefix=prefix, page_size=1000):
            yield item.pathname

    def head(self, pathname: str) -> int | None:
        try:
            return int(self._blob.head_blob(pathname).size)
        except self._blob.BlobNotFoundError:
            return None


# A row whose pieces the browser uploaded straight to Blob (see BlobSigner).
BLOB_AT_REST = "blob-at-rest"


def _blob_key(encryption_key: str) -> bytes:
    """A 256-bit key for blob pieces only, derived like store.purpose_fernet."""
    return hmac.new(
        encryption_key.strip().encode(), b"botrbac drops blob encryption v1", hashlib.sha256
    ).digest()


class BlobParts:
    """Pieces as private blobs. Each is `0x01 | nonce | AES-GCM(piece)` (the pathname is
    the associated data, so a piece cannot be moved to another drop), or `0x00 | piece`
    without ENCRYPTION_KEY."""

    kind = "blob"

    def __init__(self, api: BlobApi, encryption_key: str | None):
        self.api = api
        self._aead: Any = None
        if encryption_key:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            self._aead = AESGCM(_blob_key(encryption_key))

    @staticmethod
    def path(drop_id: str, exp: int, n: int) -> str:
        return f"{BLOB_PREFIX}{exp}/{drop_id}/{n}"

    def _seal(self, path: str, data: bytes) -> bytes:
        if self._aead is None:
            return b"\x00" + data
        nonce = secrets.token_bytes(12)
        return b"\x01" + nonce + self._aead.encrypt(nonce, data, path.encode())

    def _open(self, path: str, raw: bytes) -> bytes | None:
        if raw[:1] == b"\x00":
            return raw[1:]
        if raw[:1] == b"\x01" and self._aead is not None:
            try:
                return self._aead.decrypt(raw[1:13], raw[13:], path.encode())
            except Exception:
                return None
        return None

    def put_piece(self, drop_id: str, exp: int, n: int, data: bytes) -> None:
        path = self.path(drop_id, exp, n)
        self.api.put(path, self._seal(path, data))

    def get_piece(self, row: dict[str, Any], n: int) -> bytes | None:
        path = self.path(str(row["id"]), int(row.get("exp") or 0), n)
        raw = self.api.get(path)
        if raw is None:
            return None
        # The browser put these bytes straight into Blob: no framing, no encryption here.
        # Only for rows this app marked so at `begin`; every other row opens as before.
        if row.get("enc") == BLOB_AT_REST:
            return raw
        return self._open(path, raw)

    def size(self, row: dict[str, Any], n: int) -> int | None:
        """Bytes stored for piece `n` (one HEAD, a simple operation), or None."""
        return self.api.head(self.path(str(row["id"]), int(row.get("exp") or 0), n))

    def delete(self, row: dict[str, Any]) -> None:
        exp = int(row.get("exp") or 0)
        drop_id = str(row["id"])
        self.api.delete([self.path(drop_id, exp, n) for n in range(int(row.get("parts") or 0))])

    def sweep(self, now: int) -> int:
        """Delete every piece whose drop has expired. One list call (an advanced
        operation per 1,000 blobs); deletes are free."""
        expired: list[str] = []
        for pathname in self.api.list(BLOB_PREFIX):
            match = _BLOB_PATH.fullmatch(pathname)
            if match is None or int(match.group(1)) < now:
                expired.append(pathname)
        for i in range(0, len(expired), 1000):
            self.api.delete(expired[i : i + 1000])
        return len(expired)


# ---- staying inside the free Blob tier ------------------------------------------

BUDGET_PREFIX = "drops:blob:"
# How often an upload may trigger a sweep of expired pieces.
SWEEP_EVERY_SECONDS = 6 * 3600


class BlobBudget:
    """Keeps Blob use under the free tier, counted in pieces (each at most PIECE_BYTES).

    * Uploads: each piece is one advanced operation, plus one for each sweep. At most
      `monthly_uploads` a calendar month (UTC). The free tier includes 2,000.
    * Storage: an upload is refused when the pieces stored over the last few days (the
      hold, plus the time a piece may wait for a sweep) could pass `held_bytes`. The free
      tier includes 1 GB.

    Counted in the shared (not per-person) store, before the upload, so a failed upload
    still counts. Sends that arrive together may pass a cap by a few pieces."""

    def __init__(
        self,
        store: KeyValueStore,
        parts: BlobParts,
        *,
        monthly_uploads: int,
        held_bytes: int,
        hold_hours: int,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ):
        self.store = store
        self.parts = parts
        self.monthly_uploads = monthly_uploads
        self.held_pieces = max(1, held_bytes // PIECE_BYTES)
        hours = hold_hours + SWEEP_EVERY_SECONDS // 3600 + 1
        self.window_days = -(-hours // 24) + 1
        self.clock = clock

    def _month_key(self, now: datetime) -> str:
        return f"{BUDGET_PREFIX}ops:{now:%Y-%m}"

    def _day_key(self, day: datetime) -> str:
        return f"{BUDGET_PREFIX}pieces:{day:%Y-%m-%d}"

    def _count(self, key: str) -> int:
        try:
            return int(self.store.get(key) or 0)
        except ValueError:
            return 0

    def usage(self) -> dict[str, int]:
        now = self.clock()
        held = sum(
            self._count(self._day_key(now - timedelta(days=d))) for d in range(self.window_days)
        )
        return {"month_uploads": self._count(self._month_key(now)), "recent_pieces": held}

    def reserve(self, pieces: int) -> bool:
        """Count `pieces` uploads, or return False (and count nothing) when they would
        pass a cap."""
        now = self.clock()
        use = self.usage()
        if use["month_uploads"] + pieces > self.monthly_uploads:
            return False
        if use["recent_pieces"] + pieces > self.held_pieces:
            return False
        for _ in range(pieces):
            self.store.incr(self._month_key(now), 40 * 86400)
            self.store.incr(self._day_key(now), (self.window_days + 1) * 86400)
        return True

    def maybe_sweep(self) -> None:
        """Delete expired pieces, at most once every SWEEP_EVERY_SECONDS."""
        now = self.clock()
        if not self.store.set_if_absent(f"{BUDGET_PREFIX}swept", "1", ex=SWEEP_EVERY_SECONDS):
            return
        try:
            self.store.incr(self._month_key(now), 40 * 86400)
            removed = self.parts.sweep(int(now.timestamp()))
        except Exception as exc:
            report_exception(exc, where="drop_sweep")
            return
        if removed:
            logger.info("deleted %d expired held-file pieces from Blob", removed)


def blob_configured() -> bool:
    """A Blob store is connected: Vercel adds BLOB_READ_WRITE_TOKEN (or BLOB_STORE_ID,
    used with its OIDC token) when one is connected to the project."""
    return bool(
        os.environ.get("BLOB_READ_WRITE_TOKEN", "").strip()
        or os.environ.get("BLOB_STORE_ID", "").strip()
    )


# ---- signing Blob URLs (api/blob-sign.mjs) ----------------------------------------

SIGNER_PATH = "/api/blob-sign"
SIGNER_TIMEOUT_SECONDS = 5
# Hosts a presigned URL may point at: the Blob API (uploads) and a private store (reads).
_SIGNED_HOSTS = re.compile(r"vercel\.com|[a-z0-9-]{1,64}\.private\.blob\.vercel-storage\.com")
# What the browser sends with a presigned PUT (the SDK's own upload headers).
_PUT_HEADERS = frozenset(
    {"x-vercel-blob-access", "x-api-version", "x-vercel-blob-store-id", "x-content-type"}
)


class SignerError(Exception):
    """The signing function did not return a usable URL."""


def signer_key(encryption_key: str) -> bytes:
    """The key that authenticates this app to api/blob-sign.mjs. Derived from
    ENCRYPTION_KEY (every function in a Vercel project sees the same variables), so there
    is no new secret to set. The function derives it the same way."""
    return hmac.new(
        encryption_key.strip().encode(), b"botrbac blob signer v1", hashlib.sha256
    ).digest()


def signer_headers(key: bytes, body: bytes, now: int) -> dict[str, str]:
    """`x-botrbac-timestamp`, and `x-botrbac-signature`: the hex HMAC-SHA256 of
    `<timestamp>.<body>`. The function refuses one older than 60 seconds."""
    mac = hmac.new(key, str(now).encode() + b"." + body, hashlib.sha256).hexdigest()
    return {"x-botrbac-timestamp": str(now), "x-botrbac-signature": mac}


def _checked_url(value: Any) -> str:
    if not isinstance(value, str):
        raise SignerError("no url")
    parts = urlsplit(value)
    if parts.scheme != "https" or not _SIGNED_HOSTS.fullmatch(parts.hostname or ""):
        raise SignerError("unexpected url host")
    return value


class BlobSigner(Protocol):
    """Presigned Blob URLs, one pathname each (tests pass a fake)."""

    def sign_put(
        self, pathname: str, max_bytes: int, valid_for: int, ttl_days: int
    ) -> dict[str, Any]:
        """{"url": ..., "headers": {...}} for one browser PUT of at most `max_bytes`."""
        ...

    def sign_get(self, pathname: str, valid_for: int) -> str: ...


class HttpBlobSigner:
    """Calls api/blob-sign.mjs. `bypass` is VERCEL_AUTOMATION_BYPASS_SECRET, needed when
    Deployment Protection covers the URL called."""

    def __init__(
        self,
        url: str,
        encryption_key: str,
        *,
        bypass: str | None = None,
        timeout: float = SIGNER_TIMEOUT_SECONDS,
        clock: Callable[[], float] = time.time,
    ):
        parts = urlsplit(url)
        local = parts.hostname in {"localhost", "127.0.0.1"}
        if not (parts.scheme == "https" or (parts.scheme == "http" and local)):
            raise ValueError("the Blob signer URL must be https://")
        self.url = url
        self._key = signer_key(encryption_key)
        self._bypass = bypass
        self.timeout = timeout
        self.clock = clock

    def _call(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload, separators=(",", ":")).encode()
        headers = {
            "content-type": "application/json",
            **signer_headers(self._key, body, int(self.clock())),
        }
        if self._bypass:
            headers["x-vercel-protection-bypass"] = self._bypass
        # S310: the scheme is checked in __init__ (https, or http to localhost).
        request = urllib.request.Request(self.url, data=body, headers=headers, method="POST")  # noqa: S310
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                data = json.loads(response.read(64 * 1024))
        except urllib.error.HTTPError as exc:
            raise SignerError(f"signer answered {exc.code}") from None
        except (OSError, ValueError) as exc:
            raise SignerError(f"signer unreachable: {type(exc).__name__}") from None
        if not isinstance(data, dict):
            raise SignerError("unexpected answer")
        return data

    def sign_put(
        self, pathname: str, max_bytes: int, valid_for: int, ttl_days: int
    ) -> dict[str, Any]:
        data = self._call(
            {
                "op": "put",
                "pathname": pathname,
                "maxBytes": max_bytes,
                "validForSeconds": valid_for,
                "ttlDays": ttl_days,
            }
        )
        raw = data.get("headers")
        headers = {
            str(k).lower(): str(v)
            for k, v in (raw.items() if isinstance(raw, dict) else [])
            if str(k).lower() in _PUT_HEADERS
        }
        return {"url": _checked_url(data.get("url")), "headers": headers}

    def sign_get(self, pathname: str, valid_for: int) -> str:
        data = self._call({"op": "get", "pathname": pathname, "validForSeconds": valid_for})
        return _checked_url(data.get("url"))


def signer_url_from_env(app_base_url: str | None) -> str | None:
    """Where api/blob-sign.mjs answers, or None when there is no signer.

    BLOB_SIGNER_URL wins ("off" turns direct uploads off). Otherwise only on Vercel: a
    production deployment calls APP_BASE_URL (normally a custom domain, outside
    Deployment Protection); any other deployment calls its own URL (VERCEL_URL), so a
    preview signs with its own code."""
    explicit = os.environ.get("BLOB_SIGNER_URL", "").strip()
    if explicit.lower() in {"off", "0", "false", "no"}:
        return None
    if explicit:
        return explicit
    own = os.environ.get("VERCEL_URL", "").strip()
    if not own:
        return None
    base = f"https://{own}"
    if os.environ.get("VERCEL_ENV", "").strip() == "production" and app_base_url:
        base = app_base_url
    return base.rstrip("/") + SIGNER_PATH


def blob_signer_from_env(
    encryption_key: str | None, app_base_url: str | None
) -> HttpBlobSigner | None:
    """The signer, when Blob, ENCRYPTION_KEY (its auth key) and a URL are all there."""
    url = signer_url_from_env(app_base_url)
    if not url or not encryption_key or not blob_configured():
        return None
    bypass = os.environ.get("VERCEL_AUTOMATION_BYPASS_SECRET", "").strip() or None
    return HttpBlobSigner(url, encryption_key, bypass=bypass)

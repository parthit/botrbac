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
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import re
import secrets
from collections.abc import Callable, Iterable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

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
        # Unencrypted pieces only when no key is set: with a key, a plain piece is one
        # someone else wrote to the store.
        if raw[:1] == b"\x00" and self._aead is None:
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
        return None if raw is None else self._open(path, raw)

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
# The longest a dashboard upload may take (drops.UPLOAD_SECONDS), in hours.
UPLOAD_HOURS = 1
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
        # Pieces may wait the hold, the longest upload, and a sweep interval.
        hours = hold_hours + SWEEP_EVERY_SECONDS // 3600 + UPLOAD_HOURS + 1
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

    def allows(self, pieces: int) -> bool:
        """Whether `pieces` more uploads fit under both caps now (counts nothing)."""
        use = self.usage()
        return (
            use["month_uploads"] + pieces <= self.monthly_uploads
            and use["recent_pieces"] + pieces <= self.held_pieces
        )

    def reserve(self, pieces: int) -> bool:
        """Count `pieces` uploads, or return False (and count nothing) when they would
        pass a cap."""
        now = self.clock()
        if not self.allows(pieces):
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

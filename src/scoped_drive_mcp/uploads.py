"""Chunked uploads: an assistant sends a file it made in pieces, then the whole is checked
and created in Drive in one step.

A model can't reliably copy tens of thousands of base64 characters into one tool call, so
`upload_file` alone can't carry a PDF or an image an assistant generated. Here the
assistant declares the file first (name, type, folder, size and SHA-256), sends it in
fixed-size pieces, and asks for it to be finished. Nothing reaches Drive until every piece
is here and the assembled bytes match the declared size and hash, so a bad copy never
becomes a broken file in someone's Drive.

Sessions live in the key-value store (each request may run on a different serverless
instance), expire UPLOAD_TTL seconds after they start, and belong to the sign-in that
started them: another token, another connected app or another person gets
`upload_not_found` for the same id. The parent folder is checked when the upload starts
and again when it is finished, by the same scope checks as `upload_file`.
"""

import base64
import binascii
import hashlib
import json
import math
import re
import secrets
import time
from collections.abc import Callable
from typing import Any

from .store import KeyValueStore

UPLOAD_TTL = 15 * 60
# Bytes per piece. Every piece but the last is exactly chunk_size bytes, so the number of
# pieces, and the space a session can take in the store, follow from the declared size.
MIN_CHUNK = 1024
MAX_CHUNK = 512 * 1024
# 6 KiB of bytes is exactly 8,192 base64 characters per call.
DEFAULT_CHUNK = 6 * 1024
# Uploads one account may start in UPLOAD_TTL seconds.
MAX_STARTS = 10
# How many missing piece numbers an error lists.
MISSING_SHOWN = 50

KEY = "upload:"
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class UploadError(Exception):
    """A refused upload call, with a machine-readable code for the assistant."""

    def __init__(self, code: str, message: str, **details: Any) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details

    def payload(self) -> dict[str, Any]:
        return {"error": self.code, "message": self.message, **self.details}


def _not_found() -> UploadError:
    # The same answer for an id that never existed, one that expired, and one that belongs
    # to someone else, so an id can't be probed.
    return UploadError(
        "upload_not_found",
        "No upload with that id is open for this sign-in. It may have expired "
        f"({UPLOAD_TTL // 60} minutes after start_upload) or been finished or cancelled. "
        "Call start_upload again.",
    )


def _int(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise UploadError("invalid_input", f"{what} must be an integer")
    return value


class UploadSessions:
    def __init__(
        self,
        store: KeyValueStore,
        max_bytes: int,
        *,
        clock: Callable[[], float] = time.time,
        ttl: int = UPLOAD_TTL,
    ) -> None:
        self.store = store
        self.max_bytes = max_bytes
        self.clock = clock
        self.ttl = ttl

    # ---- keys ------------------------------------------------------------------------

    @staticmethod
    def _meta_key(upload_id: str) -> str:
        return f"{KEY}{upload_id}"

    @staticmethod
    def _chunk_key(upload_id: str, index: int) -> str:
        return f"{KEY}{upload_id}:c:{index}"

    @staticmethod
    def _claim_key(upload_id: str) -> str:
        return f"{KEY}{upload_id}:finishing"

    # ---- sessions --------------------------------------------------------------------

    def start(
        self,
        who: dict[str, str | None],
        *,
        name: str,
        mime_type: str,
        parent_id: str,
        size: Any,
        sha256: Any,
        chunk_size: Any = DEFAULT_CHUNK,
        owner: str | None = None,
    ) -> dict[str, Any]:
        """Open a session. The caller has already checked the name, type and parent."""
        if not who.get("email"):
            raise UploadError("unauthenticated", "Sign in before uploading.")
        size = _int(size, "size")
        chunk_size = _int(chunk_size, "chunk_size")
        if size < 1:
            raise UploadError(
                "invalid_input", "size must be at least 1; use upload_file for an empty file"
            )
        if size > self.max_bytes:
            raise UploadError(
                "too_large",
                f"size is over this server's {self.max_bytes}-byte upload limit",
                max_bytes=self.max_bytes,
            )
        if not MIN_CHUNK <= chunk_size <= MAX_CHUNK:
            raise UploadError(
                "invalid_input", f"chunk_size must be between {MIN_CHUNK} and {MAX_CHUNK}"
            )
        if not isinstance(sha256, str) or not _SHA_RE.fullmatch(sha256.strip().lower()):
            raise UploadError("invalid_input", "sha256 must be 64 hex characters")
        sha256 = sha256.strip().lower()

        starts = self.store.incr(f"{KEY}starts:{who['email']}", self.ttl)
        if starts > MAX_STARTS:
            raise UploadError(
                "too_many_uploads",
                f"At most {MAX_STARTS} uploads can be started in {self.ttl // 60} minutes. "
                "Finish or cancel the open ones, then try again later.",
            )

        upload_id = secrets.token_urlsafe(18)
        now = self.clock()
        expires_at = now + self.ttl
        chunk_count = math.ceil(size / chunk_size)
        meta = {
            "email": who.get("email"),
            "token_name": who.get("token_name"),
            "grant_id": who.get("grant_id"),
            "owner": owner,
            "name": name,
            "mime_type": mime_type,
            "parent_id": parent_id,
            "size": size,
            "sha256": sha256,
            "chunk_size": chunk_size,
            "chunk_count": chunk_count,
            "expires_at": expires_at,
        }
        self.store.set(self._meta_key(upload_id), json.dumps(meta), ex=self.ttl)
        return {
            "upload_id": upload_id,
            "chunk_size": chunk_size,
            "chunk_count": chunk_count,
            "last_chunk_size": size - (chunk_count - 1) * chunk_size,
            "expires_in_seconds": self.ttl,
        }

    def _load(self, who: dict[str, str | None], upload_id: Any) -> dict[str, Any]:
        if not isinstance(upload_id, str) or not _ID_RE.fullmatch(upload_id):
            raise _not_found()
        raw = self.store.get(self._meta_key(upload_id))
        if raw is None:
            raise _not_found()
        try:
            meta = json.loads(raw)
        except ValueError:
            raise _not_found() from None
        if not isinstance(meta, dict):
            raise _not_found()
        for field in ("email", "token_name", "grant_id"):
            if meta.get(field) != who.get(field):
                raise _not_found()
        if float(meta.get("expires_at") or 0) <= self.clock():
            raise _not_found()
        return meta

    def _remaining(self, meta: dict[str, Any]) -> int:
        return max(1, math.ceil(float(meta["expires_at"]) - self.clock()))

    def _expected_length(self, meta: dict[str, Any], index: int) -> int:
        size, chunk_size, count = meta["size"], meta["chunk_size"], meta["chunk_count"]
        return size - (count - 1) * chunk_size if index == count - 1 else chunk_size

    def append(
        self, who: dict[str, str | None], upload_id: Any, index: Any, content_base64: Any
    ) -> dict[str, Any]:
        meta = self._load(who, upload_id)
        index = _int(index, "index")
        count = meta["chunk_count"]
        if not 0 <= index < count:
            raise UploadError(
                "invalid_chunk",
                f"index must be between 0 and {count - 1} for this upload",
                chunk_count=count,
            )
        expected = self._expected_length(meta, index)
        if not isinstance(content_base64, str):
            raise UploadError("invalid_chunk", "content_base64 must be a string")
        encoded = "".join(content_base64.split())
        # A cheap bound before decoding: base64 of `expected` bytes is this long.
        if len(encoded) > 4 * math.ceil(expected / 3):
            raise UploadError(
                "invalid_chunk",
                f"chunk {index} must be exactly {expected} bytes",
                index=index,
                expected_bytes=expected,
            )
        try:
            data = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise UploadError(
                "invalid_chunk", "content_base64 is not valid base64", index=index
            ) from None
        if len(data) != expected:
            raise UploadError(
                "invalid_chunk",
                f"chunk {index} is {len(data)} bytes; it must be exactly {expected} bytes "
                f"(every chunk is chunk_size bytes except the last)",
                index=index,
                expected_bytes=expected,
            )
        stored = base64.b64encode(data).decode("ascii")
        key = self._chunk_key(upload_id, index)
        duplicate = False
        if not self.store.set_if_absent(key, stored, ex=self._remaining(meta)):
            if self.store.get(key) != stored:
                raise UploadError(
                    "chunk_conflict",
                    f"chunk {index} was already received with different content. Cancel "
                    "this upload and start again.",
                    index=index,
                )
            duplicate = True  # a retry of the same piece is harmless
        return {
            "upload_id": upload_id,
            "index": index,
            "byte_count": len(data),
            "duplicate": duplicate,
            "chunk_count": count,
        }

    def take(self, who: dict[str, str | None], upload_id: Any) -> tuple[dict[str, Any], bytes]:
        """Claim the session and return its meta and the checked bytes.

        On success the caller writes the file and then calls `discard`; if the write fails
        it calls `release` so finish can be tried again. A size or hash mismatch discards
        the session: some piece is wrong, and there is no telling which."""
        meta = self._load(who, upload_id)
        if not self.store.set_if_absent(self._claim_key(upload_id), "1", ex=self._remaining(meta)):
            raise UploadError(
                "upload_busy", "This upload is already being finished. Wait for that call."
            )
        try:
            pieces: list[str] = []
            missing: list[int] = []
            for index in range(meta["chunk_count"]):
                piece = self.store.get(self._chunk_key(upload_id, index))
                if piece is None:
                    missing.append(index)
                elif not missing:
                    pieces.append(piece)
            if missing:
                raise UploadError(
                    "missing_chunks",
                    f"{len(missing)} of {meta['chunk_count']} chunks have not been received. "
                    "Send them with append_chunk, then call finish_upload again.",
                    missing=missing[:MISSING_SHOWN],
                    missing_count=len(missing),
                )
            data = b"".join(base64.b64decode(p) for p in pieces)
        except BaseException:
            self.release(upload_id)
            raise
        digest = hashlib.sha256(data).hexdigest()
        if len(data) != meta["size"] or digest != meta["sha256"]:
            self.discard(upload_id, meta)
            raise UploadError(
                "integrity_mismatch",
                "The assembled file does not match the declared size and sha256, so nothing "
                "was written to Drive. The upload was discarded; start again.",
                expected_size=meta["size"],
                received_size=len(data),
                expected_sha256=meta["sha256"],
                received_sha256=digest,
            )
        return meta, data

    def release(self, upload_id: str) -> None:
        self.store.delete(self._claim_key(upload_id))

    def discard(self, upload_id: str, meta: dict[str, Any] | None = None) -> None:
        if meta is None:
            raw = self.store.get(self._meta_key(upload_id))
            meta = json.loads(raw) if raw else {}
        # Delete the session first, so nothing can use the pieces while they go.
        self.store.delete(self._meta_key(upload_id))
        for index in range(int(meta.get("chunk_count") or 0)):
            self.store.delete(self._chunk_key(upload_id, index))
        self.store.delete(self._claim_key(upload_id))

    def cancel(self, who: dict[str, str | None], upload_id: Any) -> dict[str, Any]:
        meta = self._load(who, upload_id)
        self.discard(upload_id, meta)
        return {"upload_id": upload_id, "cancelled": True}

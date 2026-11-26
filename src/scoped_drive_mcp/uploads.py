"""Chunked uploads: an assistant sends a file it made in pieces, then the whole is checked
and created in Drive (or the person's OneDrive) in one step.

A model can't reliably copy tens of thousands of base64 characters into one tool call, so
`upload_file` alone can't carry a PDF or an image an assistant generated. Here the
assistant declares the file first (name, type, folder, size and SHA-256), sends it in
fixed-size pieces, and asks for it to be finished. Nothing reaches Drive until every piece
is here and the assembled bytes match the declared size and hash, so a bad copy never
becomes a broken file in someone's Drive.

**Upload links** (`DirectUploads`): an assistant whose sandbox can make HTTPS requests
asks for one with `direct`. It gets a presigned Vercel Blob URL (api/blob-sign.mjs) for
one pathname, `uploads/<expiry>/<upload id>`, at most the declared size, that can't
overwrite, valid until the session expires, and uploads the whole file there itself, so
the bytes never pass through the model. Finishing reads it back from Blob and runs the
same checks; pieces sent with append_chunk still work for the same session. The file
sits unencrypted in the private store until the session is finished, cancelled or
expires (the Blob sweep deletes what is left).

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
import logging
import math
import re
import secrets
import time
from collections.abc import Callable
from typing import Any

from .drop_storage import PIECE_BYTES, UPLOAD_BLOB_PREFIX, BlobApi, BlobBudget, BlobSigner
from .errors import report_exception
from .store import KeyValueStore

logger = logging.getLogger(__name__)

UPLOAD_TTL = 15 * 60
# Bytes per piece. Every piece but the last is exactly chunk_size bytes, so the number of
# pieces, and the space a session can take in the store, follow from the declared size.
MIN_CHUNK = 1024
MAX_CHUNK = 512 * 1024
# 6 KiB of bytes is exactly 8,192 base64 characters per call.
DEFAULT_CHUNK = 6 * 1024
# Pieces in one upload. With MAX_BYTES up to 50 MiB, chunk_size must grow with the file, so
# finishing or cancelling never takes more than this many store round trips.
MAX_CHUNKS = 1024
# Uploads one account may start in UPLOAD_TTL seconds, and have open at once.
MAX_STARTS = 10
MAX_OPEN = 3
# How many missing piece numbers an error lists.
MISSING_SHOWN = 50

# Where a finished upload is written. A session started before targets existed has none
# and is a Drive upload.
TARGETS = frozenset({"drive", "onedrive"})

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


class DirectUploads:
    """Upload links into the deployment's private Blob store (see the module notes).
    `budget` keeps them inside the same free-tier caps as held files."""

    def __init__(self, api: BlobApi, signer: BlobSigner, budget: BlobBudget | None) -> None:
        self.api = api
        self.signer = signer
        self.budget = budget


def blob_path(upload_id: str, expires_at: float) -> str:
    return f"{UPLOAD_BLOB_PREFIX}{math.ceil(expires_at)}/{upload_id}"


def _unavailable(why: str) -> UploadError:
    return UploadError(
        "direct_unavailable",
        f"{why} Start again without direct and send the file with append_chunk.",
    )


def upload_command(url: str, headers: dict[str, str]) -> str:
    """The curl command that uploads FILE to `url`. Header values come from the signer
    and are checked to be plain tokens; the URL is checked by drop_storage."""
    parts = ["curl -sS --fail-with-body -X PUT"]
    for name, value in sorted(headers.items()):
        parts.append(f"-H '{name}: {value}'")
    parts.append("--data-binary @FILE")
    parts.append(f"'{url}'")
    return " ".join(parts)


_HEADER_NAME = re.compile(r"[A-Za-z0-9-]{1,64}")
_HEADER_VALUE = re.compile(r"[A-Za-z0-9._/+-]{1,128}")


class UploadSessions:
    def __init__(
        self,
        store: KeyValueStore,
        max_bytes: int,
        *,
        clock: Callable[[], float] = time.time,
        ttl: int = UPLOAD_TTL,
        direct: DirectUploads | None = None,
    ) -> None:
        self.store = store
        self.max_bytes = max_bytes
        self.clock = clock
        self.ttl = ttl
        self.direct = direct

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

    @staticmethod
    def _open_key(email: str) -> str:
        return f"{KEY}open:{email}"

    def _open_uploads(self, email: str) -> int:
        """Uploads this account has open, dropping ones that have expired."""
        key = self._open_key(email)
        now = self.clock()
        live = 0
        for upload_id, expires in self.store.hgetall(key).items():
            try:
                alive = float(expires) > now
            except ValueError:
                alive = False
            if alive:
                live += 1
            else:
                self.store.hdel(key, upload_id)
        return live

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
        target: str = "drive",
        direct: bool = False,
    ) -> dict[str, Any]:
        """Open a session. The caller has already checked the name, type and parent.
        `target` is where finish_upload writes the file: "drive" (Google Drive, the
        person's own or `owner`'s shared folder) or "onedrive" (the person's OneDrive)."""
        if target not in TARGETS:
            raise UploadError("invalid_input", "unknown upload target")
        if not isinstance(direct, bool):
            raise UploadError("invalid_input", "direct must be true or false")
        if direct and self.direct is None:
            raise _unavailable("This server can't give upload links (no Blob store).")
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
        chunk_count = math.ceil(size / chunk_size)
        if chunk_count > MAX_CHUNKS:
            raise UploadError(
                "invalid_input",
                f"a file of {size} bytes needs chunk_size of at least "
                f"{math.ceil(size / MAX_CHUNKS)} (at most {MAX_CHUNKS} chunks per upload)",
                min_chunk_size=math.ceil(size / MAX_CHUNKS),
            )
        email = str(who["email"])
        if self._open_uploads(email) >= MAX_OPEN:
            raise UploadError(
                "too_many_uploads",
                f"At most {MAX_OPEN} uploads can be open at once. Finish or cancel one first.",
            )

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
        link = self._link(upload_id, expires_at, size) if direct else None
        meta = {
            "email": who.get("email"),
            "token_name": who.get("token_name"),
            "grant_id": who.get("grant_id"),
            "owner": owner,
            "target": target,
            "name": name,
            "mime_type": mime_type,
            "parent_id": parent_id,
            "size": size,
            "sha256": sha256,
            "chunk_size": chunk_size,
            "chunk_count": chunk_count,
            "expires_at": expires_at,
            "blob_path": link["path"] if link else None,
        }
        self.store.set(self._meta_key(upload_id), json.dumps(meta), ex=self.ttl)
        self.store.hset(self._open_key(email), upload_id, str(expires_at))
        started: dict[str, Any] = {
            "upload_id": upload_id,
            "chunk_size": chunk_size,
            "chunk_count": chunk_count,
            "last_chunk_size": size - (chunk_count - 1) * chunk_size,
            "expires_in_seconds": self.ttl,
        }
        if link:
            started["upload_url"] = link["url"]
            started["upload_headers"] = link["headers"]
            started["upload_command"] = upload_command(link["url"], link["headers"])
        return started

    def _link(self, upload_id: str, expires_at: float, size: int) -> dict[str, Any]:
        """A presigned PUT for this upload's pathname, at most `size` bytes. Signed first
        and charged to the Blob budget after, so a failed signing costs nothing. A link
        that is never used still counts: there is no telling whether it was."""
        assert self.direct is not None
        budget = self.direct.budget
        if budget is not None and not budget.allows(max(1, math.ceil(size / PIECE_BYTES))):
            raise _unavailable("Upload links are used up for now.")
        path = blob_path(upload_id, expires_at)
        try:
            signed = self.direct.signer.sign_put(path, size, self.ttl, 1)
        except Exception as exc:
            report_exception(exc, where="upload_link")
            raise _unavailable("An upload link could not be made just now.") from None
        raw = signed.get("headers") if isinstance(signed, dict) else None
        headers = dict(raw) if isinstance(raw, dict) else {}
        url = signed.get("url") if isinstance(signed, dict) else None
        unsafe = [
            name
            for name, value in headers.items()
            if not (
                isinstance(name, str)
                and isinstance(value, str)
                and _HEADER_NAME.fullmatch(name)
                and _HEADER_VALUE.fullmatch(value)
            )
        ]
        if unsafe or not isinstance(url, str) or "'" in url:
            # Dropping a header would make the upload fail at Blob for no stated reason.
            logger.error("refused an upload link with %d unexpected header(s)", len(unsafe))
            raise _unavailable("An upload link could not be made just now.")
        if budget is not None and not budget.reserve(max(1, math.ceil(size / PIECE_BYTES))):
            raise _unavailable("Upload links are used up for now.")
        return {"path": path, "url": url, "headers": headers}

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
        if self.store.get(self._claim_key(upload_id)) is not None:
            raise UploadError(
                "upload_busy", "This upload is being finished; no more chunks are taken."
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
        elif self.store.get(self._meta_key(upload_id)) is None:
            # Cancelled or finished while this piece was on its way: don't leave it behind.
            self.store.delete(key)
            raise _not_found()
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
            data = self._uploaded(meta)
        except BaseException:
            self.release(upload_id)
            raise
        if data is None:
            data = self._assembled(upload_id, meta)
        self._check(upload_id, meta, data)
        return meta, data

    def _uploaded(self, meta: dict[str, Any]) -> bytes | None:
        """The file uploaded through the session's link, or None when nothing is there."""
        path = meta.get("blob_path")
        if not path:
            return None
        if self.direct is None:
            # Blob was turned off after this upload started.
            return None
        try:
            return self.direct.api.get(str(path))
        except Exception as exc:
            report_exception(exc, where="upload_link_read")
            raise UploadError(
                "upload_unavailable",
                "The uploaded file could not be read from storage just now. Call "
                "finish_upload again.",
            ) from None

    def _assembled(self, upload_id: str, meta: dict[str, Any]) -> bytes:
        """The pieces sent with append_chunk, joined. Releases the claim on failure."""
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
                if meta.get("blob_path") and len(missing) == meta["chunk_count"]:
                    raise UploadError(
                        "upload_not_received",
                        "Nothing has arrived for this upload yet. Run upload_command "
                        "(or send the pieces with append_chunk), then call finish_upload "
                        "again.",
                    )
                raise UploadError(
                    "missing_chunks",
                    f"{len(missing)} of {meta['chunk_count']} chunks have not been received. "
                    "Send them with append_chunk, then call finish_upload again.",
                    missing=missing[:MISSING_SHOWN],
                    missing_count=len(missing),
                )
            return b"".join(base64.b64decode(p) for p in pieces)
        except BaseException:
            self.release(upload_id)
            raise

    def _check(self, upload_id: str, meta: dict[str, Any], data: bytes) -> None:
        """A size or hash mismatch discards the session: some byte is wrong, and there is
        no telling which."""
        digest = hashlib.sha256(data).hexdigest()
        if len(data) != meta["size"] or digest != meta["sha256"]:
            try:
                self.discard(upload_id, meta)
            finally:
                self.release(upload_id)
            raise UploadError(
                "integrity_mismatch",
                "The assembled file does not match the declared size and sha256, so nothing "
                "was written. The upload was discarded; start again.",
                expected_size=meta["size"],
                received_size=len(data),
                expected_sha256=meta["sha256"],
                received_sha256=digest,
            )

    def release(self, upload_id: str) -> None:
        self.store.delete(self._claim_key(upload_id))

    def discard(self, upload_id: str, meta: dict[str, Any] | None = None) -> None:
        if meta is None:
            raw = self.store.get(self._meta_key(upload_id))
            meta = json.loads(raw) if raw else {}
        # Delete the session first, so nothing can use the pieces while they go.
        self.store.delete(self._meta_key(upload_id))
        path = meta.get("blob_path")
        if path and self.direct is not None:
            try:
                self.direct.api.delete([str(path)])
            except Exception as exc:
                # The Blob sweep deletes it once its expiry has passed.
                report_exception(exc, where="upload_link_delete")
        if meta.get("email"):
            self.store.hdel(self._open_key(str(meta["email"])), upload_id)
        for index in range(int(meta.get("chunk_count") or 0)):
            self.store.delete(self._chunk_key(upload_id, index))
        self.store.delete(self._claim_key(upload_id))

    def cancel(self, who: dict[str, str | None], upload_id: Any) -> dict[str, Any]:
        meta = self._load(who, upload_id)
        self.discard(upload_id, meta)
        return {"upload_id": upload_id, "cancelled": True}

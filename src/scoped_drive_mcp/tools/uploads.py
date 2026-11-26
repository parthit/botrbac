"""Chunked upload tools, for a file too big to pass inline to upload_file (or, when
OneDrive is set up, onedrive_upload_file). One set of append_chunk, finish_upload and
cancel_upload serves both: the session remembers where the file goes."""

import mimetypes
from collections.abc import Callable
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..auth import current_principal
from ..onedrive import OneDriveService
from ..policy import PayloadToolError, require
from ..service import DriveService
from ..uploads import DEFAULT_CHUNK, UploadError, UploadSessions
from .common import WRITE, Guarded, _run
from .shared import RunShared


def register(
    mcp: FastMCP,
    guarded: Guarded,
    service: DriveService,
    sessions: UploadSessions,
    run_shared: RunShared,
    onedrive: OneDriveService | None = None,
) -> None:
    # ---- chunked uploads (uploads.py) ----------------------------------------------

    def upload_who() -> dict[str, str | None]:
        principal = current_principal.get()
        return {
            "email": principal.email if principal else None,
            "token_name": principal.token_name if principal else None,
            "grant_id": principal.grant_id if principal else None,
        }

    def run_upload(fn: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        try:
            return fn()
        except UploadError as exc:
            raise PayloadToolError(exc.payload()) from None

    def begin_upload(
        name: str,
        mime_type: str,
        size: int,
        sha256: str,
        parent_id: str | None,
        chunk_size: int,
        owner: str | None,
    ) -> dict[str, Any]:
        name, mime_type = service.check_upload_meta(name, mime_type)
        who = upload_who()
        if owner:
            checked = run_shared("check_upload_parent", owner, parent_id)
            parent = checked["parent_id"]
            owner = checked["owner"]
        else:
            parent = service.resolve_parent(parent_id)
        started = run_upload(
            lambda: sessions.start(
                who,
                name=name,
                mime_type=mime_type,
                parent_id=parent,
                size=size,
                sha256=sha256,
                chunk_size=chunk_size,
                owner=owner or None,
            )
        )
        return {
            **started,
            "parent_id": parent,
            **({"owner": owner} if owner else {}),
            "next": "Send each chunk with append_chunk (index 0 to chunk_count - 1), then "
            "call finish_upload.",
        }

    def begin_onedrive_upload(
        onedrive_service: OneDriveService,
        name: str,
        size: int,
        sha256: str,
        parent_id: str | None,
        chunk_size: int,
    ) -> dict[str, Any]:
        # The same checks as onedrive_upload_file, before any piece is sent.
        clean, parent = onedrive_service.check_upload(name, parent_id)
        mime_type = mimetypes.guess_type(clean)[0] or "application/octet-stream"
        started = run_upload(
            lambda: sessions.start(
                upload_who(),
                name=clean,
                mime_type=mime_type,
                parent_id=parent,
                size=size,
                sha256=sha256,
                chunk_size=chunk_size,
                target="onedrive",
            )
        )
        return {
            **started,
            "parent_id": parent,
            "next": "Send each chunk with append_chunk (index 0 to chunk_count - 1), then "
            "call finish_upload.",
        }

    def write_onedrive(meta: dict[str, Any], data: bytes) -> dict[str, Any]:
        if onedrive is None:
            # OneDrive was turned off on the server after this upload started.
            raise PayloadToolError(
                {
                    "error": "onedrive_unavailable",
                    "message": "OneDrive is not set up on this server any more. "
                    "Call cancel_upload.",
                }
            )
        # upload_bytes checks the connection, that it was granted editing, and the folder
        # again: the allowed list may have changed since the upload started.
        return onedrive.upload_bytes(meta["name"], data, meta["parent_id"])

    def complete_upload(upload_id: str) -> dict[str, Any]:
        meta, data = run_upload(lambda: sessions.take(upload_who(), upload_id))
        try:
            if meta.get("target") == "onedrive":
                created = write_onedrive(meta, data)
            elif meta.get("owner"):
                created = run_shared(
                    "upload_bytes",
                    meta["owner"],
                    meta["name"],
                    meta["mime_type"],
                    data,
                    meta["parent_id"],
                    sessions.max_bytes,
                )
            else:
                created = service.upload_bytes(
                    meta["name"],
                    meta["mime_type"],
                    data,
                    meta["parent_id"],
                    max_bytes=sessions.max_bytes,
                )
        except BaseException:
            # Nothing was written, so the pieces stay and finish can be tried again.
            sessions.release(upload_id)
            raise
        sessions.discard(upload_id, meta)
        return {
            **created,
            "upload_id": upload_id,
            "byte_count": len(data),
            "sha256": meta["sha256"],
        }

    @mcp.tool(annotations=WRITE)
    @guarded("start_upload")
    async def start_upload(
        name: str,
        mime_type: str,
        size: int,
        sha256: str,
        parent_id: str | None = None,
        chunk_size: int = DEFAULT_CHUNK,
        owner: str | None = None,
    ) -> dict[str, Any]:
        """Start uploading a file too big to pass inline to upload_file (a PDF, DOCX or
        image you made). Give its exact size in bytes and its SHA-256 (64 hex chars), e.g.
        from `sha256sum`. Then send the bytes in order-independent pieces with append_chunk:
        piece i is bytes [i*chunk_size, (i+1)*chunk_size) of the file, base64-encoded
        (e.g. `split -b 6144 -d`). Every piece but the last is exactly chunk_size bytes
        (default 6144, i.e. 8192 base64 chars; 1024 to 524288). Then call finish_upload,
        which writes the file only if the size and hash match. Same folder checks as
        upload_file. To write into a folder another person shares with you and lets you
        edit, pass their email as owner. The upload expires after 15 minutes. For
        OneDrive, use onedrive_start_upload instead."""
        return await _run(begin_upload, name, mime_type, size, sha256, parent_id, chunk_size, owner)

    @mcp.tool(annotations=WRITE)
    @guarded("append_chunk")
    async def append_chunk(upload_id: str, index: int, content_base64: str) -> dict[str, Any]:
        """Send piece `index` (0-based) of an upload started with start_upload (or
        onedrive_start_upload), as base64.
        Sending the same piece again is harmless; a different piece under the same index is
        refused."""
        return await _run(
            run_upload, lambda: sessions.append(upload_who(), upload_id, index, content_base64)
        )

    @mcp.tool(annotations=WRITE)
    @guarded("finish_upload")
    async def finish_upload(upload_id: str) -> dict[str, Any]:
        """Check an upload's pieces against the declared size and SHA-256 and create the
        file in Drive (or in OneDrive, for an upload started with onedrive_start_upload).
        Missing pieces are listed in the error (send them and call again). On a mismatch
        nothing is written and the upload is discarded."""
        return await _run(complete_upload, upload_id)

    @mcp.tool(annotations=WRITE)
    @guarded("cancel_upload")
    async def cancel_upload(upload_id: str) -> dict[str, Any]:
        """Discard an unfinished upload and the pieces sent so far. Nothing is written."""
        return await _run(run_upload, lambda: sessions.cancel(upload_who(), upload_id))

    if onedrive is not None:
        onedrive_service = onedrive

        @mcp.tool(annotations=WRITE)
        @require("onedrive_start_upload")
        async def onedrive_start_upload(
            name: str,
            size: int,
            sha256: str,
            parent_id: str | None = None,
            chunk_size: int = DEFAULT_CHUNK,
        ) -> dict[str, Any]:
            """Start uploading a new OneDrive file too big to pass inline to
            onedrive_upload_file (a PDF, DOCX or image you made). Works like start_upload:
            give the exact size in bytes and the SHA-256 (64 hex chars), send the pieces
            with append_chunk, then call finish_upload, which creates the file in the
            allowed OneDrive folder only if the size and hash match. The type comes from
            the name's extension. A taken name fails with name_taken; nothing is
            overwritten. Omit parent_id only when exactly one OneDrive folder is allowed.
            The upload expires after 15 minutes."""
            return await _run(
                begin_onedrive_upload,
                onedrive_service,
                name,
                size,
                sha256,
                parent_id,
                chunk_size,
            )

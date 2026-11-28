"""Shared with me pages: browsing, opening and searching what paired people share,
and held files (drops) sent to or from this person.
"""

import base64
import os
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from typing import Any
from urllib.parse import quote

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from ..audit import audit_owner
from ..external import SharedAccessError, normalize_email
from ..ratelimit import allow
from ..shared_sources import VIA_DASHBOARD
from .common import (
    _SHARED_ID,
    DROP_PIECE_LIMIT,
    DROP_UPLOAD_LIMIT,
    DROP_UPLOAD_MB,
    DROPS_SHOWN,
    attachment_disposition,
    shared_href,
)
from .kit import FormHandler, Handler, Kit


@dataclass(frozen=True)
class DropPages:
    """What dashboard.py needs from this module: the handlers it routes to, and
    the helpers other page modules call."""

    shared_overview: Handler
    shared_search: Handler
    shared_browse: Handler
    shared_open: Handler
    shared_download: Handler
    drop_send: FormHandler
    drop_begin: FormHandler
    drop_piece_put: FormHandler
    drop_finish: FormHandler
    drop_allow: FormHandler
    drop_download: Handler
    drop_piece_get: Handler
    drop_piece_link: Handler
    drop_act: FormHandler
    body_limited: Callable[[Handler, int], Handler]


def drop_pages(kit: Kit) -> DropPages:
    ctx = kit.ctx
    peer_requests = kit.peer_requests
    refused = kit.refused
    render = kit.render
    flash = kit.flash
    blocking = kit.blocking

    # ---- shared with me ------------------------------------------------
    # The receiving side of Sharing: what paired people let this person read, across
    # every source, browsable to any depth. Every call runs the same guest checks as the
    # MCP tools (pairing active, item on the owner's shared list, read-only), and is
    # recorded on the owner's activity log as "guest:<you> (dashboard)".

    def shared_error(request: Request, exc: SharedAccessError) -> Response:
        status = {
            "invalid_input": 400,
            "owner_unavailable": 503,
            "no_bytes": 404,
        }.get(exc.code, 403)
        message = exc.message
        if exc.code == "own_drive":
            # The MCP wording names tools. A person opens their own files from Browse.
            message = "This is in your own Drive. Open it from Browse."
        elif exc.code == "invalid_input" and ("_shared_" in message or "read_file" in message):
            # Drive's wording for an assistant (it names tools). Say it for a person.
            message = (
                "This item can't be opened that way. If it is a folder, open it from the list."
            )
        return render(request, "shared_error.html", status, message=message, code=exc.code)

    def shared_args(request: Request) -> tuple[Any, str, str | None]:
        """The source, owner and item id from the query string, checked for shape only.
        Whether the caller may see the item is decided by the source on every call."""
        source = ctx.shared_with_me.get(request.query_params.get("source") or "google_drive")
        if source is None:
            raise SharedAccessError("invalid_input", "That source is not available here.")
        owner = normalize_email(request.query_params.get("owner"))
        item = request.query_params.get("id") or None
        if item is not None and not _SHARED_ID.fullmatch(item):
            raise SharedAccessError("invalid_input", "That item id is not valid.")
        return source, owner, item

    async def shared_overview(request: Request) -> Response:
        if ctx.shared_with_me is None:
            return render(request, "error.html", 404, message="Sharing is not set up.")
        email = str(request.session.get("owner") or "")

        def gather() -> dict[str, Any]:
            peers = ctx.mailbox.active_peers(email) if ctx.mailbox is not None else []
            data: dict[str, Any] = {
                "people": ctx.shared_with_me.overview(email),
                "peers": peers,
                "drops_on": ctx.drops is not None,
                "drops_direct": ctx.drops is not None and ctx.drops.direct,
                "drops_store_host": ctx.drops.store_host if ctx.drops is not None else None,
                "received": [],
                "send_limit_mb": DROP_UPLOAD_MB,
                "send_max_mb": ctx.drops.max_mb if ctx.drops is not None else 0,
                "send_max_bytes": ctx.drops.max_bytes if ctx.drops is not None else 0,
                "hold_hours": ctx.drops.hold_hours if ctx.drops is not None else 0,
            }
            if ctx.drops is not None:
                data["received"] = [
                    # The page needs no key (a download asks for it, piece by piece).
                    {
                        **{k: v for k, v in row.items() if k != "key"},
                        "pieces": ctx.drops.pieces(row),
                    }
                    for row in ctx.drops.received(DROPS_SHOWN)
                ]
            # Asking a paired person for something (peer_requests.py).
            data["ask_on"] = peer_requests is not None
            if peer_requests is not None:
                data["ask_sent"] = peer_requests.sent(email)
                data["askable"] = {p: peer_requests.askable(email, p) for p in peers}
            return data

        data = await blocking(gather)
        return render(request, "shared.html", **data)

    async def drop_send(request: Request, form: dict[str, str]) -> Response:
        """A person sends one file from the dashboard to someone they are paired with."""
        back = "/sharing?tab=with-me"
        if ctx.drops is None:
            return render(request, "error.html", 404, message="Sending files is not set up.")
        email = str(request.session.get("owner") or "")
        upload = (await request.form()).get("file")
        to = (form.get("to") or "").strip()
        if not to:
            flash(request, "error", "Pick who to send the file to.")
            return RedirectResponse(back, status_code=303)
        if upload is None or isinstance(upload, str) or not upload.filename:
            flash(request, "error", "Choose a file to send.")
            return RedirectResponse(back, status_code=303)
        data = await upload.read(DROP_UPLOAD_LIMIT + 1)
        if len(data) > DROP_UPLOAD_LIMIT:
            flash(request, "error", f"That file is larger than {DROP_UPLOAD_MB} MB.")
            return RedirectResponse(back, status_code=303)
        if not data:
            flash(request, "error", "That file is empty.")
            return RedirectResponse(back, status_code=303)
        mime = (upload.content_type or "").split(";")[0].strip() or "application/octet-stream"
        try:
            sent = await blocking(
                ctx.drops.send,
                email,
                to,
                upload.filename,
                mime,
                None,
                base64.b64encode(data).decode(),
                via=VIA_DASHBOARD,
            )
        except SharedAccessError as exc:
            flash(request, "error", exc.message)
        else:
            flash(request, "ok", f"Sent “{sent['name']}” to {sent['to']}.")
        return RedirectResponse(back, status_code=303)

    def body_limited(handler: Handler, limit: int) -> Handler:
        """Refuse a request body larger than `limit` before it is read."""

        async def wrapped(request: Request) -> Response:
            try:
                length = int(request.headers.get("content-length") or "")
            except ValueError:
                length = -1
            if length < 0 or length > limit:
                return refused(
                    request,
                    413,
                    f"That file is too large to send. The limit is {DROP_UPLOAD_MB} MB.",
                    title="File too large",
                )
            return await handler(request)

        return wrapped

    def drop_json_error(exc: SharedAccessError) -> Response:
        return JSONResponse({"ok": False, "error": exc.code, "message": exc.message}, 400)

    async def drop_begin(request: Request, form: dict[str, str]) -> Response:
        """Start sending a file in pieces (ui.js): every check, before any bytes."""
        if ctx.drops is None:
            return JSONResponse({"ok": False, "message": "Sending files is not set up."}, 404)
        email = str(request.session.get("owner") or "")
        try:
            size = int(form.get("size") or "")
        except ValueError:
            size = -1
        mime = (form.get("type") or "").split(";")[0].strip() or "application/octet-stream"
        try:
            started = await blocking(
                partial(
                    ctx.drops.begin,
                    email,
                    (form.get("to") or "").strip(),
                    form.get("name") or "",
                    mime,
                    size,
                    via=VIA_DASHBOARD,
                    # ui.js sends direct=0 when the browser cannot encrypt or reach Blob.
                    direct=form.get("direct") != "0",
                )
            )
        except SharedAccessError as exc:
            return drop_json_error(exc)
        return JSONResponse({"ok": True, **started})

    async def drop_piece_put(request: Request, form: dict[str, str]) -> Response:
        """One piece of a file being sent (ui.js)."""
        if ctx.drops is None:
            return JSONResponse({"ok": False, "message": "Sending files is not set up."}, 404)
        email = str(request.session.get("owner") or "")
        piece = (await request.form()).get("piece")
        if piece is None or isinstance(piece, str):
            return JSONResponse({"ok": False, "message": "No file data arrived."}, 400)
        data = await piece.read(DROP_PIECE_LIMIT + 1)
        try:
            n = int(request.path_params["n"])
        except ValueError:
            n = -1
        try:
            await blocking(ctx.drops.put_piece, email, request.path_params["upload_id"], n, data)
        except SharedAccessError as exc:
            return drop_json_error(exc)
        return JSONResponse({"ok": True})

    async def drop_finish(request: Request, form: dict[str, str]) -> Response:
        """All pieces sent: list the file for its recipient (ui.js)."""
        if ctx.drops is None:
            return JSONResponse({"ok": False, "message": "Sending files is not set up."}, 404)
        email = str(request.session.get("owner") or "")
        try:
            sent = await blocking(ctx.drops.finish, email, request.path_params["upload_id"])
        except SharedAccessError as exc:
            return drop_json_error(exc)
        message = f"Sent “{sent['name']}” to {sent['to']}."
        flash(request, "ok", message)
        return JSONResponse({"ok": True, "message": message})

    async def drop_piece_get(request: Request) -> Response:
        """One piece of a held file, for the recipient's browser to join (ui.js). Each
        response stays under Vercel's 4.5 MB limit."""
        if ctx.drops is None:
            return Response(status_code=404)
        try:
            n = int(request.path_params["n"])
        except ValueError:
            n = -1
        try:
            _row, data = await blocking(ctx.drops.piece, request.path_params["drop_id"], n)
        except SharedAccessError as exc:
            return drop_json_error(exc)
        return Response(
            data,
            media_type="application/octet-stream",
            headers={"Content-Disposition": "attachment", "Cache-Control": "no-store"},
        )

    async def drop_piece_link(request: Request) -> Response:
        """Where the recipient's browser fetches one piece: a presigned Blob URL valid for
        a few minutes, with the key that opens it, when the piece was uploaded straight
        to Blob; else this app's own piece route (ui.js)."""
        if ctx.drops is None:
            return Response(status_code=404)
        drop_id = request.path_params["drop_id"]
        try:
            n = int(request.path_params["n"])
        except ValueError:
            n = -1
        try:
            link = await blocking(ctx.drops.piece_link, drop_id, n)
        except SharedAccessError as exc:
            return drop_json_error(exc)
        if link is None:
            return JSONResponse({"ok": True, "url": f"/drops/{quote(drop_id, safe='')}/piece/{n}"})
        return JSONResponse({"ok": True, "direct": True, **link})

    async def drop_download(request: Request) -> Response:
        """The recipient downloads a held file. Never served inline: it is another
        person's file and this is our origin."""
        if ctx.drops is None:
            return render(request, "error.html", 404, message="Sending files is not set up.")
        try:
            row, data = await blocking(ctx.drops.download, request.path_params["drop_id"])
        except SharedAccessError as exc:
            flash(request, "error", exc.message)
            return RedirectResponse("/sharing?tab=with-me", status_code=303)
        if len(data) > DROP_PIECE_LIMIT and os.environ.get("VERCEL", "").strip():
            # One response this large is refused on Vercel; ui.js downloads it in pieces.
            flash(
                request,
                "error",
                "This file is too large to download without JavaScript. Turn JavaScript on, "
                "or save it to Google Drive and open it there.",
            )
            return RedirectResponse("/sharing?tab=with-me", status_code=303)
        return Response(
            data,
            media_type="application/octet-stream",
            headers={"Content-Disposition": attachment_disposition(str(row.get("name") or "file"))},
        )

    async def drop_act(request: Request, form: dict[str, str]) -> Response:
        """Save a held file to the recipient's Drive, or delete it now."""
        if ctx.drops is None:
            return render(request, "error.html", 404, message="Sending files is not set up.")
        drop_id = request.path_params["drop_id"]
        action = request.path_params["action"]
        try:
            if action == "save":
                saved = await blocking(ctx.drops.save, drop_id)
                audit_owner("drop_saved", file_id=saved["file_id"])
                flash(
                    request,
                    "ok",
                    f"Saved “{saved['name']}” to “Sent to me (Bot RBAC)” in your Google Drive.",
                )
            elif action == "dismiss":
                await blocking(ctx.drops.dismiss, drop_id)
                audit_owner("drop_deleted", drop=drop_id)
                flash(request, "ok", "Deleted.")
            else:
                return render(request, "error.html", 404, message="That page is not available.")
        except SharedAccessError as exc:
            flash(request, "error", exc.message)
        return RedirectResponse("/sharing?tab=with-me", status_code=303)

    async def drop_allow(request: Request, form: dict[str, str]) -> Response:
        """Turn files from one paired person on or off."""
        if ctx.drops is None:
            return render(request, "error.html", 404, message="Sending files is not set up.")
        person = (form.get("person") or "").strip()
        on = form.get("on") == "1"
        try:
            await blocking(ctx.drops.set_allowed, person, on)
        except SharedAccessError as exc:
            flash(request, "error", exc.message)
        else:
            audit_owner("drops_on" if on else "drops_off", person=person.lower())
            flash(
                request,
                "ok",
                f"{person} can send you files again."
                if on
                else f"{person} can no longer send you files. Your pairing is still on.",
            )
        return RedirectResponse("/sharing?tab=people", status_code=303)

    async def shared_search(request: Request) -> Response:
        if ctx.shared_with_me is None:
            return render(request, "error.html", 404, message="Sharing is not set up.")
        email = str(request.session.get("owner") or "")
        q = (request.query_params.get("q") or "").strip()
        if not q:
            return RedirectResponse("/sharing?tab=with-me", status_code=303)
        allowed = await blocking(
            allow, ctx.store, "shared_search", "user:" + email, kit.shared_search_limit(), 60
        )
        if not allowed:
            # Each search reads every sharer's Drive; keep one person from using up theirs.
            return render(
                request,
                "error.html",
                429,
                message="Too many searches. Wait a minute and try again.",
            )
        try:
            results = await blocking(ctx.shared_with_me.search, email, q)
        except SharedAccessError as exc:
            return shared_error(request, exc)
        return render(request, "shared_search.html", q=q, results=results)

    async def shared_browse(request: Request) -> Response:
        if ctx.shared_with_me is None:
            return render(request, "error.html", 404, message="Sharing is not set up.")
        email = str(request.session.get("owner") or "")
        try:
            source, owner, folder = shared_args(request)
            listing = await blocking(source.list, email, owner, folder)
        except SharedAccessError as exc:
            return shared_error(request, exc)
        return render(
            request,
            "shared_browse.html",
            source=source,
            shared_owner=owner,
            listing=listing,
        )

    async def shared_open(request: Request) -> Response:
        if ctx.shared_with_me is None:
            return render(request, "error.html", 404, message="Sharing is not set up.")
        email = str(request.session.get("owner") or "")
        try:
            source, owner, item = shared_args(request)
            if item is None:
                raise SharedAccessError("invalid_input", "Pick an item to open.")
            doc = await blocking(source.open, email, owner, item)
        except SharedAccessError as exc:
            return shared_error(request, exc)
        if doc.node.is_container:
            return RedirectResponse(
                shared_href("browse", source.key, owner, doc.node.id), status_code=303
            )
        return render(request, "shared_item.html", source=source, shared_owner=owner, doc=doc)

    async def shared_download(request: Request) -> Response:
        if ctx.shared_with_me is None:
            return render(request, "error.html", 404, message="Sharing is not set up.")
        email = str(request.session.get("owner") or "")
        try:
            source, owner, item = shared_args(request)
            if item is None:
                raise SharedAccessError("invalid_input", "Pick an item to download.")
            got = await blocking(source.download, email, owner, item)
        except SharedAccessError as exc:
            return shared_error(request, exc)
        # Never served inline: the bytes come from another person and this is our origin.
        # Cache-Control: no-store and nosniff come from the security headers middleware.
        return Response(
            got.data,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": attachment_disposition(got.filename),
                "X-Download-Truncated": "1" if got.truncated else "0",
            },
        )

    return DropPages(
        shared_overview=shared_overview,
        shared_search=shared_search,
        shared_browse=shared_browse,
        shared_open=shared_open,
        shared_download=shared_download,
        drop_send=drop_send,
        drop_begin=drop_begin,
        drop_piece_put=drop_piece_put,
        drop_finish=drop_finish,
        drop_allow=drop_allow,
        drop_download=drop_download,
        drop_piece_get=drop_piece_get,
        drop_piece_link=drop_piece_link,
        drop_act=drop_act,
        body_limited=body_limited,
    )

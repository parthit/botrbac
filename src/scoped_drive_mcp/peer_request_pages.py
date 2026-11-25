"""Dashboard pages for requests between paired people (peer_requests.py).

These are the only way in or out for those requests: a signed-in person's browser, with
the same session, CSRF and same-origin checks as every other dashboard form.
"""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import anyio
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from .access import MAX_TEXT
from .grants import GrantError, GrantService
from .peer_requests import DESCRIBE, EDIT, MORE_TIME, PER_DAY, PeerRequestService
from .scope import InvalidInputError

Handler = Callable[[Request], Awaitable[Response]]
FormHandler = Callable[[Request, dict[str, str]], Awaitable[Response]]

SENT = "/sharing?tab=with-me#ask"
# Told to the person asking whatever happened, so the answer says nothing about the
# other person's account or files.
SENT_MESSAGE = (
    "Request sent. If you are paired, they will see it on their Requests page. "
    f"Up to {PER_DAY} requests a day reach each person."
)


@dataclass(frozen=True)
class Kit:
    """The dashboard helpers these pages use (all defined in dashboard.py)."""

    owner_only: Callable[[Handler], Handler]
    csrf_protected: Callable[[FormHandler], Handler]
    render: Callable[..., Response]
    flash: Callable[[Request, str, str], None]
    ext_grants: Callable[[], GrantService]
    end_of_day: Callable[[str], str | None]


async def _run(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    return await anyio.to_thread.run_sync(lambda: fn(*args, **kwargs))


def _me(request: Request) -> str:
    return str(request.session.get("owner") or "")


def page_routes(service: PeerRequestService, kit: Kit) -> list[Route]:
    def missing(request: Request) -> Response:
        return kit.render(
            request,
            "error.html",
            404,
            title="Request not found",
            message="This request doesn’t exist or has expired. Requests from people "
            "expire after 14 days.",
            actions=[{"label": "All requests", "href": "/requests", "primary": True}],
        )

    async def send(request: Request, form: dict[str, str]) -> Response:
        kind = form.get("kind") or DESCRIBE
        try:
            await _run(
                service.send,
                _me(request),
                form.get("owner") or "",
                kind,
                text=form.get("text"),
                item_id=form.get("item"),
            )
        except InvalidInputError:
            kit.flash(
                request,
                "error",
                f"Write what you are asking for, in up to {MAX_TEXT} characters.",
            )
            return RedirectResponse(SENT, status_code=303)
        kit.flash(request, "ok", SENT_MESSAGE)
        return RedirectResponse(SENT, status_code=303)

    async def detail(request: Request) -> Response:
        me = _me(request)
        req = await _run(service.get, me, request.path_params["rid"])
        if req is None:
            return missing(request)
        return kit.render(
            request,
            "peer_request.html",
            req=req,
            kinds={"describe": DESCRIBE, "edit": EDIT, "more_time": MORE_TIME},
            **await _run(service.details, me, req),
        )

    async def approve(request: Request, form: dict[str, str]) -> Response:
        me, rid = _me(request), request.path_params["rid"]
        req = await _run(service.get, me, rid)
        if req is None:
            return missing(request)
        back = f"/requests/peer/{quote(req.id)}"
        try:
            expires_at = kit.end_of_day(form.get("expires_on") or "")
        except ValueError:
            kit.flash(request, "error", "Pick a valid end date, or leave it empty.")
            return RedirectResponse(back, status_code=303)
        try:
            req, entry = await _run(
                service.approve,
                me,
                rid,
                kit.ext_grants(),
                expect=form.get("requester"),
                target_id=form.get("target_id") or None,
                expires_at=expires_at,
            )
        except GrantError as exc:
            kit.flash(request, "error", str(exc))
            return RedirectResponse(back, status_code=303)
        if req.kind == EDIT:
            done = f"Approved: “{entry.name}” can now be edited."
        elif req.kind == MORE_TIME:
            until = f" until {entry.expires_at[:10]}" if entry.expires_at else ""
            done = f"Approved: “{entry.name}” stays shared{until}."
        else:
            done = f"Approved: shared “{entry.name}” with {req.requester}."
        kit.flash(request, "ok", done)
        return RedirectResponse(back, status_code=303)

    async def deny(request: Request, form: dict[str, str]) -> Response:
        me, rid = _me(request), request.path_params["rid"]
        if await _run(service.get, me, rid) is None:
            return missing(request)
        try:
            await _run(service.deny, me, rid, expect=form.get("requester"))
            kit.flash(request, "ok", "Request declined.")
        except GrantError as exc:
            kit.flash(request, "error", str(exc))
        return RedirectResponse(f"/requests/peer/{quote(rid)}", status_code=303)

    return [
        Route("/shared/request", kit.csrf_protected(send), methods=["POST"]),
        Route("/requests/peer/{rid}", kit.owner_only(detail), methods=["GET"]),
        Route("/requests/peer/{rid}/approve", kit.csrf_protected(approve), methods=["POST"]),
        Route("/requests/peer/{rid}/deny", kit.csrf_protected(deny), methods=["POST"]),
    ]

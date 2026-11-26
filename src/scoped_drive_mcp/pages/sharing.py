"""Sharing pages: what this person shares with paired people (Shared by me), and the
forms that add, narrow and remove those shares.
"""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from starlette.requests import Request
from starlette.responses import Response

from ..errors import report_exception
from ..grants import KEEP, GrantError
from ..scope import validate_drive_id
from ..store import ACCESS_EDIT, ACCESS_READ, AUDIENCE_LINKED
from .common import COVER_CHECK_LIMIT, _end_of_day, describe_mime
from .kit import FormHandler, Handler, Kit


@dataclass(frozen=True)
class SharingPages:
    """What dashboard.py needs from this module: the handlers it routes to, and
    the helpers other page modules call."""

    share_add: FormHandler
    share_remove: FormHandler
    share_audience: FormHandler
    first_reads_clear: FormHandler
    sharing: Handler


def sharing_pages(
    kit: Kit,
    *,
    still_covered: Callable[..., Awaitable[str | None]],
) -> SharingPages:
    ctx = kit.ctx
    render = kit.render
    action_done = kit.action_done
    blocking = kit.blocking
    safe_next = kit.safe_next

    def share_covers(entries: dict[str, Any]) -> dict[str, Any]:
        """For items narrowed to some people or a date: the shared folder above that still
        includes them. A folder on the list covers what is inside it, so narrowing an item
        inside a more widely shared folder does not hide it; the page says so."""
        covers: dict[str, Any] = {}
        grants = ctx.ext_grants()
        # Newest first, the order the page shows, so the rows on top are the ones checked.
        narrowed = sorted(
            (e for e in entries.values() if not e.for_everyone or e.expires_at),
            key=lambda e: e.granted_at,
            reverse=True,
        )
        # Bounded, like the Access page: each check walks Drive parents.
        for entry in narrowed[:COVER_CHECK_LIMIT]:
            try:
                found = grants.covering_entry(entry.id)
            except Exception as exc:
                # Drive is not answering; one failure is enough to stop asking.
                report_exception(exc, where="share_covers")
                break
            if found and found[0] in entries:
                covers[entry.id] = entries[found[0]]
        return covers

    async def share_add(request: Request, form: dict[str, str]) -> Response:
        file_id = validate_drive_id(form.get("file_id"))
        next_url = safe_next(form.get("next") or "/sharing")
        try:
            entry = await blocking(ctx.ext_grants().grant, file_id)
        except GrantError as exc:
            return action_done(request, "error", str(exc), next_url)
        return action_done(
            request,
            "ok",
            f"Shared \u201c{entry.name}\u201d with the assistants of people you are paired with.",
            next_url,
        )

    async def first_reads_clear(request: Request, form: dict[str, str]) -> Response:
        if ctx.first_reads is not None:
            await blocking(ctx.first_reads.clear)
        return action_done(request, "ok", "Cleared. Activity still lists every read.", "/")

    async def share_audience(request: Request, form: dict[str, str]) -> Response:
        """Who may read one item on the Sharing list, and until when."""
        file_id = validate_drive_id(form.get("file_id"))
        next_url = safe_next(form.get("next") or "/sharing?tab=by-me")
        email = str(request.session.get("owner") or "")
        chosen = [str(v) for v in (await request.form()).getlist("person")]
        try:
            expires_at = _end_of_day(form.get("expires_on") or "")
        except ValueError:
            return action_done(
                request, "error", "Pick a valid end date, or leave it empty.", next_url
            )
        peers = await blocking(ctx.mailbox.active_peers, email) if ctx.mailbox else []
        if form.get("who") == "people":
            # Only people you are paired with now can be named.
            people = tuple(p for p in peers if p in {c.strip().lower() for c in chosen})
            audience: str | tuple[str, ...] = people
        else:
            audience = AUDIENCE_LINKED
        # The form always sends `access_shown`; without it (an old page, a script) the
        # current setting is kept rather than silently turned off.
        if form.get("access_shown"):
            access: Any = ACCESS_EDIT if form.get("access") == ACCESS_EDIT else ACCESS_READ
        else:
            access = KEEP
        try:
            entry = await blocking(
                ctx.ext_grants().set_audience, file_id, audience, expires_at, access
            )
        except GrantError as exc:
            return action_done(request, "error", str(exc), next_url)
        who = (
            "everyone you are paired with" if entry.for_everyone else ", ".join(entry.audience)  # type: ignore[arg-type]
        )
        until = f" until {entry.expires_at[:10]}" if entry.expires_at else ""
        can = " Their assistants can add and edit inside it." if entry.access == ACCESS_EDIT else ""
        message = f"“{entry.name}” is now shared with {who}{until}.{can}"
        cover = await still_covered(ctx.ext_grants(), file_id)
        if cover:
            message += (
                f" It is inside “{cover}”, which is also on your Sharing list, so whoever can "
                "see that folder can still read it."
            )
        return action_done(request, "ok", message, next_url)

    async def share_remove(request: Request, form: dict[str, str]) -> Response:
        file_id = validate_drive_id(form.get("file_id"))
        next_url = safe_next(form.get("next") or "/sharing")
        ext_grants = ctx.ext_grants()
        try:
            await blocking(ext_grants.revoke, file_id)
        except GrantError as exc:
            ext = ctx.ext_allowlist
            gone = ext is not None and await blocking(lambda: ext.get(file_id) is None)
            return action_done(
                request,
                "error",
                str(exc).replace("allowlist", "shared list"),
                next_url,
                changed=gone,
            )
        cover = await still_covered(ext_grants, file_id)
        if cover is None:
            message = "Stopped sharing. Other people's assistants can no longer read it."
        elif cover:
            message = (
                "Stopped sharing it on its own, but other people's assistants can still "
                f"read it because “{cover}” is on your Sharing list."
            )
        else:
            message = (
                "Stopped sharing it on its own. If a folder above it is on your Sharing "
                "list, other people's assistants can still read it through that folder."
            )
        return action_done(request, "ok", message, next_url)

    async def sharing(request: Request) -> Response:
        if ctx.ext_allowlist is None:
            return render(request, "error.html", 404, message="Sharing is not set up.")
        email = str(request.session.get("owner") or "")

        def gather() -> dict[str, Any]:
            peers = ctx.mailbox.active_peers(email) if ctx.mailbox is not None else []
            entries = ctx.ext_allowlist.entries()
            connected = ctx.drive_connected()
            return {
                "entries": entries,
                "covers": share_covers(entries) if connected else {},
                "peers": peers,
                "drive_connected": connected,
            }

        data = await blocking(gather)
        rows = sorted(data["entries"].values(), key=lambda e: e.granted_at, reverse=True)
        return render(
            request,
            "sharing.html",
            rows=rows,
            covers=data["covers"],
            peers=data["peers"],
            describe_mime=describe_mime,
            drive_connected=data["drive_connected"],
        )

    return SharingPages(
        share_add=share_add,
        share_remove=share_remove,
        share_audience=share_audience,
        first_reads_clear=first_reads_clear,
        sharing=sharing,
    )

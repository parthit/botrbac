"""Requests and Activity pages: the access requests assistants made, approving or
denying one, and the activity log.
"""

import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from ..access import (
    APPROVED,
    OWNER_INDEX,
    OWNER_INDEX_SINCE,
    PENDING,
    REQUEST_TTL,
    SOURCE_ONEDRIVE,
    AccessRequests,
    validate_request_id,
)
from ..audit import app_tag, audit_owner
from ..auth import current_actor
from ..drive_client import DriveNotFoundError
from ..errors import report_exception
from ..grants import GrantError
from ..humanize import (
    ACTIVITY_FILTERS,
    app_names,
    describe,
    group_repeats,
    item_ids,
    matches,
)
from ..onedrive_client import OneDriveApiError, normalize_item_id
from ..policy import PayloadToolError
from ..ratelimit import allow
from ..scope import InvalidInputError, validate_drive_id
from ..store import EXTERNAL_ALLOWLIST_KEY, Allowlist
from .common import ACTIVITY_LOOKUPS, ACTIVITY_PAGE, OwnerNotConnectedError, describe_mime
from .kit import FormHandler, Handler, Kit

# A connection tag on an Activity row (audit.app_tag).
_APP_TAG = re.compile(r"[0-9a-f]{12}")


@dataclass(frozen=True)
class RequestPages:
    """What dashboard.py needs from this module: the handlers it routes to, and
    the helpers other page modules call."""

    requests_page: Handler
    request_detail: Handler
    request_approve: FormHandler
    request_deny: FormHandler
    activity: Handler


def request_pages(kit: Kit) -> RequestPages:
    ctx = kit.ctx
    settings = kit.settings
    peer_requests = kit.peer_requests
    logger = kit.logger
    render = kit.render
    flash = kit.flash
    blocking = kit.blocking

    def my_app_names() -> dict[str, str]:
        if ctx.mcp_oauth is None:
            return {}
        return app_names(ctx.mcp_oauth.list_grants(current_actor.get()))

    async def requests_page(request: Request) -> Response:
        reqs = await blocking(ctx.requests.recent, 100)
        pending = [r for r in reqs if r.status == PENDING]
        decided = [r for r in reqs if r.status != PENDING]
        apps = await blocking(my_app_names)
        peer_pending, peer_decided = [], []
        if peer_requests is not None:
            peer_pending, peer_decided = await blocking(
                peer_requests.inbox, str(current_actor.get() or "")
            )
        return render(
            request,
            "requests.html",
            pending=pending,
            decided=decided,
            apps=apps,
            peer_on=peer_requests is not None,
            peer_pending=peer_pending,
            peer_decided=peer_decided,
        )

    def request_elsewhere(rid: str, email: str | None) -> bool:
        """Whether this request id belongs to another signed-in person. Ids are 192 random
        bits, so this only ever matches a link someone was sent. It says nothing about whose
        request it is."""
        if ctx.directory is None:
            return False
        try:
            validate_request_id(rid)
        except InvalidInputError:
            return False
        owner = ctx.store.get(f"{OWNER_INDEX}{rid}")
        if owner:
            return owner != email
        # Requests filed before the index existed are not in it. They expire REQUEST_TTL
        # after they were filed, so the look through every account is only needed that long.
        now = time.time()
        # Ten years: the mark only has to outlive the window it starts.
        ctx.store.set_if_absent(OWNER_INDEX_SINCE, f"{now:.0f}", ex=10 * 365 * 24 * 3600)
        since = ctx.store.get(OWNER_INDEX_SINCE) or f"{now:.0f}"
        try:
            if now - float(since) >= REQUEST_TTL:
                return False
        except ValueError:
            return False
        # While the look-through is still needed, one person may cause it a few times an
        # hour. Past that an unknown link is simply not found.
        if not allow(ctx.store, "request-lookup", email or "anon", 20, 3600):
            return False
        for person in ctx.directory.known_users():
            if person == email:
                continue
            if AccessRequests(ctx.directory.store_for(person)).get(rid) is not None:
                return True
        return False

    async def missing_request(request: Request, rid: str) -> Response:
        email = current_actor.get()
        if await blocking(request_elsewhere, rid, email):
            return render(
                request,
                "error.html",
                403,
                title="This request is for a different account",
                message=(
                    f"This request isn\u2019t for {email}. Sign in with the Google account "
                    "that owns this assistant to approve or deny it."
                ),
                actions=[
                    {
                        "label": "Switch account",
                        "logout_next": f"/requests/{rid}",
                        "primary": True,
                    },
                    {"label": "All requests", "href": "/requests"},
                ],
            )
        return render(
            request,
            "error.html",
            404,
            title="Request not found",
            message=(
                "This request doesn\u2019t exist or has expired. Requests expire after 7 days."
            ),
            actions=[
                {"label": "All requests", "href": "/requests", "primary": True},
                {"label": "Back to Overview", "href": "/"},
            ],
        )

    def paired_sharer(file_id: str) -> str | None:
        """A paired person whose Sharing list covers this id (a request filed before
        read_file pointed assistants at read_shared_file). Uses the same guard as a guest
        read, so a file inside a shared folder counts, not only the exact shared id."""
        me = current_actor.get()
        if ctx.sharer_of is not None:
            return ctx.sharer_of(me, file_id) if me else None
        if ctx.mailbox is None or ctx.ext_allowlist is None or ctx.directory is None:
            return None
        for peer in ctx.mailbox.active_peers(me):
            store = ctx.directory.store_for(peer)
            entry = Allowlist(store, EXTERNAL_ALLOWLIST_KEY).get(file_id)
            if entry is not None and entry.readable_by(me):
                return peer
        return None

    def onedrive_options(req: Any) -> tuple[list[dict[str, str]], bool, bool]:
        """(options, connected, error) for a pending OneDrive request with an item id."""
        if ctx.onedrive is None or ctx.onedrive_record() is None:
            return [], False, False
        try:
            return ctx.onedrive.approval_options(req.file_id), True, False
        except (PayloadToolError, OneDriveApiError):
            return [], True, True

    async def onedrive_detail(request: Request, req: Any) -> Response:
        options: list[dict[str, str]] = []
        connected = ctx.onedrive is not None and await blocking(ctx.onedrive_record) is not None
        error = False
        if req.file_id and req.status == PENDING:
            options, connected, error = await blocking(onedrive_options, req)
        # Shown only. A page view never writes the request: a save after the OneDrive call
        # above could put back "pending" over an approval made meanwhile in another tab.
        meta = {"name": options[0]["name"]} if options else None
        return render(
            request,
            "request.html",
            req=req,
            options=options,
            owner_meta=meta,
            onedrive_connected=connected,
            onedrive_error=error,
            apps=await blocking(my_app_names),
            describe_mime=describe_mime,
        )

    def approve_onedrive(req: Any, target: str) -> str:
        """Allow `target` for a OneDrive request. Returns the message to show."""
        if ctx.onedrive is None:
            raise GrantError("OneDrive is not set up on this server.")
        if req.status != PENDING:
            raise GrantError(f"This request was already {req.status}.")
        clean = normalize_item_id(target)
        if clean is None:
            raise GrantError("Pick the requested item or its folder.")
        if req.file_id:
            # Only the item the assistant named, or its folder, may answer its request.
            options = ctx.onedrive.approval_options(req.file_id)
            if clean not in {o["id"] for o in options}:
                raise GrantError("Pick the requested item or its folder.")
            # Filed without asking OneDrive, so the request has no name yet; decide() saves it.
            req.file_name = options[0]["name"]
        # Already allowed, or inside an allowed folder: approve with it as it is. allow()
        # would rewrite an existing entry, or add a second one under its folder.
        covered = ctx.onedrive.covered_item(clean)
        if covered is not None:
            granted_id, granted_name = covered["id"], covered["name"]
            done = f"Approved: “{granted_name}” is already allowed for your assistants."
        else:
            entry = ctx.onedrive.allow(clean)
            if entry is None:
                raise GrantError(
                    "That item can’t be allowed. It may have been deleted, be the top of your "
                    "OneDrive, or be a shortcut to someone else’s file."
                )
            granted_id, granted_name = entry.id, entry.name
            done = f"Approved: allowed “{granted_name}” in your OneDrive for your assistants."
        ctx.requests.decide(req, APPROVED, granted_id=granted_id, granted_name=granted_name)
        ctx.requests.clear_denials(granted_id, SOURCE_ONEDRIVE)
        audit_owner("approve_request", request_id=req.id, file_id=granted_id, connection="onedrive")
        return done

    async def request_detail(request: Request) -> Response:
        rid = request.path_params["rid"]
        req = await blocking(ctx.requests.get, rid)
        if req is None:
            return await missing_request(request, rid)
        if req.is_onedrive:
            return await onedrive_detail(request, req)
        options = []
        owner_meta = None
        drive_error = False
        shared_by = None
        if req.file_id and req.status == PENDING:
            grants = ctx.grants()
            try:
                options = await blocking(grants.approval_options, req)
                owner_meta = await blocking(grants.owner_meta, req.file_id)
            except (InvalidInputError, OwnerNotConnectedError):
                raise
            except Exception as exc:
                report_exception(exc, where="request")
                options = []
                owner_meta = None
                drive_error = True
            if owner_meta is None and not drive_error:
                shared_by = await blocking(paired_sharer, req.file_id)
        return render(
            request,
            "request.html",
            req=req,
            options=options,
            owner_meta=owner_meta,
            drive_error=drive_error,
            shared_by=shared_by,
            apps=await blocking(my_app_names),
            picker_ready=settings.picker_configured,
            describe_mime=describe_mime,
        )

    async def request_approve(request: Request, form: dict[str, str]) -> Response:
        rid = request.path_params["rid"]
        req = await blocking(ctx.requests.get, rid)
        if req is None:
            return await missing_request(request, rid)
        target = form.get("target_id") or req.file_id
        if req.is_onedrive:
            if not target:
                flash(request, "error", "Pick an item to allow first.")
                return RedirectResponse(
                    f"/files?tab=onedrive&request={quote(req.id)}", status_code=303
                )
            try:
                flash(request, "ok", await blocking(approve_onedrive, req, target))
            except GrantError as exc:
                flash(request, "error", str(exc))
            except (PayloadToolError, OneDriveApiError):
                flash(request, "error", "OneDrive didn’t answer. Try again in a minute.")
            return RedirectResponse(f"/requests/{quote(req.id)}", status_code=303)
        if not target:
            flash(request, "error", "Pick an item to share first.")
            return RedirectResponse(f"/files?request={quote(req.id)}", status_code=303)
        try:
            entry = await blocking(ctx.grants().approve, req, validate_drive_id(target))
            flash(request, "ok", f"Approved: shared \u201c{entry.name}\u201d with the assistant.")
        except GrantError as exc:
            flash(request, "error", str(exc))
        return RedirectResponse(f"/requests/{quote(req.id)}", status_code=303)

    async def request_deny(request: Request, form: dict[str, str]) -> Response:
        rid = request.path_params["rid"]
        req = await blocking(ctx.requests.get, rid)
        if req is None:
            return await missing_request(request, rid)
        try:
            await blocking(ctx.grants().deny, req)
            flash(request, "ok", "Request denied.")
        except GrantError as exc:
            flash(request, "error", str(exc))
        return RedirectResponse(f"/requests/{quote(req.id)}", status_code=303)

    def activity_names(records: list[dict[str, Any]]) -> dict[str, Any]:
        """Names for the ids on this page, from what this person already has: their two
        lists, their requests, and (for a few ids) their own Drive. The log keeps ids only."""
        names: dict[str, str] = {}
        for entry in ctx.allowlist.entries().values():
            if entry.name:
                names[entry.id] = entry.name
        if ctx.ext_allowlist is not None:
            for entry in ctx.ext_allowlist.entries().values():
                if entry.name:
                    names.setdefault(entry.id, entry.name)
        if ctx.onedrive is not None:
            for entry in ctx.onedrive.allowlist.entries().values():
                if entry.name:
                    names.setdefault(entry.id, entry.name)
        request_names: dict[str, str] = {}
        for req in ctx.requests.recent(300):
            if req.file_id and req.file_name:
                names.setdefault(req.file_id, req.file_name)
            if req.granted_id and req.granted_name:
                names.setdefault(req.granted_id, req.granted_name)
            label = req.granted_name or req.file_name or req.description
            if label:
                request_names[req.id] = str(label)
        unknown = [i for i in item_ids(records) if i not in names][:ACTIVITY_LOOKUPS]
        if unknown and ctx.drive_connected():
            try:
                drive = ctx.owner_drive()
                for item in unknown:
                    try:
                        meta = drive.get_file(item, fields="id,name")
                    except DriveNotFoundError:
                        # Under drive.file Google also answers 404 for real files this
                        # app never opened, so a 404 proves nothing: not called missing.
                        continue
                    if meta.get("name"):
                        names[item] = str(meta["name"])
            except Exception:
                logger.warning("activity name lookup failed", exc_info=True)
        return {"names": names, "request_names": request_names, "apps": my_app_names()}

    async def activity(request: Request) -> Response:
        view = request.query_params.get("view") or "all"
        if view not in ACTIVITY_FILTERS:
            view = "all"
        show_checks = request.query_params.get("checks") == "1"
        try:
            limit = int(request.query_params.get("show") or ACTIVITY_PAGE)
        except ValueError:
            limit = ACTIVITY_PAGE
        limit = max(ACTIVITY_PAGE, min(limit, 500))
        records = await blocking(ctx.activity.recent)
        # One connected app's rows only (?app= is the tag Activity rows carry). The choices
        # come from the rows themselves, so an app that was disconnected can still be shown;
        # connected ones are named, others called what they were (their token name).
        grants = (
            await blocking(ctx.mcp_oauth.list_grants, current_actor.get())
            if ctx.mcp_oauth is not None
            else []
        )
        named = {app_tag(g.id): f"{g.client_name} (…{g.id[-5:]})" for g in grants}
        app_choices: dict[str, str] = {}
        for r in records:
            tag = r.get("app")
            if isinstance(tag, str) and _APP_TAG.fullmatch(tag) and tag not in app_choices:
                old = str(r.get("token_name") or "").removeprefix("oauth:") or "An app"
                app_choices[tag] = named.get(tag) or f"{old} (disconnected)"
        app = request.query_params.get("app") or ""
        if app not in app_choices:
            app = ""
        if app:
            records = [r for r in records if r.get("app") == app]
        rows = [describe(r) for r in records]
        shown_ids = [i for i, row in enumerate(rows) if matches(row, view, show_checks)]
        page = shown_ids[:limit]
        lookup = await blocking(activity_names, [records[i] for i in page])
        page_rows = [
            describe(records[i], lookup["names"], lookup["request_names"], lookup["apps"])
            for i in page
        ]
        counts = {k: sum(1 for r in rows if matches(r, k, show_checks)) for k in ACTIVITY_FILTERS}

        def href(**changes: Any) -> str:
            params = {"view": view, "app": app, "checks": "1" if show_checks else "", "show": ""}
            params.update({k: str(v) for k, v in changes.items()})
            pairs = [(k, v) for k, v in params.items() if v and not (k == "view" and v == "all")]
            return "/activity" + (f"?{urlencode(pairs)}" if pairs else "")

        return render(
            request,
            "activity.html",
            rows=group_repeats(page_rows),
            total=len(records),
            more_href=href(show=limit + ACTIVITY_PAGE) if len(shown_ids) > limit else None,
            view=view,
            filters=[(k, label, href(view=k), counts[k]) for k, label in ACTIVITY_FILTERS.items()],
            show_checks=show_checks,
            hidden_checks=sum(1 for r in rows if r.polling),
            checks_href=href(checks="" if show_checks else "1"),
            app=app,
            apps=[(tag, name, href(app=tag)) for tag, name in app_choices.items()],
            all_apps_href=href(app=""),
        )

    return RequestPages(
        requests_page=requests_page,
        request_detail=request_detail,
        request_approve=request_approve,
        request_deny=request_deny,
        activity=activity,
    )

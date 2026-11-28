"""Connections pages (step 2): /connect and connect/disconnect for each service, plus
the Notion and OneDrive OAuth callbacks and their allow/remove lists.
"""

import hmac
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

from itsdangerous import BadSignature
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from ..access import PENDING, SOURCE_ONEDRIVE
from ..audit import audit_owner
from ..auth import current_actor
from ..connections import get_connection
from ..mcp_oauth import AuthorizeError, QueryMapping
from ..notion_client import NotionApiError, NotionOAuthError
from ..onedrive import can_write as onedrive_can_write
from ..onedrive_client import READ_SCOPES as ONEDRIVE_READ_SCOPES
from ..onedrive_client import SCOPES as ONEDRIVE_SCOPES
from ..onedrive_client import WRITE_SCOPE as ONEDRIVE_WRITE_SCOPE
from ..onedrive_client import OneDriveApiError, OneDriveOAuthError
from ..onedrive_client import normalize_item_id as normalize_onedrive_id
from ..onedrive_client import normalize_scopes as normalize_onedrive_scopes
from ..onedrive_client import scopes_acceptable as onedrive_scopes_acceptable
from ..onedrive_client import scopes_can_write as onedrive_scopes_can_write
from ..policy import PayloadToolError
from .common import STATE_MAX_AGE
from .kit import FormHandler, Handler, Kit


@dataclass(frozen=True)
class ConnectionPages:
    """What dashboard.py needs from this module: the handlers it routes to, and
    the helpers other page modules call."""

    connect_page: Handler
    connect_start: FormHandler
    connect_remove: FormHandler
    notion_callback: Handler
    notion_files: Handler
    notion_allow: FormHandler
    notion_remove: FormHandler
    onedrive_callback: Handler
    onedrive_files: Handler
    onedrive_allow: FormHandler
    onedrive_remove: FormHandler
    drive_row_connected: Callable[[list[dict[str, Any]]], bool]


# Remove on the Allowed tab returns there; nothing else is accepted as a destination.
ALLOWED_TAB = "/files?tab=allowed"


def connection_pages(
    kit: Kit,
    *,
    start_oauth: Callable[..., RedirectResponse],
    login_rate_limited: Callable[[Request], Awaitable[Response | None]],
) -> ConnectionPages:
    ctx = kit.ctx
    oauth = kit.oauth
    serializer = kit.serializer
    refused = kit.refused
    render = kit.render
    flash = kit.flash
    action_done = kit.action_done
    blocking = kit.blocking
    safe_next = kit.safe_next

    # ---- connections (step 2) -------------------------------------------

    def waiting_client(next_url: str) -> str | None:
        """The app whose connection sent this person here (/oauth/authorize?...), if any."""
        if ctx.mcp_oauth is None or not next_url.startswith("/oauth/authorize?"):
            return None
        params = dict(parse_qsl(urlsplit(next_url).query, keep_blank_values=True))
        try:
            return ctx.mcp_oauth.parse_authorize(QueryMapping(params)).client_name
        except AuthorizeError:
            return None

    def drive_row_connected(rows: list[dict[str, Any]]) -> bool:
        return any(r["connected"] for r in rows if r["connection"].provider == "google")

    async def connect_page(request: Request) -> Response:
        rows = await blocking(ctx.connection_rows)
        next_url = safe_next(request.query_params.get("next"))
        if next_url.startswith("/connect"):
            next_url = "/"
        client_name = await blocking(waiting_client, next_url)
        if drive_row_connected(rows) and next_url == "/" and not client_name:
            # Set up already: the services list lives in Settings now.
            return RedirectResponse("/settings#services", status_code=303)
        return render(
            request,
            "connect.html",
            rows=rows,
            next=next_url,
            waiting_client=client_name,
            drive_connected=drive_row_connected(rows),
        )

    async def connect_start(request: Request, form: dict[str, str]) -> Response:
        connection = get_connection(request.path_params.get("key"))
        if connection is None:
            return render(request, "error.html", 404, message="Unknown connection.")
        if connection.provider == "notion" and ctx.notion is None:
            return render(request, "error.html", 404, message="Unknown connection.")
        if connection.provider == "microsoft" and ctx.onedrive is None:
            return render(request, "error.html", 404, message="Unknown connection.")
        limited = await login_rate_limited(request)
        if limited is not None:
            return limited
        request.session["oauth_next"] = safe_next(form.get("next"))
        if connection.provider == "notion":
            return start_notion(request)
        if connection.provider == "microsoft":
            return start_onedrive(request, read_only=form.get("access") == "read")
        if connection.key == "google_drive":
            # An old full-Drive token is revoked before Google's consent screen. Revoking
            # ends this app's whole grant for the account, so doing it after the new
            # consent would also kill the new per-file token.
            revoked = await blocking(ctx.revoke_legacy_drive, oauth.revoke)
            if revoked is False:
                audit_owner("revoke_legacy_drive", "deny", reason="google_unreachable")
                return render(
                    request,
                    "error.html",
                    503,
                    title="Couldn’t end your old connection",
                    message=(
                        "Google didn’t confirm that your old Drive connection was ended, so "
                        "nothing was changed. Try Reconnect again in a minute."
                    ),
                )
            if revoked:
                ctx.forget_drive(current_actor.get() or None)
                audit_owner("revoke_legacy_drive")
        return start_oauth(request, "connect", current_actor.get() or None, connection)

    async def connect_remove(request: Request, form: dict[str, str]) -> Response:
        connection = get_connection(request.path_params.get("key"))
        if connection is None:
            return render(request, "error.html", 404, message="Unknown connection.")
        if connection.provider == "notion":
            if ctx.notion is None:
                return render(request, "error.html", 404, message="Unknown connection.")
            return await notion_disconnect(request)
        if connection.provider == "microsoft":
            if ctx.onedrive is None:
                return render(request, "error.html", 404, message="Unknown connection.")
            return await onedrive_disconnect(request)
        email = current_actor.get()
        # An old full-Drive token is kept until Google confirms it is revoked, so a failed
        # revoke can be retried. It is never used meanwhile.
        legacy = await blocking(ctx.revoke_legacy_drive, oauth.revoke)
        if legacy is False:
            ctx.forget_drive(email)
            flash(
                request,
                "error",
                "Google didn\u2019t confirm that your old Drive connection was ended, so it "
                "is kept (and still unused). Choose Disconnect again in a minute.",
            )
            return RedirectResponse("/settings#services", status_code=303)
        # A current per-file token is removed here at once, as asked, then revoked.
        token = await blocking(ctx.disconnect_drive)
        confirmed = True
        if token:
            # Google's revoke also ends this app's sign-in grant. Step 1 holds no token,
            # so the dashboard session is unaffected.
            confirmed = await blocking(oauth.revoke, token)
        ctx.forget_drive(email)
        audit_owner("disconnect", connection=connection.key)
        if confirmed:
            flash(
                request,
                "ok",
                f"{connection.name} is disconnected. Assistants can no longer reach it.",
            )
        else:
            flash(
                request,
                "error",
                f"{connection.name} is disconnected here, but Google didn\u2019t confirm it "
                "ended the permission. Remove Bot RBAC at myaccount.google.com/permissions "
                "to be sure.",
            )
        return RedirectResponse("/connect", status_code=303)

    # ---- Notion (a second connection, its own OAuth) ---------------------------

    def start_notion(request: Request) -> Response:
        """Send the signed-in person to Notion's consent screen. The state is signed,
        expires, is tied to this browser (nonce) and names the account it is for."""
        nonce = secrets.token_urlsafe(24)
        request.session["notion_nonce"] = nonce
        state = serializer.dumps(
            {"flow": "notion", "nonce": nonce, "who": current_actor.get() or ""}
        )
        url = ctx.notion.oauth.authorization_url(state)
        return RedirectResponse(url, status_code=303)

    async def notion_callback(request: Request) -> Response:
        if ctx.notion is None:
            return render(request, "error.html", 404, message="Unknown connection.")
        params = request.query_params
        nonce = request.session.pop("notion_nonce", None)
        request.session.pop("oauth_next", None)
        retry_actions = [
            {"label": "Back to Settings", "href": "/settings#services", "primary": True},
        ]
        if params.get("error"):
            cancelled = params.get("error") == "access_denied"
            return render(
                request,
                "error.html",
                400,
                title="You didn’t connect Notion" if cancelled else "Notion isn’t connected",
                message=(
                    "You cancelled on Notion’s screen, so nothing changed."
                    if cancelled
                    else "Notion didn’t finish connecting. Nothing changed."
                ),
                actions=retry_actions,
            )
        try:
            data = serializer.loads(params.get("state", ""), max_age=STATE_MAX_AGE)
        except BadSignature:
            data = None
        email = current_actor.get() or ""
        if (
            not isinstance(data, dict)
            or data.get("flow") != "notion"
            or not nonce
            or not hmac.compare_digest(str(nonce), str(data.get("nonce", "")))
            or str(data.get("who") or "") != email
        ):
            audit_owner("notion_connect", "deny", reason="bad_state")
            return render(
                request,
                "error.html",
                400,
                title="Notion connection expired",
                message="That Notion connection didn’t start here, or took too long. Try again.",
                actions=retry_actions,
            )
        code = params.get("code")
        if not code:
            return render(request, "error.html", 400, message="Notion did not return a code.")
        try:
            tokens = await blocking(ctx.notion.oauth.exchange_code, code)
        except NotionOAuthError as exc:
            return render(
                request,
                "error.html",
                502,
                title="Notion isn’t connected",
                message=f"Connecting Notion failed: {exc}.",
                actions=retry_actions,
            )
        previous = await blocking(ctx.notion_record)
        if previous and previous.get("workspace_id") != tokens.workspace_id:
            # Another workspace: the old list names pages that are not there.
            await blocking(ctx.notion.clear)
        await blocking(
            ctx.vault.set_notion,
            tokens.access_token,
            tokens.refresh_token,
            email,
            tokens.workspace_id,
            tokens.workspace_name,
        )
        audit_owner("notion_connect", connection="notion")
        flash(
            request,
            "ok",
            "Notion is connected. Now allow the pages your assistants may read.",
        )
        return RedirectResponse("/files?tab=notion", status_code=303)

    async def notion_disconnect(request: Request) -> Response:
        record = await blocking(ctx.notion_record)
        await blocking(ctx.vault.clear_notion)
        # The list belongs to that connection's workspace; a later connection starts empty.
        await blocking(ctx.notion.clear)
        confirmed = True
        # Notion revokes one token per call: the access token, then the refresh token.
        for key in ("t", "r"):
            if record and record.get(key):
                confirmed = await blocking(ctx.notion.oauth.revoke, record[key]) and confirmed
        audit_owner("notion_disconnect", connection="notion")
        if confirmed:
            flash(request, "ok", "Notion is disconnected. Assistants can no longer reach it.")
        else:
            flash(
                request,
                "error",
                "Notion is disconnected here, but Notion didn’t confirm it ended the "
                "connection. In Notion, open Settings → Connections and remove Bot RBAC "
                "to be sure.",
            )
        return RedirectResponse("/settings#services", status_code=303)

    async def notion_files(request: Request) -> Response:
        """Files → From Notion: what assistants may read, and what Notion shows Bot RBAC."""
        query = (request.query_params.get("q") or "").strip()[:200]

        def gather() -> dict[str, Any]:
            record = ctx.notion_record()
            allowed = sorted(ctx.notion.allowlist.entries().values(), key=lambda e: e.name.lower())
            out: dict[str, Any] = {
                "notion_connected": record is not None,
                "workspace": (record or {}).get("workspace_name") or "",
                "allowed": allowed,
                "visible": [],
                "notion_error": None,
            }
            if record is None:
                return out
            try:
                out["visible"] = ctx.notion.visible(query)
            except PayloadToolError as exc:
                out["notion_error"] = str(exc.payload.get("message") or "Notion refused.")
            except NotionApiError:
                out["notion_error"] = "Notion didn’t answer. Reload the page in a minute."
            return out

        data = await blocking(gather)
        return render(
            request,
            "notion.html",
            query=query,
            next="/files?tab=notion",
            **data,
        )

    async def notion_allow(request: Request, form: dict[str, str]) -> Response:
        if ctx.notion is None:
            return refused(request, 404, "Notion is not set up on this server.")
        back = "/files?tab=notion"
        try:
            entry = await blocking(ctx.notion.allow, form.get("page_id", ""))
        except PayloadToolError as exc:
            return action_done(request, "error", str(exc.payload.get("message")), back)
        except NotionApiError:
            return action_done(request, "error", "Notion didn’t answer. Try again.", back)
        if entry is None:
            return action_done(
                request,
                "error",
                "Notion doesn’t show Bot RBAC that page. Choose Pick pages in Notion to add it "
                "there first.",
                back,
                changed=False,
            )
        audit_owner("notion_allow", page_id=entry.id, name=entry.name)
        return action_done(request, "ok", f"Allowed “{entry.name}” for your assistants.", back)

    async def notion_remove(request: Request, form: dict[str, str]) -> Response:
        if ctx.notion is None:
            return refused(request, 404, "Notion is not set up on this server.")
        entry = await blocking(ctx.notion.remove, form.get("page_id", ""))
        back = ALLOWED_TAB if form.get("next") == ALLOWED_TAB else "/files?tab=notion"
        if entry is None:
            return action_done(request, "ok", "That page was not allowed.", back, changed=False)
        audit_owner("notion_remove", page_id=entry.id, name=entry.name)
        return action_done(
            request, "ok", f"Removed “{entry.name}”. Assistants can no longer read it.", back
        )

    # ---- OneDrive (an optional connection, Microsoft's own OAuth) ----------------

    def start_onedrive(request: Request, *, read_only: bool = False) -> Response:
        """Send the signed-in person to Microsoft's sign-in and consent screen. The state
        is signed, expires, is tied to this browser (nonce), names the account, and carries
        whether they chose reading only (then only the read scopes are asked for)."""
        nonce = secrets.token_urlsafe(24)
        request.session["onedrive_nonce"] = nonce
        access = "read" if read_only else "edit"
        state = serializer.dumps(
            {"flow": "onedrive", "nonce": nonce, "who": current_actor.get() or "", "access": access}
        )
        scopes = ONEDRIVE_READ_SCOPES if read_only else ONEDRIVE_SCOPES
        return RedirectResponse(
            ctx.onedrive.oauth.authorization_url(state, scopes), status_code=303
        )

    async def onedrive_callback(request: Request) -> Response:
        if ctx.onedrive is None:
            return render(request, "error.html", 404, message="Unknown connection.")
        params = request.query_params
        nonce = request.session.pop("onedrive_nonce", None)
        request.session.pop("oauth_next", None)
        retry_actions = [
            {"label": "Back to Settings", "href": "/settings#services", "primary": True},
        ]
        error = params.get("error")
        if error:
            # error_description is Microsoft's text; only its AADSTS code is looked at.
            description = params.get("error_description") or ""
            needs_admin = error in ("consent_required", "admin_consent_required") or any(
                code in description for code in ("AADSTS65001", "AADSTS90094", "AADSTS90095")
            )
            if needs_admin:
                title = "Your organization has to approve Bot RBAC"
                message = (
                    "Your school or work account doesn’t let you connect apps like Bot RBAC "
                    "yourself. Ask your IT administrator to approve Bot RBAC for your "
                    "organization, then try again. Nothing changed. Some organizations let "
                    "you approve reading but not editing: you can try Connect for reading "
                    "only on Files → From OneDrive."
                )
                retry_actions = [
                    {
                        "label": "Connect for reading only",
                        "href": "/files?tab=onedrive#onedrive-connect",
                        "primary": True,
                    },
                    {"label": "Back to Settings", "href": "/settings#services"},
                ]
            elif error == "access_denied":
                title = "You didn’t connect OneDrive"
                message = "You cancelled on Microsoft’s screen, so nothing changed."
            else:
                title = "OneDrive isn’t connected"
                message = "Microsoft didn’t finish connecting. Nothing changed."
            return render(
                request, "error.html", 400, title=title, message=message, actions=retry_actions
            )
        try:
            data = serializer.loads(params.get("state", ""), max_age=STATE_MAX_AGE)
        except BadSignature:
            data = None
        email = current_actor.get() or ""
        if (
            not isinstance(data, dict)
            or data.get("flow") != "onedrive"
            or not nonce
            or not hmac.compare_digest(str(nonce), str(data.get("nonce", "")))
            or str(data.get("who") or "") != email
        ):
            audit_owner("onedrive_connect", "deny", reason="bad_state")
            return render(
                request,
                "error.html",
                400,
                title="OneDrive connection expired",
                message="That OneDrive connection didn’t start here, or took too long. Try again.",
                actions=retry_actions,
            )
        code = params.get("code")
        if not code:
            return render(request, "error.html", 400, message="Microsoft did not return a code.")
        read_only = data.get("access") == "read"
        try:
            tokens = await blocking(
                ctx.onedrive.oauth.exchange_code,
                code,
                ONEDRIVE_READ_SCOPES if read_only else ONEDRIVE_SCOPES,
            )
        except OneDriveOAuthError as exc:
            return render(
                request,
                "error.html",
                502,
                title="OneDrive isn’t connected",
                message=f"Connecting OneDrive failed: {exc}.",
                actions=retry_actions,
            )
        if not onedrive_scopes_acceptable(tokens.scopes):
            # Not stored. Microsoft has no per-token revoke for this kind of app; the token
            # expires within the hour and is never used.
            audit_owner("onedrive_connect", "deny", reason="scopes")
            return render(
                request,
                "error.html",
                400,
                title="OneDrive isn’t connected",
                message=(
                    "Microsoft gave Bot RBAC different access than it asks for (read and "
                    "edit your files), so the connection was not kept. Try again, and keep "
                    "the permission to your files ticked."
                ),
                actions=retry_actions,
            )
        try:
            account = await blocking(ctx.onedrive.account_for, tokens.access_token)
        except OneDriveApiError as exc:
            if exc.status in (400, 404):
                message = (
                    "This Microsoft account has no OneDrive yet. Open OneDrive once in a "
                    "browser, then try again."
                )
            elif exc.status in (401, 403):
                message = (
                    "Microsoft refused Bot RBAC access to this account’s OneDrive. A school "
                    "or work account may block it; ask its IT administrator."
                )
            else:
                message = "Microsoft didn’t answer. Try again in a minute."
            return render(
                request,
                "error.html",
                502,
                title="OneDrive isn’t connected",
                message=message,
                actions=retry_actions,
            )
        previous = await blocking(ctx.onedrive_record)
        if previous is None or previous.get("drive_id") != account.drive_id:
            # A list is kept only when the same drive reconnects. With no usable earlier
            # connection we can't tell which account the list was chosen for, so it goes.
            await blocking(ctx.onedrive.clear)
        granted = normalize_onedrive_scopes(tokens.scopes)
        if read_only:
            # Reading only was chosen: the connection never writes, even when Microsoft's
            # token lists Files.ReadWrite (approved once before). Refreshes keep it so.
            granted.discard(ONEDRIVE_WRITE_SCOPE)
        await blocking(
            ctx.vault.set_onedrive,
            tokens.access_token,
            tokens.refresh_token,
            email,
            tokens.expires_at,
            account.drive_id,
            account.name,
            account.drive_type,
            " ".join(sorted(granted)),
        )
        audit_owner("onedrive_connect", connection="onedrive")
        if onedrive_scopes_can_write(granted):
            done = "OneDrive is connected. Now allow the files and folders your assistants may use."
        elif read_only:
            done = (
                "OneDrive is connected for reading only. Now allow the files and folders "
                "your assistants may read."
            )
        else:
            done = (
                "OneDrive is connected for reading only: Microsoft didn’t grant editing. "
                "Now allow the files and folders your assistants may read."
            )
        flash(request, "ok", done)
        return RedirectResponse("/files?tab=onedrive", status_code=303)

    async def onedrive_disconnect(request: Request) -> Response:
        await blocking(ctx.vault.clear_onedrive)
        # The list belongs to that account's drive; a later connection starts empty.
        await blocking(ctx.onedrive.clear)
        audit_owner("onedrive_disconnect", connection="onedrive")
        flash(
            request,
            "ok",
            "OneDrive is disconnected. Assistants can no longer reach it. To remove Bot "
            "RBAC’s permission at Microsoft too, open account.live.com/consent/Manage "
            "(personal account) or myapps.microsoft.com (work or school account).",
        )
        return RedirectResponse("/settings#services", status_code=303)

    async def onedrive_files(request: Request) -> Response:
        """Files → From OneDrive: what assistants may read, and the person's drive."""
        query = (request.query_params.get("q") or "").strip()[:200]
        folder = (request.query_params.get("folder") or "").strip()[:256]
        rid = (request.query_params.get("request") or "").strip()[:64]

        def gather() -> dict[str, Any]:
            record = ctx.onedrive_record()
            # Picking the item for an assistant's request: Allow answers that request.
            picking = ctx.requests.get(rid) if rid else None
            if picking is not None and not (picking.is_onedrive and picking.status == PENDING):
                picking = None
            allowed = sorted(
                ctx.onedrive.allowlist.entries().values(), key=lambda e: e.name.lower()
            )
            out: dict[str, Any] = {
                "onedrive_connected": record is not None,
                "onedrive_can_write": onedrive_can_write(record),
                "account": (record or {}).get("account") or "",
                "allowed": allowed,
                "listing": {"folder": None, "up": None, "items": []},
                "onedrive_error": None,
                "picking": picking,
            }
            if record is None:
                return out
            try:
                out["listing"] = ctx.onedrive.browse(folder or None, query)
            except PayloadToolError as exc:
                out["onedrive_error"] = str(exc.payload.get("message") or "Microsoft refused.")
            except OneDriveApiError:
                out["onedrive_error"] = "OneDrive didn’t answer. Reload the page in a minute."
            return out

        data = await blocking(gather)
        here = "/files?" + urlencode(
            {
                "tab": "onedrive",
                **({"folder": folder} if folder else {}),
                **({"q": query} if query else {}),
                **({"request": data["picking"].id} if data["picking"] else {}),
            }
        )
        return render(request, "onedrive.html", query=query, next=here, **data)

    def onedrive_back(form: dict[str, str]) -> str:
        """Where an Allow or Remove returns to: the Allowed tab, or the same OneDrive folder."""
        if form.get("next") == ALLOWED_TAB:
            return ALLOWED_TAB
        folder = normalize_onedrive_id(form.get("folder") or "")
        return f"/files?tab=onedrive&folder={quote(folder)}" if folder else "/files?tab=onedrive"

    async def onedrive_allow(request: Request, form: dict[str, str]) -> Response:
        if ctx.onedrive is None:
            return refused(request, 404, "OneDrive is not set up on this server.")
        back = onedrive_back(form)
        try:
            entry = await blocking(ctx.onedrive.allow, form.get("file_id", ""))
        except PayloadToolError as exc:
            return action_done(request, "error", str(exc.payload.get("message")), back)
        except OneDriveApiError:
            return action_done(request, "error", "OneDrive didn’t answer. Try again.", back)
        if entry is None:
            return action_done(
                request,
                "error",
                "That item can’t be allowed. It may have been deleted, be the top of your "
                "OneDrive, or be a shortcut to someone else’s file.",
                back,
                changed=False,
            )
        await blocking(ctx.requests.clear_denials, entry.id, SOURCE_ONEDRIVE)
        audit_owner("onedrive_allow", file_id=entry.id, name=entry.name)
        return action_done(request, "ok", f"Allowed “{entry.name}” for your assistants.", back)

    async def onedrive_remove(request: Request, form: dict[str, str]) -> Response:
        if ctx.onedrive is None:
            return refused(request, 404, "OneDrive is not set up on this server.")
        entry = await blocking(ctx.onedrive.remove, form.get("file_id", ""))
        back = onedrive_back(form)
        if entry is None:
            return action_done(request, "ok", "That item was not allowed.", back, changed=False)
        await blocking(ctx.requests.clear_denials, entry.id, SOURCE_ONEDRIVE)
        audit_owner("onedrive_remove", file_id=entry.id, name=entry.name)
        return action_done(
            request, "ok", f"Removed “{entry.name}”. Assistants can no longer read it.", back
        )

    return ConnectionPages(
        connect_page=connect_page,
        connect_start=connect_start,
        connect_remove=connect_remove,
        notion_callback=notion_callback,
        notion_files=notion_files,
        notion_allow=notion_allow,
        notion_remove=notion_remove,
        onedrive_callback=onedrive_callback,
        onedrive_files=onedrive_files,
        onedrive_allow=onedrive_allow,
        onedrive_remove=onedrive_remove,
        drive_row_connected=drive_row_connected,
    )

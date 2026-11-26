"""MCP OAuth consent pages: /oauth/authorize (the screen and the decision) and
/oauth/continue.
"""

import hmac
import html
import secrets
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit

from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from ..audit import audit_owner
from ..auth import current_actor
from ..mcp_oauth import APP_ROLES, DEFAULT_APP_ROLE, SCOPE, AuthorizeError, QueryMapping
from .kit import FormHandler, Handler, Kit


@dataclass(frozen=True)
class ConsentPages:
    """What dashboard.py needs from this module: the handlers it routes to, and
    the helpers other page modules call."""

    oauth_authorize: Handler
    oauth_decide: FormHandler
    oauth_continue: Handler


def consent_pages(kit: Kit) -> ConsentPages:
    ctx = kit.ctx
    session_user = kit.session_user
    remember_pending = kit.remember_pending
    connect_redirect = kit.connect_redirect
    render = kit.render
    blocking = kit.blocking

    # ---- MCP OAuth consent (Grok Bot / other remote clients) ------------

    def _oauth_error(request: Request, exc: AuthorizeError, *, from_form: bool = False) -> Response:
        if exc.redirect_uri and ctx.mcp_oauth is not None:
            try:
                target = ctx.mcp_oauth.error_redirect(exc)
            except AuthorizeError:
                target = None
            if target is not None:
                # A form POST's redirect chain is checked against form-action. Stay on
                # this origin and let the next page navigate to the client.
                if from_form:
                    return _parked_redirect(request, target)
                return RedirectResponse(target, status_code=303)
        status = 403 if exc.error == "access_denied" else 400
        return render(request, "error.html", status, message=exc.description)

    def _parked_redirect(request: Request, url: str) -> Response:
        assert ctx.mcp_oauth is not None
        try:
            ticket = ctx.mcp_oauth.park_completion(url, str(request.session.get("owner") or ""))
        except AuthorizeError as exc:
            return render(request, "error.html", 400, message=exc.description)
        return RedirectResponse("/oauth/continue?" + urlencode({"ticket": ticket}), status_code=303)

    def _completion_page(url: str) -> HTMLResponse:
        safe = html.escape(url, quote=True)
        body = (
            "<!doctype html><html><head><meta charset=utf-8>"
            f'<meta http-equiv="refresh" content="0;url={safe}">'
            "<title>Returning to the app</title></head><body>"
            "<p>Returning to the app.</p>"
            f'<p><a href="{safe}">Continue</a></p>'
            "</body></html>"
        )
        return HTMLResponse(body)

    async def oauth_authorize(request: Request) -> Response:
        if ctx.mcp_oauth is None:
            return render(request, "error.html", 404, message="OAuth is not configured.")
        try:
            pending = ctx.mcp_oauth.parse_authorize(request.query_params)
        except AuthorizeError as exc:
            return _oauth_error(request, exc)
        signed_in = session_user(request)
        if request.session.get("owner") and not signed_in:
            return render(
                request,
                "error.html",
                403,
                message="This Google account is not allowed to connect apps.",
            )
        if not signed_in:
            target = request.url.path
            if request.url.query:
                target += "?" + request.url.query
            return RedirectResponse(f"/login?{urlencode({'next': target})}", status_code=303)
        reset = current_actor.set(signed_in)
        try:
            if not await blocking(ctx.drive_connected):
                # An assistant can only be allowed once there is something to reach.
                return connect_redirect(request)
            # The form carries this id back, so Allow only ever approves the request this
            # page describes. A second authorize request in another tab replaces it.
            # Signing in through a named role's address: say so, and refuse a role this
            # person does not have instead of approving a connection that reaches nothing.
            role_slug = ctx.mcp_oauth.bound_role(pending.resource)
            agent_role = None
            if role_slug:
                if ctx.agent_roles is not None:
                    agent_role = await blocking(ctx.agent_roles.get, role_slug)
                if agent_role is None:
                    return render(
                        request,
                        "error.html",
                        404,
                        message=f"You have no role named “{role_slug}”. Make it in Settings, "
                        "under Roles, then connect again.",
                    )
            consent_id = secrets.token_urlsafe(16)
            request.session["mcp_auth"] = {**pending.to_dict(), "consent_id": consent_id}
            await remember_pending(request)
            return_host = urlsplit(pending.redirect_uri).hostname or pending.redirect_uri
            here = request.url.path + ("?" + request.url.query if request.url.query else "")
            return render(
                request,
                "consent.html",
                client_name=pending.client_name,
                # Named by where the approval goes, which the allow list vouches for, not
                # by the name the app chose for itself.
                platform=ctx.mcp_oauth.platform(pending.redirect_uri),
                scope=SCOPE,
                requested_scope=pending.requested_scope,
                return_host=return_host,
                consent_id=consent_id,
                switch_next=here,
                agent_role=agent_role,
                mailbox_on=ctx.mailbox is not None and agent_role is None,
                shared_on=ctx.shared_with_me is not None and agent_role is None,
            )
        finally:
            current_actor.reset(reset)

    async def oauth_decide(request: Request, form: dict[str, str]) -> Response:
        if ctx.mcp_oauth is None:
            return render(request, "error.html", 404, message="OAuth is not configured.")
        decision = form.get("decision")
        if decision not in ("allow", "deny"):
            return render(request, "error.html", 400, message="Choose Allow or Deny.")
        raw = request.session.get("mcp_auth")
        if not isinstance(raw, dict):
            return render(
                request,
                "error.html",
                400,
                message="This approval expired. Start the connection again from the app.",
            )
        expected = str(raw.get("consent_id") or "")
        if not expected or not hmac.compare_digest(
            expected.encode(), str(form.get("consent_id") or "").encode()
        ):
            # The newer request stays pending: its own page can still be answered.
            return render(
                request,
                "error.html",
                400,
                message=(
                    "A newer connection request replaced this page, so nothing was approved. "
                    "Use the newest page, or start the connection again from the app."
                ),
            )
        try:
            pending = ctx.mcp_oauth.parse_authorize(QueryMapping(raw))
        except AuthorizeError as exc:
            request.session.pop("mcp_auth", None)
            return _oauth_error(request, exc, from_form=True)
        request.session.pop("mcp_auth", None)
        try:
            if decision == "deny":
                audit_owner("oauth_deny", client=pending.client_name)
                target = ctx.mcp_oauth.deny(pending)
            else:
                role = form.get("role") or DEFAULT_APP_ROLE
                if role not in APP_ROLES:
                    raise AuthorizeError("invalid_request", "Choose what this app may do.")
                audit_owner("oauth_approve", client=pending.client_name, role=role)
                target = ctx.mcp_oauth.approve(str(request.session.get("owner")), pending, role)
        except AuthorizeError as exc:
            return _oauth_error(request, exc, from_form=True)
        return _parked_redirect(request, target)

    async def oauth_continue(request: Request) -> Response:
        if ctx.mcp_oauth is None:
            return render(request, "error.html", 404, message="OAuth is not configured.")
        url = ctx.mcp_oauth.take_completion(
            request.query_params.get("ticket") or "", str(request.session.get("owner") or "")
        )
        if url is None:
            return render(
                request,
                "error.html",
                400,
                message="This return link expired. Start the connection again from the app.",
            )
        return _completion_page(url)

    return ConsentPages(
        oauth_authorize=oauth_authorize,
        oauth_decide=oauth_decide,
        oauth_continue=oauth_continue,
    )

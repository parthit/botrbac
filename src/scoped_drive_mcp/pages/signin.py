"""Sign-in pages: /login, the Google OAuth round trip (step 1, and the callback that
also finishes step 2, connecting Google Drive), and /logout.
"""

import hmac
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from itsdangerous import BadSignature
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from ..audit import audit_owner
from ..auth import current_actor
from ..connections import Connection, get_connection
from ..oauth import SIGN_IN_SCOPES, OAuthError
from ..ratelimit import allow, ip_identity
from ..store import usable_email
from .common import _LOGIN_HINT, SESSION_MAX_AGE, STATE_MAX_AGE
from .kit import FormHandler, Handler, Kit


@dataclass(frozen=True)
class SigninPages:
    """What dashboard.py needs from this module: the handlers it routes to, and
    the helpers other page modules call."""

    login: Handler
    auth_login: Handler
    auth_callback: Handler
    logout: FormHandler
    start_oauth: Callable[..., RedirectResponse]
    login_rate_limited: Callable[[Request], Awaitable[Response | None]]


def signin_pages(kit: Kit) -> SigninPages:
    ctx = kit.ctx
    settings = kit.settings
    oauth = kit.oauth
    serializer = kit.serializer
    session_user = kit.session_user
    render = kit.render
    flash = kit.flash
    blocking = kit.blocking
    safe_next = kit.safe_next

    # ---- sign-in -------------------------------------------------------

    def start_oauth(
        request: Request,
        flow: str,
        login_hint: str | None,
        connection: Connection | None = None,
    ) -> RedirectResponse:
        """Step 1 (`flow="signin"`) or step 2 (`flow="connect"` with a connection)."""
        nonce = secrets.token_urlsafe(24)
        request.session["oauth_nonce"] = nonce
        payload: dict[str, str] = {"flow": flow, "nonce": nonce}
        if connection is None:
            url_scopes = SIGN_IN_SCOPES
            offline = False
        else:
            payload["connection"] = connection.key
            url_scopes = SIGN_IN_SCOPES + connection.scopes
            offline = True
        state = serializer.dumps(payload)
        url = oauth.authorization_url(state, login_hint, scopes=url_scopes, offline=offline)
        return RedirectResponse(url, status_code=303)

    async def login_rate_limited(request: Request) -> Response | None:
        allowed = await blocking(
            allow,
            ctx.store,
            "login",
            ip_identity(request.scope),
            settings.login_rate_limit,
            settings.login_rate_window_seconds,
        )
        if allowed:
            return None
        page = render(
            request,
            "error.html",
            429,
            message=(
                "Too many sign-in attempts from this network. Wait a few minutes and try again."
            ),
        )
        page.headers["retry-after"] = str(settings.login_rate_window_seconds)
        return page

    async def login(request: Request) -> Response:
        if session_user(request):
            return RedirectResponse(safe_next(request.query_params.get("next")), status_code=303)
        # A cookie whose session has ended on the server still names its account. Forget
        # it, so this page (and its header) does not show that address to whoever is at
        # the browser now.
        for stale in ("owner", "sid", "csrf"):
            request.session.pop(stale, None)
        next_url = safe_next(request.query_params.get("next"))
        purpose = hint = None
        if next_url.startswith("/requests/"):
            purpose = "review an access request"
            hint = "Use the Google account that owns the assistant that asked."
        elif next_url.startswith("/oauth/authorize"):
            purpose = "connect an assistant"
            hint = "Use the Google account whose files the assistant should work with."
        return render(
            request,
            "login.html",
            next=next_url,
            purpose=purpose,
            purpose_hint=hint,
            signed_out=request.query_params.get("signed_out") == "1",
        )

    def supplied_login_hint(request: Request) -> str | None:
        """A hint only when this visitor typed one. Never the server's owner address."""
        raw = request.query_params.get("login_hint")
        if not isinstance(raw, str):
            return None
        raw = raw.strip().lower()
        if not raw or len(raw) > 254 or not _LOGIN_HINT.fullmatch(raw):
            return None
        return raw

    async def auth_login(request: Request) -> Response:
        limited = await login_rate_limited(request)
        if limited is not None:
            return limited
        request.session["oauth_next"] = safe_next(request.query_params.get("next"))
        return start_oauth(request, "signin", supplied_login_hint(request))

    async def auth_callback(request: Request) -> Response:
        params = request.query_params
        if params.get("error"):
            return oauth_cancelled(request, params)
        try:
            data = serializer.loads(params.get("state", ""), max_age=STATE_MAX_AGE)
        except BadSignature:
            return render(request, "error.html", 400, message="Invalid sign-in state. Try again.")
        nonce = request.session.pop("oauth_nonce", None)
        if (
            not isinstance(data, dict)
            or not nonce
            or not hmac.compare_digest(str(nonce), str(data.get("nonce", "")))
        ):
            return render(request, "error.html", 400, message="Sign-in expired. Try again.")
        flow = data.get("flow")
        if flow not in ("signin", "connect"):
            return render(request, "error.html", 400, message="Invalid sign-in state.")
        code = params.get("code")
        if not code:
            return render(request, "error.html", 400, message="Google did not return a code.")

        try:
            tokens = await blocking(oauth.exchange_code, code)
            info = await blocking(oauth.userinfo, tokens.access_token)
        except OAuthError as exc:
            return render(request, "error.html", 502, message=f"Sign-in failed: {exc}.")

        email = str(info.get("email", "")).strip().lower()
        verified = info.get("email_verified") in (True, "true")
        # An address that cannot name a tenant (one with ':' or control characters) is
        # refused here, so it gets a clear answer instead of failing inside the store.
        if not verified or not usable_email(email) or not settings.sign_in_allowed(email):
            await blocking(oauth.revoke, tokens.refresh_token or tokens.access_token)
            audit_owner("login", "deny", reason="wrong_account")
            return render(
                request,
                "error.html",
                403,
                message="This Google account is not allowed to use this dashboard.",
            )
        if flow == "connect":
            return await finish_connect(request, data, tokens, email)
        return await finish_sign_in(request, email)

    def oauth_cancelled(request: Request, params: Any) -> Response:
        """Google sent the person back without a code (they chose Cancel, or Google
        refused). Say which step it was and offer to try that step again."""
        flow = None
        connection = None
        try:
            data = serializer.loads(params.get("state", ""), max_age=STATE_MAX_AGE)
        except BadSignature:
            data = None
        if isinstance(data, dict):
            flow = data.get("flow")
            connection = get_connection(str(data.get("connection") or ""))
        request.session.pop("oauth_nonce", None)
        next_url = safe_next(request.session.get("oauth_next"))
        cancelled = params.get("error") == "access_denied"
        if flow == "connect" and session_user(request):
            name = connection.name if connection else "Google Drive"
            retry = "/connect" + (f"?{urlencode({'next': next_url})}" if next_url != "/" else "")
            return render(
                request,
                "error.html",
                400,
                title=f"You didn’t connect {name}" if cancelled else f"{name} isn’t connected",
                message=(
                    f"You cancelled on Google’s screen, so nothing changed. Your assistant "
                    f"can’t reach {name} until you connect it."
                    if cancelled
                    else f"Google didn’t finish connecting {name}. Nothing changed."
                ),
                actions=[
                    {"label": "Try again", "href": retry, "primary": True},
                    {"label": "Back to Overview", "href": "/"},
                ],
            )
        retry = "/login" + (f"?{urlencode({'next': next_url})}" if next_url != "/" else "")
        return render(
            request,
            "error.html",
            400,
            title="Sign-in cancelled" if cancelled else "Sign-in didn’t finish",
            message=(
                "You cancelled on Google’s screen, so you are not signed in."
                if cancelled
                else "Google didn’t finish signing you in. Nothing was changed."
            ),
            actions=[
                {"label": "Try again", "href": retry, "primary": True},
                {"label": "Back to home", "href": "/"},
            ],
        )

    async def finish_sign_in(request: Request, email: str) -> Response:
        """Step 1 done. Nothing from Google is stored except that this address signed in."""
        if ctx.directory is not None:
            reset = current_actor.set(email)
            try:
                await blocking(ctx.directory.remember_user, email)
            finally:
                current_actor.reset(reset)
        next_url = safe_next(request.session.get("oauth_next"))
        old_sid = request.session.get("sid")
        request.session.clear()
        request.session["owner"] = email
        if ctx.directory is not None:
            # End the session this browser had before, so a copy of the old cookie
            # stops working (and a different account's session does not linger).
            await blocking(ctx.directory.close_session, old_sid)
            request.session["sid"] = await blocking(
                ctx.directory.open_session, email, SESSION_MAX_AGE
            )
        request.session["csrf"] = secrets.token_urlsafe(32)
        # As the person signing in, so the row lands in their own Activity. With no
        # actor it would be written to the admin's list, by anyone with a Google account.
        reset = current_actor.set(email)
        try:
            audit_owner("login")
            connected = await blocking(ctx.drive_connected)
        finally:
            current_actor.reset(reset)
        if not connected:
            # Step 2 is its own page and its own click, never chained silently.
            return RedirectResponse(f"/connect?{urlencode({'next': next_url})}", status_code=303)
        return RedirectResponse(next_url, status_code=303)

    async def refuse_token(tokens: Any, email: str) -> None:
        # Google's revoke ends this app's whole grant for that Google account, which
        # would also kill a token already stored for it (a reconnect that was
        # declined, or another person's account). Only revoke when none is stored.
        if ctx.directory is not None:
            stored = await blocking(ctx.directory.has_owner_refresh, email)
        else:
            stored = True
        if not stored:
            await blocking(oauth.revoke, tokens.refresh_token or tokens.access_token)

    async def finish_connect(
        request: Request, data: dict[str, Any], tokens: Any, email: str
    ) -> Response:
        """Step 2 done. Store the refresh token for the signed-in person."""
        signed_in = session_user(request)
        connection = get_connection(str(data.get("connection") or ""))
        if not signed_in or connection is None:
            await refuse_token(tokens, email)
            return render(request, "error.html", 400, message="Sign in first, then connect.")
        if email != signed_in:
            # The Drive an assistant uses must belong to the person who signed in.
            await refuse_token(tokens, email)
            reset = current_actor.set(signed_in)
            try:
                audit_owner("connect", "deny", reason="different_account")
            finally:
                current_actor.reset(reset)
            next_url = safe_next(request.session.get("oauth_next"))
            retry = "/connect" + (f"?{urlencode({'next': next_url})}" if next_url != "/" else "")
            return render(
                request,
                "error.html",
                403,
                title="That was a different Google account",
                message=(
                    f"You are signed in as {signed_in}, but Google returned a different "
                    f"account. Connect {connection.name} with {signed_in}."
                ),
                actions=[
                    {"label": "Try again", "href": retry, "primary": True},
                    {"label": "Back to Overview", "href": "/"},
                ],
            )
        # Everything below reads or changes this person's own stored state. The callback
        # runs outside owner_only, so set the actor here: unset, the store falls back to
        # the admin's keys, and a refused connection would wipe the admin's Drive token.
        reset = current_actor.set(email)
        try:
            return await complete_connect(request, tokens, email, connection)
        finally:
            current_actor.reset(reset)

    async def complete_connect(
        request: Request, tokens: Any, email: str, connection: Connection
    ) -> Response:
        """The rest of step 2, with `current_actor` already set to `email`."""
        if connection.scopes_too_wide(tokens.scopes):
            # Wider than this app asks for. Never stored. Revoking it ends this app's grant
            # for that account, which is the point: Google should not keep it either.
            await blocking(oauth.revoke, tokens.refresh_token or tokens.access_token)
            await blocking(ctx.disconnect_drive)
            ctx.forget_drive(email)
            audit_owner("connect", "deny", reason="scope_too_wide")
            return render(
                request,
                "error.html",
                400,
                title="Google gave more access than Bot RBAC asks for",
                message=(
                    "Bot RBAC only uses access to the files you pick, so that connection "
                    "was refused and revoked. Remove Bot RBAC at "
                    "myaccount.google.com/permissions, then choose Connect again."
                ),
            )
        if connection.required_scope not in tokens.scopes:
            await refuse_token(tokens, email)
            return render(
                request,
                "error.html",
                400,
                message=(
                    f"{connection.name} access was not granted. Choose Connect again and "
                    f"allow access to the files you pick."
                ),
            )
        if not tokens.refresh_token:
            return render(
                request,
                "error.html",
                400,
                message="Google did not return a refresh token. Remove the app at "
                "myaccount.google.com/permissions and try again.",
            )

        scope_stamp = " ".join(sorted(tokens.scopes))
        await blocking(ctx.vault.set_owner, tokens.refresh_token, email, scope_stamp)
        if ctx.directory is not None:
            await blocking(ctx.directory.remember_user, email)
        ctx.forget_drive(email)
        audit_owner("connect", connection=connection.key)
        next_url = safe_next(request.session.pop("oauth_next", None))
        flash(request, "ok", f"{connection.name} is connected.")
        return RedirectResponse(next_url, status_code=303)

    async def logout(request: Request, form: dict[str, str]) -> Response:
        audit_owner("logout")
        if ctx.directory is not None:
            await blocking(ctx.directory.close_session, request.session.get("sid"))
        request.session.clear()
        # "Switch account" on a request page and "Use a different account" on the consent
        # page sign out, then signs in with ?next back.
        pairs = [("signed_out", "1")]
        next_url = safe_next(form.get("next"))
        if next_url != "/":
            pairs.append(("next", next_url))
        return RedirectResponse(f"/login?{urlencode(pairs)}", status_code=303)

    return SigninPages(
        login=login,
        auth_login=auth_login,
        auth_callback=auth_callback,
        logout=logout,
        start_oauth=start_oauth,
        login_rate_limited=login_rate_limited,
    )

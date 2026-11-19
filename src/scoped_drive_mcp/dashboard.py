"""Web dashboard: sign-in, connections, Drive browser, allowlist, access requests, activity.

Google is asked twice. Step 1 (`/auth/login`) signs the person in with `openid` and
`email` only, and sets a signed, httponly, SameSite=Lax session cookie. Step 2
(`/connect`) is a separate, explicit choice that asks for the wider scopes of one
connection (Google Drive today, see `connections.py`) and stores that refresh token.
Pages that need Drive send a signed-in person without a connection to `/connect`.
Each person sees only their own data.
`OWNER_EMAIL` is the admin and the only account that can open `/admin`. MCP bearer tokens
are never consulted here, and the MCP endpoint never reads this cookie (it is a separate
ASGI app behind BearerAuthMiddleware). Every POST requires the per-session CSRF token, and
a cross-origin `Origin` is refused.
"""

import hmac
import html
import logging
import re
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

import anyio.to_thread
from itsdangerous import BadSignature, URLSafeTimedSerializer
from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .access import PENDING, AccessRequests
from .audit import audit_owner
from .auth import current_actor
from .bridge import MailboxError
from .config import Settings
from .connections import CONNECTIONS, Connection, get_connection
from .drive_client import (
    DRIVE_SCOPE,
    FOLDER_MIME,
    SHORTCUT_MIME,
    DriveNotFoundError,
    LazyBotDriveClient,
    OwnerDriveClient,
)
from .errors import report_exception
from .grants import OWNER_FIELDS, GrantError, GrantService
from .mcp_oauth import SCOPE, AuthorizeError, McpOAuth, QueryMapping
from .oauth import SIGN_IN_SCOPES, OAuthClient, OAuthError, refresh_access_token
from .ratelimit import allow, client_ip
from .scope import InvalidInputError, clean_search_text, parents_clause, validate_drive_id
from .store import ActivityLog, Allowlist, TokenVault

logger = logging.getLogger(__name__)

SESSION_COOKIE = "sdm_session"
SESSION_MAX_AGE = 8 * 3600
STATE_MAX_AGE = 600
STATE_SALT = "sdm-oauth-state"
BROWSE_PAGE_SIZE = 200
MAX_BREADCRUMBS = 25

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)

SECURITY_HEADERS = [
    (b"x-frame-options", b"DENY"),
    (b"x-content-type-options", b"nosniff"),
    # `no-referrer` makes browsers send `Origin: null` on HTML form POSTs (Fetch:
    # non-GET, non-cors). check_csrf treats that as a cross-origin request, so a
    # signed-in Sign out fails before the session token is compared. `same-origin`
    # still withholds the referrer from other sites, and a same-origin form POST
    # carries this app's origin.
    (b"referrer-policy", b"same-origin"),
    (b"cache-control", b"no-store"),
    (
        b"content-security-policy",
        # Google Picker loads api.js from apis.google.com (that script evaluates code),
        # then opens Drive in a frame. frame-ancestors stays none so this site is not embedded.
        b"default-src 'self'; "
        b"script-src 'self' https://apis.google.com https://www.gstatic.com 'unsafe-eval'; "
        b"style-src 'self' 'unsafe-inline'; "
        b"img-src 'self' data: https://*.googleusercontent.com https://*.gstatic.com; "
        b"connect-src 'self' https://www.googleapis.com https://content.googleapis.com; "
        b"frame-src https://docs.google.com https://drive.google.com https://accounts.google.com "
        b"https://content.googleapis.com https://*.google.com https://*.googleusercontent.com; "
        b"worker-src 'self' blob:; "
        b"form-action 'self' https://accounts.google.com; "
        b"frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
    ),
]

_LOGIN_HINT = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class OwnerNotConnectedError(Exception):
    """Signed in, but Google Drive is not connected yet (send them to /connect)."""


@dataclass
class DashboardContext:
    settings: Settings
    store: Any
    allowlist: Allowlist
    vault: TokenVault
    requests: AccessRequests
    activity: ActivityLog
    oauth: OAuthClient | None
    owner_drive_factory: Callable[[str], OwnerDriveClient]
    bot_drive: Any = None
    on_allowlist_change: Callable[[], None] = lambda: None
    mcp_oauth: McpOAuth | None = None
    directory: Any = None
    drive_router: Any = None
    mailbox: Any = None
    _owner_clients: dict[str, tuple[str, OwnerDriveClient]] = field(
        default_factory=dict, repr=False
    )

    def _admin_actor(self) -> bool:
        actor = current_actor.get()
        return not actor or actor == self.settings.owner_email

    def owner_drive(self) -> OwnerDriveClient:
        record = self.vault.owner()
        if not record or not record.get("t"):
            raise OwnerNotConnectedError
        token = record["t"]
        actor = current_actor.get() or ""
        cached = self._owner_clients.get(actor)
        if cached is None or cached[0] != token:
            self._owner_clients[actor] = (token, self.owner_drive_factory(token))
        return self._owner_clients[actor][1]

    def grants(self) -> GrantService:
        return GrantService(
            self.owner_drive,
            self.allowlist,
            self.requests,
            None,
            on_change=self.on_allowlist_change,
        )

    def visible_root_folder_id(self) -> str | None:
        """The deployment root is the admin's folder. Other people do not see its id."""
        if self._admin_actor():
            return self.settings.root_folder_id
        return None

    def forget_drive(self, email: str | None = None) -> None:
        if isinstance(self.bot_drive, LazyBotDriveClient) and (
            email is None or email == self.settings.owner_email
        ):
            self.bot_drive.invalidate()
        if self.drive_router is not None:
            self.drive_router.invalidate(email)

    def bot_status(self) -> dict[str, Any]:
        """Which Google account the MCP tools act as, and where its token comes from."""
        if self._admin_actor() and self.settings.env_bot_refresh_token:
            return {"connected": True, "source": "env", "email": self.settings.owner_email}
        record = self.vault.owner() if self.vault.enabled else None
        if record and record.get("t"):
            return {"connected": True, "source": "owner", "email": record.get("email")}
        return {"connected": False, "source": None, "email": None}

    def owner_connected(self) -> bool:
        return bool(self.vault.enabled and self.vault.owner())

    def drive_connected(self) -> bool:
        """Step 2 is done: a Google Drive refresh token is stored for this person."""
        if not self.vault.enabled:
            return False
        record = self.vault.owner()
        return bool(record and record.get("t"))

    def connection_rows(self) -> list[dict[str, Any]]:
        """Each connection and whether this person has finished it."""
        rows = []
        for conn in CONNECTIONS.values():
            connected = self.drive_connected() if conn.key == "google_drive" else False
            # A stored token without the full scope (old drive.file, or no scope stamp)
            # still works for what it covers, but has to be upgraded by connecting again.
            needs_upgrade = connected and conn.key == "google_drive" and self.reconsent_needed()
            rows.append(
                {"connection": conn, "connected": connected, "needs_upgrade": needs_upgrade}
            )
        return rows

    def disconnect_drive(self) -> str | None:
        """Forget this person's Drive token. Returns the token so Google can revoke it."""
        record = self.vault.owner() if self.vault.enabled else None
        token = record.get("t") if record else None
        self.vault.clear_owner()
        return token

    def reconsent_needed(self) -> bool:
        """True when the saved sign-in cannot see the whole Drive.

        A missing scope stamp, or a token that only has drive.file, has to sign in
        again. A token that already includes full Drive does not.
        """
        if not self.vault.enabled:
            return False
        record = self.vault.owner()
        if not record or not record.get("t"):
            return False
        scopes = set(str(record.get("scopes") or "").split())
        return DRIVE_SCOPE not in scopes


async def blocking[T](fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    return await anyio.to_thread.run_sync(partial(fn, *args, **kwargs))


def safe_next(value: str | None) -> str:
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value:
        return "/"
    return value


def origin_of(url: str) -> str:
    scheme, _, rest = url.partition("://")
    return f"{scheme}://{rest.split('/', 1)[0]}"


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                message.setdefault("headers", [])
                message["headers"] = list(message["headers"]) + SECURITY_HEADERS
            await send(message)

        await self.app(scope, receive, send_with_headers)


# ---- rendering helpers ----------------------------------------------------


def _csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return token


def flash(request: Request, kind: str, message: str) -> None:
    messages = list(request.session.get("flash", []))
    messages.append([kind, message])
    request.session["flash"] = messages[-5:]


def render(request: Request, template: str, status_code: int = 200, **ctx: Any) -> HTMLResponse:
    owner = request.session.get("owner")
    admin_email = getattr(request.app.state, "owner_email", None)
    # Callers that already loaded the waiting-request count pass it. Otherwise use the
    # count stashed for this request. Rendering itself does not read the store.
    pending_count = ctx.pop("pending_count", None)
    if pending_count is None:
        pending_count = getattr(request.state, "pending_count", 0)
    reconsent = ctx.pop("reconsent", None)
    if reconsent is None:
        reconsent = getattr(request.state, "reconsent", False)
    html = _env.get_template(template).render(
        request=request,
        owner=owner,
        is_admin=bool(owner and admin_email and owner == admin_email),
        csrf=_csrf_token(request) if owner else None,
        flashes=request.session.pop("flash", []) if owner else [],
        nav=request.url.path,
        pending_count=pending_count,
        reconsent=reconsent,
        **ctx,
    )
    return HTMLResponse(html, status_code=status_code)


def render_plain(template: str, status_code: int = 200, **ctx: Any) -> HTMLResponse:
    html = _env.get_template(template).render(
        owner=None, csrf=None, flashes=[], nav="", reconsent=False, pending_count=0, **ctx
    )
    return HTMLResponse(html, status_code=status_code)


async def terms_page(_: Request) -> Response:
    return render_plain("terms.html")


async def privacy_page(_: Request) -> Response:
    return render_plain("privacy.html")


def _file_response(name: str, media: str) -> Response:
    return Response((TEMPLATES_DIR / name).read_bytes(), media_type=media)


def favicon(_: Request) -> Response:
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img">'
        '<rect width="64" height="64" rx="14" fill="#f6f2ea"/>'
        '<g transform="translate(3.8 4.975) scale(2.35)">'
        '<path id="scoped-mark" fill="#1e1915" fill-rule="evenodd" '
        'd="M5 20V10a7 7 0 0 1 14 0v10h-3.2V10a3.8 3.8 0 0 0-7.6 0v10H5z"/>'
        "</g></svg>"
    )
    return Response(svg, media_type="image/svg+xml")


_FONT_FILES = {
    "geist-400.woff2": "fonts/geist-400.woff2",
    "geist-500.woff2": "fonts/geist-500.woff2",
    "geist-600.woff2": "fonts/geist-600.woff2",
    "geist-mono-500.woff2": "fonts/geist-mono-500.woff2",
}


def font_asset(request: Request) -> Response:
    rel = _FONT_FILES.get(request.path_params["name"])
    if rel is None:
        return Response(status_code=404)
    return _file_response(rel, "font/woff2")


def robots(_: Request) -> Response:
    body = (
        "User-agent: *\n"
        "Allow: /$\n"
        "Allow: /login\n"
        "Allow: /privacy\n"
        "Allow: /terms\n"
        "Disallow: /\n"
    )
    return Response(body, media_type="text/plain; charset=utf-8")


def stylesheet(_: Request) -> Response:
    return _file_response("app.css", "text/css; charset=utf-8")


def ui_script(_: Request) -> Response:
    return _file_response("ui.js", "text/javascript; charset=utf-8")


def legal_routes() -> list[Route]:
    """Public pages and assets. Google's OAuth screen links to /terms and /privacy."""
    return [
        Route("/terms", terms_page, methods=["GET"]),
        Route("/privacy", privacy_page, methods=["GET"]),
        Route("/favicon.ico", favicon, methods=["GET"]),
        Route("/favicon.svg", favicon, methods=["GET"]),
        Route("/robots.txt", robots, methods=["GET"]),
        Route("/app.css", stylesheet, methods=["GET"]),
        Route("/ui.js", ui_script, methods=["GET"]),
        Route("/fonts/{name}", font_asset, methods=["GET"]),
    ]


Handler = Callable[[Request], Awaitable[Response]]


def build_dashboard(ctx: DashboardContext) -> Starlette:
    settings = ctx.settings
    missing = settings.dashboard_missing()
    if missing or ctx.oauth is None:

        async def not_configured(request: Request) -> Response:
            return render_plain("setup.html", status_code=503, missing=missing)

        return Starlette(
            routes=[
                *legal_routes(),
                Route("/{path:path}", not_configured, methods=["GET", "POST"]),
            ],
            middleware=[Middleware(SecurityHeadersMiddleware)],
        )

    assert settings.session_secret is not None and settings.app_base_url is not None
    oauth = ctx.oauth
    serializer = URLSafeTimedSerializer(settings.session_secret.get_secret_value(), STATE_SALT)
    app_origin = origin_of(settings.app_base_url)

    async def remember_pending(request: Request) -> None:
        """One waiting-request count for this page, off the event loop. The nav reads it."""
        try:
            request.state.pending_count = await blocking(ctx.requests.pending_count)
        except Exception:
            logger.exception("pending request count failed")
            request.state.pending_count = 0
        try:
            request.state.reconsent = await blocking(ctx.reconsent_needed)
        except Exception:
            logger.exception("reconsent check failed")
            request.state.reconsent = False

    def session_user(request: Request) -> str | None:
        """Signed-in email (step 1). A Drive connection (step 2) is not required here."""
        owner = request.session.get("owner")
        if not isinstance(owner, str) or not owner or ctx.directory is None:
            return None
        if not settings.sign_in_allowed(owner):
            return None
        if not ctx.directory.is_known_user(owner):
            return None
        return owner

    def connect_redirect(request: Request) -> RedirectResponse:
        target = request.url.path
        if request.url.query:
            target += "?" + request.url.query
        if request.method != "GET":
            target = "/"
        return RedirectResponse(f"/connect?{urlencode({'next': target})}", status_code=303)

    def owner_only(handler: Handler) -> Handler:
        async def wrapped(request: Request) -> Response:
            email = session_user(request)
            if not email:
                if request.method != "GET":
                    return Response("Sign in first.", status_code=403)
                target = request.url.path
                if request.url.query:
                    target += "?" + request.url.query
                return RedirectResponse(f"/login?{urlencode({'next': target})}", status_code=303)
            reset = current_actor.set(email)
            try:
                await remember_pending(request)
                return await handler(request)
            except OwnerNotConnectedError:
                return connect_redirect(request)
            except InvalidInputError as exc:
                return render(request, "error.html", 400, message=str(exc))
            except Exception as exc:
                report_exception(exc, where="dashboard")
                return render(
                    request, "error.html", 502, message="A Google Drive request failed. Try again."
                )
            finally:
                current_actor.reset(reset)

        return wrapped

    async def check_csrf(request: Request) -> dict[str, str] | None:
        origin = request.headers.get("origin")
        if origin is not None and origin != app_origin:
            return None
        form = await request.form()
        sent = form.get("csrf")
        expected = request.session.get("csrf")
        if not isinstance(sent, str) or not expected or not hmac.compare_digest(sent, expected):
            return None
        return {k: v for k, v in form.items() if isinstance(v, str)}

    def csrf_protected(
        handler: Callable[[Request, dict[str, str]], Awaitable[Response]],
    ) -> Handler:
        async def wrapped(request: Request) -> Response:
            form = await check_csrf(request)
            if form is None:
                audit_owner("csrf", "deny", path=request.url.path)
                return Response("CSRF check failed.", status_code=403)
            return await handler(request, form)

        return owner_only(wrapped)

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
        ip = client_ip(
            [(k.encode(), v.encode()) for k, v in request.headers.items()],
            request.client.host if request.client else "unknown",
        )
        allowed = await blocking(
            allow,
            ctx.store,
            "login",
            "ip:" + ip,
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
        return render(request, "login.html", next=safe_next(request.query_params.get("next")))

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
            return render(request, "error.html", 400, message="Google sign-in was cancelled.")
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
        if not verified or not settings.sign_in_allowed(email):
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

    async def finish_sign_in(request: Request, email: str) -> Response:
        """Step 1 done. Nothing from Google is stored except that this address signed in."""
        if ctx.directory is not None:
            reset = current_actor.set(email)
            try:
                await blocking(ctx.directory.remember_user, email)
            finally:
                current_actor.reset(reset)
        next_url = safe_next(request.session.get("oauth_next"))
        request.session.clear()
        request.session["owner"] = email
        request.session["csrf"] = secrets.token_urlsafe(32)
        audit_owner("login")
        reset = current_actor.set(email)
        try:
            connected = await blocking(ctx.drive_connected)
        finally:
            current_actor.reset(reset)
        if not connected:
            # Step 2 is its own page and its own click, never chained silently.
            return RedirectResponse(f"/connect?{urlencode({'next': next_url})}", status_code=303)
        return RedirectResponse(next_url, status_code=303)

    async def finish_connect(
        request: Request, data: dict[str, Any], tokens: Any, email: str
    ) -> Response:
        """Step 2 done. Store the refresh token for the signed-in person."""

        async def refuse_token() -> None:
            # Google's revoke ends this app's whole grant for that Google account, which
            # would also kill a token already stored for it (a reconnect that was
            # declined, or another person's account). Only revoke when none is stored.
            if ctx.directory is not None:
                stored = await blocking(ctx.directory.has_owner_refresh, email)
            else:
                stored = True
            if not stored:
                await blocking(oauth.revoke, tokens.refresh_token or tokens.access_token)

        signed_in = session_user(request)
        connection = get_connection(str(data.get("connection") or ""))
        if not signed_in or connection is None:
            await refuse_token()
            return render(request, "error.html", 400, message="Sign in first, then connect.")
        if email != signed_in:
            # The Drive an assistant uses must belong to the person who signed in.
            await refuse_token()
            audit_owner("connect", "deny", reason="different_account")
            return render(
                request,
                "error.html",
                403,
                message=(
                    f"You are signed in as {signed_in}, but Google returned a different "
                    f"account. Connect {connection.name} with {signed_in}."
                ),
            )
        if connection.required_scope not in tokens.scopes:
            await refuse_token()
            return render(
                request,
                "error.html",
                400,
                message=(
                    f"{connection.name} access was not granted. Choose Connect again and "
                    f"allow access to your Drive."
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

        reset = current_actor.set(email)
        try:
            scope_stamp = " ".join(sorted(tokens.scopes))
            await blocking(ctx.vault.set_owner, tokens.refresh_token, email, scope_stamp)
            if ctx.directory is not None:
                await blocking(ctx.directory.remember_user, email)
        finally:
            current_actor.reset(reset)
        ctx.forget_drive(email)
        audit_owner("connect", connection=connection.key)
        next_url = safe_next(request.session.pop("oauth_next", None))
        flash(request, "ok", f"{connection.name} is connected.")
        return RedirectResponse(next_url, status_code=303)

    # ---- connections (step 2) -------------------------------------------

    async def connect_page(request: Request) -> Response:
        rows = await blocking(ctx.connection_rows)
        next_url = safe_next(request.query_params.get("next"))
        if next_url.startswith("/connect"):
            next_url = "/"
        return render(request, "connect.html", rows=rows, next=next_url)

    async def connect_start(request: Request, form: dict[str, str]) -> Response:
        connection = get_connection(request.path_params.get("key"))
        if connection is None:
            return render(request, "error.html", 404, message="Unknown connection.")
        limited = await login_rate_limited(request)
        if limited is not None:
            return limited
        request.session["oauth_next"] = safe_next(form.get("next"))
        return start_oauth(request, "connect", current_actor.get() or None, connection)

    async def connect_remove(request: Request, form: dict[str, str]) -> Response:
        connection = get_connection(request.path_params.get("key"))
        if connection is None:
            return render(request, "error.html", 404, message="Unknown connection.")
        email = current_actor.get()
        token = await blocking(ctx.disconnect_drive)
        if token:
            # Google's revoke also ends this app's sign-in grant. Step 1 holds no token,
            # so the dashboard session is unaffected.
            await blocking(oauth.revoke, token)
        ctx.forget_drive(email)
        audit_owner("disconnect", connection=connection.key)
        flash(
            request,
            "ok",
            f"{connection.name} is disconnected. Assistants can no longer reach it.",
        )
        return RedirectResponse("/connect", status_code=303)

    async def logout(request: Request, form: dict[str, str]) -> Response:
        audit_owner("logout")
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    # ---- pages -----------------------------------------------------------

    async def home(request: Request) -> Response:
        # Logged-out visitors get the public page linked from the Google consent screen.
        email = session_user(request)
        if not email:
            return render_plain("home.html")
        reset = current_actor.set(email)
        try:
            await remember_pending(request)
            return await overview(request)
        finally:
            current_actor.reset(reset)

    async def overview(request: Request) -> Response:
        def gather() -> dict[str, Any]:
            entries = ctx.allowlist.entries()
            bot = ctx.bot_status()
            return {
                "bot": bot,
                "owner_connected": ctx.owner_connected(),
                "connections": ctx.connection_rows(),
                "allow_count": len(entries),
                "grants": (
                    ctx.mcp_oauth.list_grants(current_actor.get()) if ctx.mcp_oauth else []
                ),
            }

        data = await blocking(gather)
        return render(
            request,
            "overview.html",
            missing=settings.missing_settings(),
            store_kind=getattr(ctx.store, "kind", "custom"),
            root_folder_id=ctx.visible_root_folder_id(),
            mcp_url=f"{settings.app_base_url}/mcp",
            picker_ready=settings.picker_configured,
            env_token_set=bool(
                settings.env_bot_refresh_token and session_user(request) == settings.owner_email
            ),
            **data,
        )

    def browse_data(folder: str, q: str | None, page_token: str | None) -> dict[str, Any]:
        drive = ctx.owner_drive()
        # drive.file cannot files.get("root") until the app has opened My Drive.
        # The alias still works in a parents query, which is enough to list files
        # this app created or the user picked.
        root_id: str | None
        try:
            root_id = str(drive.get_file("root", fields="id")["id"])
        except DriveNotFoundError:
            root_id = None
        entries = ctx.allowlist.entries()
        crumbs: list[dict[str, str]] = []
        covered_by: str | None = None
        next_token: str | None = None
        current: dict[str, Any] | None = None
        if q:
            term = clean_search_text(q)
            query = f"trashed=false and name contains '{term}'"
            resp = drive.list_files(query, fields=OWNER_FIELDS, page_size=100)
            items = resp.get("files", [])
        else:
            if folder == "root":
                folder_id = root_id or "root"
            else:
                folder_id = validate_drive_id(folder, "folder")
            if folder_id == "root":
                current = {
                    "id": "root",
                    "name": "My Drive",
                    "mimeType": FOLDER_MIME,
                    "parents": [],
                }
            else:
                try:
                    current = drive.get_file(folder_id, fields=OWNER_FIELDS)
                except DriveNotFoundError:
                    raise InvalidInputError("folder not found in your Drive") from None
                if current.get("mimeType") != FOLDER_MIME:
                    raise InvalidInputError("that is not a folder")
            node: dict[str, Any] | None = current
            seen: set[str] = set()
            while node is not None and len(crumbs) < MAX_BREADCRUMBS:
                nid = str(node["id"])
                if nid in seen:
                    break
                seen.add(nid)
                name = "My Drive" if nid == root_id or nid == "root" else str(node.get("name", ""))
                crumbs.insert(0, {"id": "root" if nid == root_id else nid, "name": name})
                if covered_by is None and nid in entries:
                    covered_by = name
                parents = node.get("parents") or []
                if nid == root_id or nid == "root" or not parents:
                    break
                try:
                    node = drive.get_file(str(parents[0]), fields=OWNER_FIELDS)
                except DriveNotFoundError:
                    node = None
            if folder_id == "root":
                query = "'root' in parents and trashed=false"
            else:
                query = f"{parents_clause([folder_id])} and trashed=false"
            resp = drive.list_files(
                query, fields=OWNER_FIELDS, page_size=BROWSE_PAGE_SIZE, page_token=page_token
            )
            items = resp.get("files", [])
            # Drive's parents filter can echo a file that merely mentions the folder.
            # The alias "root" is not the id Drive returns on a file, so it cannot be
            # used for that check.
            if folder_id != "root":
                items = [i for i in items if folder_id in (i.get("parents") or [])]
            next_token = resp.get("nextPageToken")
        items.sort(key=lambda i: (i.get("mimeType") != FOLDER_MIME, str(i.get("name", "")).lower()))
        rows = []
        for item in items:
            iid = str(item["id"])
            mime = str(item.get("mimeType", ""))
            rows.append(
                {
                    "id": iid,
                    "name": str(item.get("name", "")),
                    "is_folder": mime == FOLDER_MIME,
                    "is_shortcut": mime == SHORTCUT_MIME,
                    "kind": describe_mime(mime),
                    "link": item.get("webViewLink"),
                    "granted": iid in entries,
                    "covered": covered_by is not None and iid not in entries,
                }
            )
        return {
            "rows": rows,
            "crumbs": crumbs,
            "covered_by": covered_by,
            "current": current,
            "current_granted": current is not None and str(current["id"]) in entries,
            "is_root": current is not None
            and (
                str(current["id"]) == root_id
                or (root_id is None and str(current["id"]) == "root")
            ),
            "next_token": next_token,
            "drive_error": False,
        }

    async def browse(request: Request) -> Response:
        folder = request.query_params.get("folder") or "root"
        q = (request.query_params.get("q") or "").strip()[:200] or None
        page_token = normalize_page_token(request.query_params.get("page"))
        prev = [
            token
            for token in (
                normalize_page_token(item) for item in request.query_params.getlist("prev")
            )
            if token
        ]
        request_id = request.query_params.get("request") or None
        picking = None
        if request_id:
            picking = await blocking(ctx.requests.get, request_id)
            if picking is None or picking.status != PENDING:
                picking = None
        try:
            data = await blocking(browse_data, folder, q, page_token)
        except (InvalidInputError, OwnerNotConnectedError):
            raise
        except Exception as exc:
            # The picker has to stay on the page. A Drive failure used to replace the
            # whole screen, which also removed the only way to approve a file.
            report_exception(exc, where="browse")
            data = {
                "rows": [],
                "crumbs": [{"id": "root", "name": "My Drive"}],
                "covered_by": None,
                "current": {"id": "root", "name": "My Drive", "mimeType": FOLDER_MIME},
                "current_granted": False,
                "is_root": True,
                "next_token": None,
                "drive_error": True,
            }
        here = request.url.path + ("?" + request.url.query if request.url.query else "")
        pager = browse_pager(
            folder,
            q=q,
            request_id=picking.id if picking else None,
            page=page_token,
            prev=prev,
            next_token=data.get("next_token"),
        )
        return render(
            request,
            "browse.html",
            q=q,
            folder=folder,
            picking=picking,
            here=here,
            picker_ready=settings.picker_configured,
            **pager,
            **data,
        )

    async def picker_session(request: Request) -> Response:
        if not settings.picker_configured:
            return JSONResponse({"error": "picker_not_configured"}, status_code=404)
        record = await blocking(ctx.vault.owner)
        if not record or not record.get("t"):
            return JSONResponse({"error": "sign_in_required"}, status_code=401)
        assert settings.google_oauth_client_id is not None
        assert settings.google_oauth_client_secret is not None
        try:
            token = await blocking(
                refresh_access_token,
                settings.google_oauth_client_id.get_secret_value(),
                settings.google_oauth_client_secret.get_secret_value(),
                record["t"],
            )
        except OAuthError as exc:
            logger.warning("picker token refresh failed")
            return JSONResponse({"error": str(exc)}, status_code=502)
        return JSONResponse(
            {
                "access_token": token,
                "api_key": settings.google_picker_api_key,
                "app_id": settings.google_cloud_project_number,
            }
        )

    async def grant(request: Request, form: dict[str, str]) -> Response:
        file_id = validate_drive_id(form.get("file_id"))
        try:
            entry = await blocking(ctx.grants().grant, file_id)
            flash(request, "ok", f"Allowed \u201c{entry.name}\u201d for the assistant.")
        except GrantError as exc:
            flash(request, "error", str(exc))
        return RedirectResponse(safe_next(form.get("next")), status_code=303)

    async def revoke(request: Request, form: dict[str, str]) -> Response:
        file_id = validate_drive_id(form.get("file_id"))
        try:
            await blocking(ctx.grants().revoke, file_id)
            flash(request, "ok", "Removed. The assistant can no longer use it.")
        except GrantError as exc:
            flash(request, "error", str(exc))
        return RedirectResponse(safe_next(form.get("next")), status_code=303)

    async def access(request: Request) -> Response:
        def gather() -> dict[str, Any]:
            return {"entries": ctx.allowlist.entries(), "bot": ctx.bot_status()}

        data = await blocking(gather)
        rows = sorted(data["entries"].values(), key=lambda e: e.granted_at, reverse=True)
        return render(
            request,
            "access.html",
            rows=rows,
            root_folder_id=ctx.visible_root_folder_id(),
            describe_mime=describe_mime,
            bot=data["bot"],
        )

    async def requests_page(request: Request) -> Response:
        reqs = await blocking(ctx.requests.recent, 100)
        pending = [r for r in reqs if r.status == PENDING]
        decided = [r for r in reqs if r.status != PENDING]
        return render(request, "requests.html", pending=pending, decided=decided)

    async def request_detail(request: Request) -> Response:
        rid = request.path_params["rid"]
        req = await blocking(ctx.requests.get, rid)
        if req is None:
            return render(request, "error.html", 404, message="Request not found or expired.")
        options = []
        owner_meta = None
        drive_error = False
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
        return render(
            request,
            "request.html",
            req=req,
            options=options,
            owner_meta=owner_meta,
            drive_error=drive_error,
            picker_ready=settings.picker_configured,
            describe_mime=describe_mime,
        )

    async def request_approve(request: Request, form: dict[str, str]) -> Response:
        rid = request.path_params["rid"]
        req = await blocking(ctx.requests.get, rid)
        if req is None:
            return render(request, "error.html", 404, message="Request not found or expired.")
        target = form.get("target_id") or req.file_id
        if not target:
            flash(request, "error", "Pick an item to share first.")
            return RedirectResponse(f"/browse?request={quote(req.id)}", status_code=303)
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
            return render(request, "error.html", 404, message="Request not found or expired.")
        try:
            await blocking(ctx.grants().deny, req)
            flash(request, "ok", "Request denied.")
        except GrantError as exc:
            flash(request, "error", str(exc))
        return RedirectResponse(f"/requests/{quote(req.id)}", status_code=303)

    async def activity(request: Request) -> Response:
        records = await blocking(ctx.activity.recent)
        return render(request, "activity.html", records=records)

    async def not_found(request: Request) -> Response:
        return render(request, "error.html", 404, message="Page not found.")

    async def admin_page(request: Request) -> Response:
        email = session_user(request)
        if email != settings.owner_email:
            return render(request, "error.html", 404, message="Page not found.")
        reset = current_actor.set(email)
        try:
            await remember_pending(request)
            people = await blocking(_directory_rows)
        finally:
            current_actor.reset(reset)
        return render(request, "admin.html", people=people)

    def _directory_rows() -> list[dict[str, Any]]:
        if ctx.directory is None:
            return []
        rows: list[dict[str, Any]] = []
        for person in ctx.directory.known_users():
            grants = ctx.mcp_oauth.list_grants(person) if ctx.mcp_oauth else []
            rows.append(
                {
                    "email": person,
                    "created_at": ctx.directory.created_at(person),
                    "grants": grants,
                }
            )
        return rows

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
            request.session["mcp_auth"] = pending.to_dict()
            await remember_pending(request)
            return render(
                request,
                "consent.html",
                client_name=pending.client_name,
                scope=SCOPE,
                requested_scope=pending.requested_scope,
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
                audit_owner("oauth_approve", client=pending.client_name)
                target = ctx.mcp_oauth.approve(str(request.session.get("owner")), pending)
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

    async def bridge_page(request: Request) -> Response:
        if ctx.mailbox is None:
            return render(request, "error.html", 404, message="The mailbox is not configured.")
        email = str(request.session.get("owner") or "")
        data = await blocking(ctx.mailbox.list_links, email)
        data["webhook"] = await blocking(ctx.mailbox.get_webhook, email)
        return render(request, "bridge.html", **data)

    def _bridge_act(request: Request, link_id: str, action: str, purge: bool = False) -> str:
        email = str(request.session.get("owner") or "")
        if action == "revoke":
            ctx.mailbox.revoke(email, link_id, purge)
            return "Pairing revoked. Both assistants have lost send and receive."
        result = ctx.mailbox.decide(email, link_id, action)
        if action == "deny" or result["status"] == "revoked":
            return "Pairing denied. Neither assistant can send on it."
        if result["status"] == "active":
            return "You approved. The mailbox is on."
        return "You approved. The mailbox stays off until the other person approves."

    async def bridge_decide(request: Request, form: dict[str, str]) -> Response:
        if ctx.mailbox is None:
            return render(request, "error.html", 404, message="The mailbox is not configured.")
        link_id = request.path_params["link_id"]
        action = request.path_params["action"]
        if action not in ("approve", "deny", "revoke"):
            return render(request, "error.html", 404, message="That page is not available.")
        purge = form.get("purge") == "on"
        try:
            message = await blocking(_bridge_act, request, link_id, action, purge)
        except MailboxError as exc:
            flash(request, "error", exc.message)
        else:
            flash(request, "ok", message)
        return RedirectResponse("/bridge", status_code=303)

    async def bridge_webhook(request: Request, form: dict[str, str]) -> Response:
        if ctx.mailbox is None:
            return render(request, "error.html", 404, message="The mailbox is not configured.")
        email = str(request.session.get("owner") or "")
        try:
            if form.get("action") == "remove":
                await blocking(ctx.mailbox.clear_webhook, email)
                flash(request, "ok", "Wake-up removed. Mail still waits for check_messages.")
            else:
                enabled = form.get("enabled", "true") != "false"
                await blocking(
                    ctx.mailbox.set_webhook,
                    email,
                    form.get("url") or "",
                    sender_key=form.get("sender_key") or None,
                    auth_scheme=form.get("auth_scheme") or "bearer",
                    enabled=enabled,
                )
                flash(request, "ok", "Wake-up saved. The key is not shown again.")
        except MailboxError as exc:
            flash(request, "error", exc.message)
        return RedirectResponse("/bridge", status_code=303)

    async def revoke_oauth_grant(request: Request, form: dict[str, str]) -> Response:
        grant_id = form.get("grant_id") or ""
        if ctx.mcp_oauth is None or not await blocking(
            ctx.mcp_oauth.revoke, grant_id, email=str(request.session.get("owner") or "")
        ):
            flash(request, "error", "That connection was not found.")
        else:
            audit_owner("oauth_revoke")
            flash(request, "ok", "Disconnected the app. Its tokens no longer work.")
        return RedirectResponse("/", status_code=303)

    async def confirm_js(_: Request) -> Response:
        return Response(
            b"document.addEventListener('submit',function(e){"
            b"var f=e.target;if(!f||!f.getAttribute)return;"
            b"var m=f.getAttribute('data-confirm');"
            b"if(m&&!window.confirm(m))e.preventDefault();});",
            media_type="text/javascript",
            headers={"cache-control": "no-store"},
        )

    routes = [
        Route("/confirm.js", confirm_js, methods=["GET"]),
        Route("/login", login, methods=["GET"]),
        Route("/auth/login", auth_login, methods=["GET"]),
        Route("/auth/callback", auth_callback, methods=["GET"]),
        Route("/connect", owner_only(connect_page), methods=["GET"]),
        Route("/connect/{key}", csrf_protected(connect_start), methods=["POST"]),
        Route("/connect/{key}/disconnect", csrf_protected(connect_remove), methods=["POST"]),
        Route("/logout", csrf_protected(logout), methods=["POST"]),
        Route("/", home, methods=["GET"]),
        Route("/browse", owner_only(browse), methods=["GET"]),
        Route("/picker/session", owner_only(picker_session), methods=["GET"]),
        Route("/grant", csrf_protected(grant), methods=["POST"]),
        Route("/revoke", csrf_protected(revoke), methods=["POST"]),
        Route("/access", owner_only(access), methods=["GET"]),
        Route("/requests", owner_only(requests_page), methods=["GET"]),
        Route("/requests/{rid}", owner_only(request_detail), methods=["GET"]),
        Route("/requests/{rid}/approve", csrf_protected(request_approve), methods=["POST"]),
        Route("/requests/{rid}/deny", csrf_protected(request_deny), methods=["POST"]),
        Route("/activity", owner_only(activity), methods=["GET"]),
        Route("/bridge", owner_only(bridge_page), methods=["GET"]),
        Route("/bridge/webhook", csrf_protected(bridge_webhook), methods=["POST"]),
        Route("/bridge/{link_id}/{action}", csrf_protected(bridge_decide), methods=["POST"]),
        Route("/admin", admin_page, methods=["GET"]),
        Route("/oauth/authorize", oauth_authorize, methods=["GET"]),
        Route("/oauth/authorize", csrf_protected(oauth_decide), methods=["POST"]),
        Route("/oauth/continue", owner_only(oauth_continue), methods=["GET"]),
        Route("/oauth/grants/revoke", csrf_protected(revoke_oauth_grant), methods=["POST"]),
        *legal_routes(),
        Route("/{path:path}", owner_only(not_found), methods=["GET"]),
    ]
    app = Starlette(
        routes=routes,
        middleware=[
            Middleware(SecurityHeadersMiddleware),
            Middleware(
                SessionMiddleware,
                secret_key=settings.session_secret.get_secret_value(),
                session_cookie=SESSION_COOKIE,
                max_age=SESSION_MAX_AGE,
                same_site="lax",
                https_only=settings.secure_cookies,
            ),
        ],
    )
    app.state.owner_email = settings.owner_email
    # Mount("/") serves this app, so request.app is this app, not the outer one.
    app.state.dashboard = ctx
    return app


def normalize_page_token(value: str | None) -> str | None:
    """Keep an opaque Drive page token.

    Google's tokens are not a fixed alphabet (`~`, `!`, `*`, `|` all show up).
    Drop only blank, huge, or control-character values so a real Next link
    still addresses the same page.
    """
    if not value or len(value) > 1024:
        return None
    if any(ord(ch) < 33 or ord(ch) == 127 for ch in value):
        return None
    return value


def browse_href(
    folder: str,
    *,
    q: str | None,
    request_id: str | None,
    page: str | None,
    prev: list[str],
) -> str:
    pairs: list[tuple[str, str]] = []
    if q:
        pairs.append(("q", q))
    else:
        pairs.append(("folder", folder or "root"))
        if page:
            pairs.append(("page", page))
        for item in prev:
            pairs.append(("prev", item))
    if request_id:
        pairs.append(("request", request_id))
    return "/browse?" + urlencode(pairs)


def browse_pager(
    folder: str,
    *,
    q: str | None,
    request_id: str | None,
    page: str | None,
    prev: list[str],
    next_token: str | None,
) -> dict[str, str | None]:
    """Previous/Next links. Drive tokens are not reversible, so the previous stack is in the URL."""
    prev_href = None
    if page and not q:
        if prev:
            prev_href = browse_href(
                folder, q=None, request_id=request_id, page=prev[-1], prev=prev[:-1]
            )
        else:
            prev_href = browse_href(folder, q=None, request_id=request_id, page=None, prev=[])
    next_href = None
    if next_token and not q:
        nxt_prev = [*prev, page] if page else list(prev)
        next_href = browse_href(
            folder, q=None, request_id=request_id, page=next_token, prev=nxt_prev
        )
    return {"prev_href": prev_href, "next_href": next_href}


def request_headline(req: Any, owner_meta: dict[str, Any] | None = None) -> str:
    """Plain-language summary of an access request. Technical fields stay out of this sentence."""
    who = str(getattr(req, "token_name", None) or "").strip() or "An assistant"
    name = None
    if owner_meta and owner_meta.get("name"):
        name = str(owner_meta["name"])
    elif getattr(req, "file_name", None):
        name = str(req.file_name)
    elif getattr(req, "description", None):
        name = str(req.description)
    item = name or "something in your Drive"
    tool = str(getattr(req, "tool", "") or "")
    sentences = {
        "read_file": f"{who} wants to read {item}.",
        "get_metadata": f"{who} wants to see the details of {item}.",
        "list_folder": f"{who} wants to list {item}.",
        "search_files": f"{who} wants to search your Drive.",
        "create_folder": f"{who} wants to create a folder in {item}.",
        "create_doc": f"{who} wants to create a document in {item}.",
        "upload_file": f"{who} wants to upload a file in {item}.",
        "update_file_content": f"{who} wants to edit {item}.",
        "rename_file": f"{who} wants to rename {item}.",
        "trash_file": f"{who} wants to move {item} to trash.",
        "request_access": f"{who} is asking to use {item}.",
    }
    return sentences.get(tool, f"{who} wants to use {item}.")


def status_label(status: str | None) -> str:
    if not status:
        return ""
    labels = {
        "pending": "Waiting for you",
        "approved": "Approved",
        "denied": "Denied",
        "allow": "Allowed",
        "deny": "Denied",
        "error": "Error",
    }
    return labels.get(status, status.replace("_", " "))


def tool_label(tool: str) -> str:
    return {
        "read_file": "Read a file",
        "get_metadata": "See file details",
        "list_folder": "List a folder",
        "search_files": "Search",
        "create_folder": "Create a folder",
        "create_doc": "Create a document",
        "upload_file": "Upload a file",
        "update_file_content": "Edit a file",
        "rename_file": "Rename a file",
        "trash_file": "Move to trash",
        "request_access": "Ask for access",
    }.get(tool, "Use a file")


def describe_mime(mime: str) -> str:
    known = {
        FOLDER_MIME: "Folder",
        SHORTCUT_MIME: "Shortcut",
        "application/vnd.google-apps.document": "Google Doc",
        "application/vnd.google-apps.spreadsheet": "Google Sheet",
        "application/vnd.google-apps.presentation": "Google Slides",
        "application/pdf": "PDF",
    }
    if mime in known:
        return known[mime]
    if mime.startswith("image/"):
        return "Image"
    if mime.startswith("text/"):
        return "Text"
    return mime.rsplit("/", 1)[-1] or "File"


_env.globals["request_headline"] = request_headline
_env.globals["status_label"] = status_label
_env.globals["tool_label"] = tool_label
_env.globals["describe_mime"] = describe_mime

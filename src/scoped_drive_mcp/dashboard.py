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

This module holds the shared pieces (context, rendering, the session and CSRF wrappers)
and `build_dashboard`, which owns the route table. The handlers are in `pages/`, one
module per group of routes; each gets the helpers it needs as a `Kit` (pages/kit.py).
"""

import functools
import hashlib
import hmac
import logging
import os
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import anyio
import anyio.to_thread
from itsdangerous import URLSafeTimedSerializer
from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .access import AccessRequests
from .audit import audit_owner
from .auth import current_actor
from .config import Settings
from .connections import CONNECTIONS, NOTION_WITH_CREATE
from .drive_client import (
    BotNotConnectedError,
    DriveAccessError,
    DriveNotFoundError,
    LazyBotDriveClient,
    OwnerDriveClient,
)
from .drop_storage import BLOB_API_HOST, BLOB_API_PATH
from .errors import report_exception
from .grants import GrantError, GrantService
from .humanize import assistant_label, when
from .mcp_oauth import McpOAuth
from .oauth import OAuthClient, refresh_access_token
from .pages.admin import admin_pages

# These moved to pages/common.py. Some are used below; the rest (attachment_disposition,
# browse_href, fetch_parents, normalize_page_token) only stay importable from here.
from .pages.common import (  # noqa: F401
    DROP_FORM_OVERHEAD,
    DROP_PIECE_LIMIT,
    DROP_UPLOAD_LIMIT,
    ROLE_LABELS,
    SESSION_MAX_AGE,
    OwnerNotConnectedError,
    _end_of_day,
    attachment_disposition,
    browse_href,
    describe_mime,
    fetch_parents,
    icon_kind,
    normalize_page_token,
    shared_href,
)
from .pages.connections import connection_pages
from .pages.consent import consent_pages
from .pages.drops import drop_pages
from .pages.files import file_pages
from .pages.kit import Handler, Kit
from .pages.requests import request_pages
from .pages.settings import settings_pages
from .pages.sharing import sharing_pages
from .pages.signin import signin_pages
from .peer_request_pages import Kit as PeerRequestKit
from .peer_request_pages import page_routes as peer_request_routes
from .peer_requests import PeerRequestService
from .scope import InvalidInputError
from .store import AUDIENCE_LINKED, ActivityLog, Allowlist, TokenVault
from .terminal.feature import Kit as TerminalKit
from .terminal.feature import epoch_iso

logger = logging.getLogger(__name__)

SESSION_COOKIE = "sdm_session"
STATE_SALT = "sdm-oauth-state"
BROWSE_PAGE_SIZE = 200

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def observability_on() -> bool:
    """Vercel Speed Insights and Web Analytics: on when running on Vercel, unless
    VERCEL_OBSERVABILITY is set to off. Their scripts are served by Vercel itself from
    /_vercel/..., on this site's own origin, so the CSP needs no new host."""
    if not os.environ.get("VERCEL", "").strip():
        return False
    flag = os.environ.get("VERCEL_OBSERVABILITY", "on").strip().lower()
    return flag not in {"0", "off", "false", "no"}


_env.globals["observability_on"] = observability_on
_env.globals["asset_url"] = lambda name: asset_url(name)

# Connect Notion posts a form that redirects to Notion's consent screen, which may pass
# through Notion's sign-in. form-action is checked along that redirect chain.
NOTION_FORM_HOSTS = b"https://api.notion.com https://www.notion.so https://app.notion.com"
# Connect OneDrive does the same with Microsoft's sign-in (personal accounts pass through
# login.live.com).
MICROSOFT_FORM_HOSTS = b"https://login.microsoftonline.com https://login.live.com"

# Every page: scripts and everything else only from this site. Sign-in forms redirect to
# Google, which form-action checks along the redirect chain. frame-ancestors stays none
# so this site is not embedded.
STRICT_CSP = (
    b"default-src 'self'; "
    b"script-src 'self'; "
    b"style-src 'self' 'unsafe-inline'; "
    b"img-src 'self' data:; "
    b"connect-src 'self'; "
    b"frame-src 'none'; "
    b"worker-src 'self'; "
    b"form-action 'self' https://accounts.google.com "
    + NOTION_FORM_HOSTS
    + b" "
    + MICROSOFT_FORM_HOSTS
    + b"; "
    b"frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
)
# Only pages that can open the Google Picker (PICKER_TEMPLATES): it loads api.js from
# apis.google.com (that script evaluates code), then opens Drive in a frame.
PICKER_CSP = (
    b"default-src 'self'; "
    b"script-src 'self' https://apis.google.com https://www.gstatic.com 'unsafe-eval'; "
    b"style-src 'self' 'unsafe-inline'; "
    b"img-src 'self' data: https://*.googleusercontent.com https://*.gstatic.com; "
    b"connect-src 'self' https://www.googleapis.com https://content.googleapis.com; "
    b"frame-src https://docs.google.com https://drive.google.com https://accounts.google.com "
    b"https://content.googleapis.com https://*.google.com https://*.googleusercontent.com; "
    b"worker-src 'self' blob:; "
    b"form-action 'self' https://accounts.google.com; "
    b"frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
)
# Sharing → Shared with me when the browser sends and fetches held files straight to and
# from Vercel Blob (drop_storage.BlobSigner): uploads go to the Blob API (that path only),
# downloads come from this deployment's own private store. Same as STRICT_CSP otherwise.
_CONNECT_SELF = b"connect-src 'self'; "
# The replace below must match, or the page would block its own uploads silently.
assert _CONNECT_SELF in STRICT_CSP, "STRICT_CSP lost its connect-src 'self'"


def direct_drop_csp(store_host: str) -> str:
    """`store_host` is the connected store's own host: no other store is allowed."""
    connect = f"https://{BLOB_API_HOST}{BLOB_API_PATH} https://{store_host}".encode()
    return STRICT_CSP.replace(_CONNECT_SELF, b"connect-src 'self' " + connect + b"; ").decode()


# Templates with a picker button (#pick-drive or [data-pick]). They get PICKER_CSP when
# the picker is configured (render's `picker_ready`); every other response gets STRICT_CSP.
PICKER_TEMPLATES = frozenset({"browse.html", "access.html", "request.html"})

SECURITY_HEADERS = [
    (b"x-frame-options", b"DENY"),
    (b"x-content-type-options", b"nosniff"),
    # Other sites get only this site's origin, never a path (so ids in URLs such as
    # /requests/<id> stay here), and nothing over a downgrade to http. Google needs
    # that origin: a Picker API key restricted to this website is checked against the
    # Referer, and `same-origin` sent none, so Google rejected the key.
    # `no-referrer` would also break forms: browsers then send `Origin: null` on HTML
    # form POSTs, which check_csrf rejects (Sign out would fail).
    (b"referrer-policy", b"strict-origin-when-cross-origin"),
    (b"cache-control", b"no-store"),
    # A response that already carries a policy (a Picker page) keeps it.
    (b"content-security-policy", STRICT_CSP),
]

# Searches per person per minute on "Shared with me". Each one reads every sharer's Drive.
SHARED_SEARCH_LIMIT = 20
# Folder lookups one Files page may make to work out search-result paths and
# folder-inherited access. Past this, the remaining rows say to open their folder.
SEARCH_LOOKUPS = 40


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
    # This person's named roles (agent_roles.py). None hides the Roles section.
    agent_roles: Any = None
    # The list other people's assistants may read (external.py). None disables Sharing.
    ext_allowlist: Allowlist | None = None
    on_ext_change: Callable[[], None] = lambda: None
    # What paired people share with this person, across every source (shared_sources.py).
    # None hides the "Shared with me" pages.
    shared_with_me: Any = None
    # (caller email, file id) -> the paired person whose Sharing list covers that id,
    # including files inside a shared folder (ExternalShares.sharer_of).
    sharer_of: Callable[[str, str], str | None] | None = None
    # The first read by each paired person's assistant, shown on Overview.
    first_reads: Any = None
    # Items removed from Bot RBAC on Files (store.HiddenFiles). None keeps every item listed.
    hidden: Any = None
    # Notion (notion.NotionService), when its OAuth client is configured. None hides it.
    notion: Any = None
    # NOTION_ALLOW_CREATE: assistants that may edit can add Notion pages. Changes only
    # what the pages say about Notion; the tool itself is registered in tools/notion.py.
    notion_create: bool = False
    # OneDrive (onedrive.OneDriveService), when its OAuth client is configured.
    onedrive: Any = None
    # Files paired people send this person (drops.DropBox). None hides sending.
    drops: Any = None
    # Bot RBAC Terminal (terminal.TerminalFeature): roles for agents on people's own
    # computers. None leaves its pages out (tests that build a bare context).
    terminal: Any = None
    _owner_clients: dict[str, tuple[str, OwnerDriveClient]] = field(
        default_factory=dict, repr=False
    )
    # actor -> (refresh token, My Drive's folder id). The id never changes for an account,
    # so Files asks Drive once per connection instead of on every page load.
    _owner_roots: dict[str, tuple[str, str]] = field(default_factory=dict, repr=False)

    def _admin_actor(self) -> bool:
        actor = current_actor.get()
        return not actor or actor == self.settings.owner_email

    def owner_drive(self) -> OwnerDriveClient:
        return self.owner_drive_and_token()[0]

    def owner_drive_and_token(self) -> tuple[OwnerDriveClient, str]:
        """The signed-in person's Drive client and the refresh token it was built from."""
        record = self.vault.owner()
        if not record or not record.get("t"):
            raise OwnerNotConnectedError
        token = record["t"]
        actor = current_actor.get() or ""
        cached = self._owner_clients.get(actor)
        if cached is None or cached[0] != token:
            self._owner_clients[actor] = (token, self.owner_drive_factory(token))
        return self._owner_clients[actor][1], token

    def owner_root_id(self, drive: OwnerDriveClient, token: str) -> str | None:
        """My Drive's folder id for the signed-in person, or None while drive.file cannot
        open it yet (not cached then, so it shows up once the app may open My Drive).
        Pass what owner_drive_and_token() returned. The cache is keyed by the token, so a
        new connection (reconsent, another account) looks it up again."""
        actor = current_actor.get() or ""
        cached = self._owner_roots.get(actor)
        if cached is not None and cached[0] == token:
            return cached[1]
        try:
            root_id = str(drive.get_file("root", fields="id")["id"])
        except DriveNotFoundError:
            return None
        self._owner_roots[actor] = (token, root_id)
        return root_id

    def grants(self) -> GrantService:
        return GrantService(
            self.owner_drive,
            self.allowlist,
            self.requests,
            on_change=self.on_allowlist_change,
        )

    def ext_grants(self) -> GrantService:
        """Grant and revoke on the external list. Same checks as the own-bot list (the item
        must be in this person's Drive, not trashed, not My Drive's root; a shortcut adds
        its target). No Drive permission is created."""
        if self.ext_allowlist is None:
            raise GrantError("Sharing is not set up on this server.")
        return GrantService(
            self.owner_drive,
            self.ext_allowlist,
            self.requests,
            on_change=self.on_ext_change,
            audience=AUDIENCE_LINKED,
            audit_actions=("share_external", "unshare_external"),
        )

    def ext_ids(self) -> set[str]:
        return set(self.ext_allowlist.entries()) if self.ext_allowlist is not None else set()

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

    def notion_record(self) -> dict[str, str] | None:
        """This person's stored Notion connection, when Notion is offered here."""
        if self.notion is None or not self.vault.enabled:
            return None
        return self.vault.notion()

    def onedrive_record(self) -> dict[str, str] | None:
        """This person's stored OneDrive connection, when OneDrive is offered here."""
        if self.onedrive is None or not self.vault.enabled:
            return None
        return self.vault.onedrive()

    def connection_rows(self) -> list[dict[str, Any]]:
        """Each connection offered here and whether this person has finished it."""
        rows = []
        for conn in CONNECTIONS.values():
            detail = None
            if conn.provider == "notion":
                if self.notion is None:
                    continue
                record = self.notion_record()
                connected = record is not None
                if record and record.get("workspace_name"):
                    detail = f"Workspace: {record['workspace_name']}"
                needs_upgrade = False
                if self.notion_create:
                    conn = NOTION_WITH_CREATE
            elif conn.provider == "microsoft":
                if self.onedrive is None:
                    continue
                record = self.onedrive_record()
                connected = record is not None
                if record and record.get("account"):
                    detail = f"Account: {record['account']}"
                needs_upgrade = False
            else:
                connected = self.drive_connected()
                # An older full-Drive (or unstamped) token is no longer used: the person
                # is not connected until they reconnect, which revokes it first.
                needs_upgrade = not connected and self.reconsent_needed()
            rows.append(
                {
                    "connection": conn,
                    "connected": connected,
                    "needs_upgrade": needs_upgrade,
                    "detail": detail,
                }
            )
        return rows

    def disconnect_drive(self) -> str | None:
        """Forget this person's Drive token, current or old. Returns it so Google can
        revoke it."""
        if not self.vault.enabled:
            self.vault.clear_owner()
            return None
        record = self.vault.owner() or self.vault.legacy_owner()
        token = record.get("t") if record else None
        self.vault.clear_owner()
        return token

    def revoke_legacy_drive(self, revoke: Callable[[str], bool]) -> bool | None:
        """Revoke an old full-Drive (or unstamped) token at Google, then delete it here.

        None when there is none. False when Google did not confirm: the token is kept so
        a later reconnect or the admin action can try again (it is never used meanwhile).
        A current drive.file token is left alone."""
        if not self.vault.enabled:
            return None
        record = self.vault.legacy_owner()
        if not record:
            return None
        if not revoke(record["t"]):
            return False
        # Only delete what was revoked: a reconnect may have stored a new token since.
        current = self.vault.legacy_owner()
        if current and current.get("t") == record["t"]:
            self.vault.clear_owner()
        return True

    def reconsent_needed(self) -> bool:
        """True when an old sign-in is stored that this server no longer uses.

        That is a full-Drive token, or one saved before scopes were recorded. It is not
        used for anything; the person reconnects with per-file access, which revokes it.
        """
        if not self.vault.enabled:
            return False
        return self.vault.legacy_owner() is not None


_GOOGLE_MODULES = ("googleapiclient", "google.auth", "google.oauth2", "httplib2")


def is_drive_failure(exc: BaseException) -> bool:
    """Whether an unexpected error came from talking to Google, as opposed to the store or
    a bug in this app. The store's clients wrap their network errors in their own types,
    so a bare OSError (a timeout, a reset, a TLS failure) is the Drive client's."""
    if isinstance(exc, DriveNotFoundError | DriveAccessError | BotNotConnectedError | OSError):
        return True
    module = type(exc).__module__ or ""
    return any(module == name or module.startswith(name + ".") for name in _GOOGLE_MODULES)


async def blocking[T](fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    return await anyio.to_thread.run_sync(partial(fn, *args, **kwargs))


def safe_next(value: str | None) -> str:
    """A same-site path, else "/". Browsers drop tabs and newlines from a URL, so
    "/\t/evil.example" in a link would become "//evil.example"; refuse those too."""
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value:
        return "/"
    if any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in value):
        return "/"
    return value


def origin_of(url: str) -> str:
    scheme, _, rest = url.partition("://")
    return f"{scheme}://{rest.split('/', 1)[0]}"


# Two years, the value browsers' preload lists expect. Only sent over HTTPS deployments.
HSTS_HEADER = (b"strict-transport-security", b"max-age=63072000; includeSubDomains")


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp, *, hsts: bool = False):
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                # Pages are never cached. A static asset sets its own policy and keeps it.
                # A header that is already there stays as it is, so wrapping both the
                # dashboard and the app around it does not send anything twice.
                present = {key.lower() for key, _ in headers}
                headers += [item for item in SECURITY_HEADERS if item[0] not in present]
                if self.hsts and HSTS_HEADER[0] not in present:
                    headers.append(HSTS_HEADER)
                message["headers"] = headers
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


def wants_json(request: Request) -> bool:
    """True when ui.js submitted a row action in the background (Accept: application/json)."""
    return "application/json" in request.headers.get("accept", "")


def action_done(
    request: Request,
    kind: str,
    message: str,
    next_url: str,
    *,
    changed: bool | None = None,
    extra: dict[str, Any] | None = None,
) -> Response:
    """Finish a dashboard action that changes one row.

    ui.js sends these in the background and updates only the affected row, so it gets
    JSON back. A plain form POST (no JavaScript) still gets a flash and a redirect.
    `changed` says whether the row's state changed. It defaults to success, but a revoke
    can remove the item from the list and still report a Drive error. `extra` adds fields
    to the JSON answer only, such as a new count for a tab label on the page.
    """
    if wants_json(request):
        return JSONResponse(
            {
                "ok": kind == "ok",
                "kind": kind,
                "message": message,
                "changed": (kind == "ok") if changed is None else changed,
                **(extra or {}),
            },
            status_code=200 if kind == "ok" else 400,
        )
    flash(request, kind, message)
    return RedirectResponse(next_url, status_code=303)


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
    ctx.setdefault("mailbox_count", getattr(request.state, "mailbox_count", 0))
    ctx.setdefault("allow_count", getattr(request.state, "allow_count", None))
    ctx.setdefault("notion_tab", getattr(request.state, "notion_tab", False))
    ctx.setdefault("onedrive_tab", getattr(request.state, "onedrive_tab", False))
    ctx.setdefault("terminal_tab", getattr(request.app.state, "terminal_tab", False))
    ctx.setdefault("notion_create", getattr(request.app.state, "notion_create", False))
    html = _env.get_template(template).render(
        request=request,
        owner=owner,
        is_admin=bool(owner and admin_email and owner == admin_email),
        csrf=_csrf_token(request) if owner else None,
        flashes=request.session.pop("flash", []) if owner else [],
        nav=request.url.path,
        pending_count=pending_count,
        reconsent=reconsent,
        status_code=status_code,
        **ctx,
    )
    response = HTMLResponse(html, status_code=status_code)
    if template in PICKER_TEMPLATES and ctx.get("picker_ready"):
        response.headers["content-security-policy"] = PICKER_CSP.decode()
    elif template == "shared.html" and ctx.get("drops_store_host"):
        response.headers["content-security-policy"] = direct_drop_csp(ctx["drops_store_host"])
    return response


def render_plain(template: str, status_code: int = 200, **ctx: Any) -> HTMLResponse:
    html = _env.get_template(template).render(
        owner=None, csrf=None, flashes=[], nav="", reconsent=False, pending_count=0, **ctx
    )
    return HTMLResponse(html, status_code=status_code)


async def terms_page(_: Request) -> Response:
    return render_plain("terms.html")


async def privacy_page(request: Request) -> Response:
    return render_plain(
        "privacy.html", notion_create=getattr(request.app.state, "notion_create", False)
    )


@functools.lru_cache(maxsize=16)
def _asset(name: str) -> tuple[bytes, str]:
    data = (TEMPLATES_DIR / name).read_bytes()
    return data, '"' + hashlib.sha256(data).hexdigest()[:32] + '"'


# A page links its CSS and JS as /app.css?v=<hash of the file>. That URL can only ever
# mean those bytes, so the browser keeps it for a year without asking again, and the CDN
# (s-maxage) answers for it without starting the function.
IMMUTABLE = "public, max-age=31536000, s-maxage=31536000, immutable"
# Fonts never change under the same name.
FONT_CACHE = "public, max-age=2592000, s-maxage=2592000"


def _version(etag: str) -> str:
    return etag.strip('"')[:16]


def asset_url(name: str) -> str:
    """The versioned URL for a bundled CSS or JS file (a Jinja global)."""
    if name == CONFIRM_JS_NAME:
        return f"/{name}?v={_version(CONFIRM_JS_ETAG)}"
    return f"/{name}?v={_version(_asset(name)[1])}"


def _bytes_response(
    request: Request, data: bytes, etag: str, media: str, cache: str = "no-cache"
) -> Response:
    """A bundled asset. Asked for by its versioned URL it is immutable. Asked for any
    other way (no `v`, or the `v` of another deployment) it is `no-cache`: the browser may
    keep it but revalidates with the ETag, so it never shows one deployment's page with
    another's CSS."""
    if request.query_params.get("v") == _version(etag):
        cache = IMMUTABLE
    headers = {"etag": etag, "cache-control": cache}
    if etag in (request.headers.get("if-none-match") or ""):
        return Response(status_code=304, headers=headers)
    return Response(data, media_type=media, headers=headers)


def _file_response(request: Request, name: str, media: str, cache: str = "no-cache") -> Response:
    data, etag = _asset(name)
    return _bytes_response(request, data, etag, media, cache)


# Asks before a form marked data-confirm is sent. ui.js asks itself on background
# (data-async) forms, and lends its in-page dialog when it loaded; otherwise this falls
# back to the browser's own confirm().
CONFIRM_JS_NAME = "confirm.js"
CONFIRM_JS = (
    b"document.addEventListener('submit',function(e){"
    b"var f=e.target;if(!f||!f.getAttribute)return;"
    b"if(window.__asyncForms&&f.hasAttribute('data-async'))return;"
    b"var m=f.getAttribute('data-confirm');if(!m)return;"
    b"if(f.__confirmed){f.__confirmed=false;return;}"
    b"e.preventDefault();var s=e.submitter;"
    b"var ask=window.__askConfirm||function(x){"
    b"return Promise.resolve(window.confirm(x.getAttribute('data-confirm')));};"
    b"ask(f).then(function(ok){if(!ok)return;f.__confirmed=true;"
    b"if(f.requestSubmit)f.requestSubmit(s||undefined);else f.submit();});});"
)
CONFIRM_JS_ETAG = '"' + hashlib.sha256(CONFIRM_JS).hexdigest()[:32] + '"'


def confirm_script(request: Request) -> Response:
    return _bytes_response(request, CONFIRM_JS, CONFIRM_JS_ETAG, "text/javascript; charset=utf-8")


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
    # Font files never change under the same name.
    return _file_response(request, rel, "font/woff2", FONT_CACHE)


def robots(_: Request) -> Response:
    body = "User-agent: *\nAllow: /$\nAllow: /login\nAllow: /privacy\nAllow: /terms\nDisallow: /\n"
    return Response(body, media_type="text/plain; charset=utf-8")


def stylesheet(request: Request) -> Response:
    return _file_response(request, "app.css", "text/css; charset=utf-8")


def ui_script(request: Request) -> Response:
    return _file_response(request, "ui.js", "text/javascript; charset=utf-8")


def observability_script(request: Request) -> Response:
    return _file_response(request, "observability.js", "text/javascript; charset=utf-8")


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
        Route("/observability.js", observability_script, methods=["GET"]),
        Route("/fonts/{name}", font_asset, methods=["GET"]),
    ]


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
    # Requests between paired people, for people only (peer_requests.py). Off wherever
    # Sharing is off.
    peer_requests = (
        PeerRequestService(ctx.directory, ctx.mailbox)
        if ctx.directory is not None and ctx.mailbox is not None and ctx.ext_allowlist is not None
        else None
    )

    async def remember_pending(request: Request) -> None:
        """The nav badges for this page, off the event loop. The three lookups are
        independent store reads, so they run side by side rather than one after another."""
        actor = current_actor.get()
        request.state.pending_count = 0
        request.state.reconsent = False
        request.state.mailbox_count = 0

        async def pending() -> None:
            try:
                request.state.pending_count = await blocking(ctx.requests.pending_count)
                if peer_requests is not None and actor:
                    request.state.pending_count += await blocking(
                        peer_requests.pending_count, actor
                    )
            except Exception:
                logger.exception("pending request count failed")

        async def reconsent() -> None:
            try:
                request.state.reconsent = await blocking(ctx.reconsent_needed)
            except Exception:
                logger.exception("reconsent check failed")

        async def mailbox() -> None:
            # Mailbox nav badge: pairings waiting on this person's approval.
            if ctx.mailbox is None or not actor:
                return
            try:
                request.state.mailbox_count = await blocking(
                    ctx.mailbox.needs_approval_count, actor
                )
            except Exception:
                logger.exception("mailbox approval count failed")

        async with anyio.create_task_group() as tg:
            tg.start_soon(pending)
            tg.start_soon(reconsent)
            tg.start_soon(mailbox)

    def session_user(request: Request) -> str | None:
        """Signed-in email (step 1). A Drive connection (step 2) is not required here."""
        owner = request.session.get("owner")
        if not isinstance(owner, str) or not owner or ctx.directory is None:
            return None
        if not settings.sign_in_allowed(owner):
            return None
        if not ctx.directory.session_alive(request.session.get("sid"), owner):
            return None
        if not ctx.directory.is_known_user(owner):
            return None
        return owner

    async def signed_in_user(request: Request) -> str | None:
        """`session_user` off the event loop: it reads the session record and the user
        index from the store, and one slow store call must not stall every other
        request this instance is serving."""
        return await blocking(session_user, request)

    def connect_redirect(request: Request) -> RedirectResponse:
        target = request.url.path
        if request.url.query:
            target += "?" + request.url.query
        if request.method != "GET":
            target = "/"
        return RedirectResponse(f"/connect?{urlencode({'next': target})}", status_code=303)

    def refused(
        request: Request, status: int, message: str, *, title: str | None = None
    ) -> Response:
        """An error for a dashboard request: JSON for a background row action (ui.js
        shows the message next to the row), otherwise the styled error page."""
        if wants_json(request):
            return JSONResponse(
                {"ok": False, "kind": "error", "message": message, "changed": False},
                status_code=status,
            )
        return render(request, "error.html", status, message=message, title=title)

    def safely(handler: Handler) -> Handler:
        """For pages that handle sign-in themselves: a store or network failure becomes
        the styled error page (with the security headers) instead of a bare 500."""

        async def wrapped(request: Request) -> Response:
            try:
                return await handler(request)
            except Exception as exc:
                report_exception(exc, where="dashboard")
                return refused(request, 500, "Something went wrong on our side. Try again.")

        return wrapped

    def owner_only(handler: Handler) -> Handler:
        async def wrapped(request: Request) -> Response:
            email = await signed_in_user(request)
            if not email:
                if request.method != "GET":
                    return refused(
                        request,
                        403,
                        "You are signed out. Sign in again, then repeat that step.",
                        title="Signed out",
                    )
                target = request.url.path
                if request.url.query:
                    target += "?" + request.url.query
                return RedirectResponse(f"/login?{urlencode({'next': target})}", status_code=303)
            reset = current_actor.set(email)
            try:
                await remember_pending(request)
                return await handler(request)
            except OwnerNotConnectedError:
                if wants_json(request):
                    return refused(
                        request, 409, "Google Drive is not connected. Open Connections first."
                    )
                return connect_redirect(request)
            except InvalidInputError as exc:
                return refused(request, 400, str(exc))
            except Exception as exc:
                report_exception(exc, where="dashboard")
                if is_drive_failure(exc):
                    return refused(request, 502, "A Google Drive request failed. Try again.")
                # Not Google: the store, or a bug here. Saying "Drive" would send the
                # person (and whoever reads the report) to the wrong place.
                return refused(request, 500, "Something went wrong on our side. Try again.")
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
        if (
            not isinstance(sent, str)
            or not isinstance(expected, str)
            or not expected
            # Bytes: compare_digest raises TypeError on non-ASCII text.
            or not hmac.compare_digest(sent.encode(), expected.encode())
        ):
            return None
        return {k: v for k, v in form.items() if isinstance(v, str)}

    def csrf_protected(
        handler: Callable[[Request, dict[str, str]], Awaitable[Response]],
    ) -> Handler:
        async def wrapped(request: Request) -> Response:
            form = await check_csrf(request)
            if form is None:
                audit_owner("csrf", "deny", path=request.url.path)
                return refused(
                    request,
                    403,
                    "This page was open too long to be sure the request came from you. "
                    "Go back, reload the page and try again.",
                    title="Please try again",
                )
            return await handler(request, form)

        return owner_only(wrapped)

    def fresh_access_token(*args: Any, **kwargs: Any) -> str:
        # Looked up here on each call, like the three limits below: tests replace
        # these names on this module and expect the pages to see the new value.
        return refresh_access_token(*args, **kwargs)

    kit = Kit(
        ctx=ctx,
        settings=settings,
        oauth=oauth,
        serializer=serializer,
        peer_requests=peer_requests,
        logger=logger,
        session_user=session_user,
        signed_in_user=signed_in_user,
        remember_pending=remember_pending,
        connect_redirect=connect_redirect,
        refused=refused,
        render=render,
        render_plain=render_plain,
        flash=flash,
        action_done=action_done,
        wants_json=wants_json,
        blocking=blocking,
        safe_next=safe_next,
        browse_page_size=lambda: BROWSE_PAGE_SIZE,
        search_lookups=lambda: SEARCH_LOOKUPS,
        shared_search_limit=lambda: SHARED_SEARCH_LIMIT,
        refresh_access_token=fresh_access_token,
    )
    signin = signin_pages(kit)
    conn = connection_pages(
        kit, start_oauth=signin.start_oauth, login_rate_limited=signin.login_rate_limited
    )
    files = file_pages(kit)
    share = sharing_pages(kit, still_covered=files.still_covered)
    drops = drop_pages(kit)
    reqs = request_pages(kit)
    admin = admin_pages(kit)
    consent = consent_pages(kit)
    prefs = settings_pages(
        kit,
        drive_row_connected=conn.drive_row_connected,
        browse=files.browse,
        access=files.access,
        notion_files=conn.notion_files,
        onedrive_files=conn.onedrive_files,
        sharing=share.sharing,
        shared_overview=drops.shared_overview,
    )

    async def not_found(request: Request) -> Response:
        return render(request, "error.html", 404, message="Page not found.")

    routes = [
        Route("/confirm.js", confirm_script, methods=["GET"]),
        Route("/login", safely(signin.login), methods=["GET"]),
        Route("/auth/login", safely(signin.auth_login), methods=["GET"]),
        Route("/auth/callback", safely(signin.auth_callback), methods=["GET"]),
        Route("/connect", owner_only(conn.connect_page), methods=["GET"]),
        Route("/connect/{key}", csrf_protected(conn.connect_start), methods=["POST"]),
        Route("/connect/{key}/disconnect", csrf_protected(conn.connect_remove), methods=["POST"]),
        Route("/connect/notion/callback", owner_only(conn.notion_callback), methods=["GET"]),
        Route("/notion/allow", csrf_protected(conn.notion_allow), methods=["POST"]),
        Route("/notion/remove", csrf_protected(conn.notion_remove), methods=["POST"]),
        Route("/connect/onedrive/callback", owner_only(conn.onedrive_callback), methods=["GET"]),
        Route("/onedrive/allow", csrf_protected(conn.onedrive_allow), methods=["POST"]),
        Route("/onedrive/remove", csrf_protected(conn.onedrive_remove), methods=["POST"]),
        Route("/logout", csrf_protected(signin.logout), methods=["POST"]),
        Route("/", safely(files.home), methods=["GET"]),
        Route("/files", owner_only(prefs.files_page), methods=["GET"]),
        Route("/browse", prefs.moved("/files"), methods=["GET"]),
        Route("/picker/session", owner_only(files.picker_session), methods=["GET"]),
        Route("/grant", csrf_protected(files.grant), methods=["POST"]),
        Route("/revoke", csrf_protected(files.revoke), methods=["POST"]),
        Route("/files/batch", csrf_protected(files.files_batch), methods=["POST"]),
        Route("/access", prefs.moved("/files", tab="allowed"), methods=["GET"]),
        Route("/sharing", owner_only(prefs.sharing_hub), methods=["GET"]),
        Route("/settings", owner_only(prefs.settings_page), methods=["GET"]),
        Route("/sharing/add", csrf_protected(share.share_add), methods=["POST"]),
        Route("/sharing/remove", csrf_protected(share.share_remove), methods=["POST"]),
        Route("/sharing/audience", csrf_protected(share.share_audience), methods=["POST"]),
        Route("/first-reads/clear", csrf_protected(share.first_reads_clear), methods=["POST"]),
        Route("/oauth/grants/role", csrf_protected(prefs.oauth_grant_role), methods=["POST"]),
        Route("/roles/save", csrf_protected(prefs.role_save), methods=["POST"]),
        Route("/roles/delete", csrf_protected(prefs.role_delete), methods=["POST"]),
        Route("/oauth/grants/rename", csrf_protected(prefs.oauth_grant_rename), methods=["POST"]),
        Route("/shared", prefs.moved("/sharing", tab="with-me"), methods=["GET"]),
        Route("/shared/search", owner_only(drops.shared_search), methods=["GET"]),
        Route("/shared/browse", owner_only(drops.shared_browse), methods=["GET"]),
        Route("/shared/open", owner_only(drops.shared_open), methods=["GET"]),
        Route("/shared/download", owner_only(drops.shared_download), methods=["GET"]),
        Route(
            "/shared/send",
            drops.body_limited(
                csrf_protected(drops.drop_send), DROP_UPLOAD_LIMIT + DROP_FORM_OVERHEAD
            ),
            methods=["POST"],
        ),
        Route("/shared/send/start", csrf_protected(drops.drop_begin), methods=["POST"]),
        Route(
            "/shared/send/{upload_id}/piece/{n}",
            drops.body_limited(
                csrf_protected(drops.drop_piece_put), DROP_PIECE_LIMIT + DROP_FORM_OVERHEAD
            ),
            methods=["POST"],
        ),
        Route(
            "/shared/send/{upload_id}/finish", csrf_protected(drops.drop_finish), methods=["POST"]
        ),
        Route("/drops/allow", csrf_protected(drops.drop_allow), methods=["POST"]),
        Route("/drops/{drop_id}/download", owner_only(drops.drop_download), methods=["GET"]),
        Route("/drops/{drop_id}/piece/{n}", owner_only(drops.drop_piece_get), methods=["GET"]),
        Route("/drops/{drop_id}/piece/{n}/url", owner_only(drops.drop_piece_link), methods=["GET"]),
        Route("/drops/{drop_id}/{action}", csrf_protected(drops.drop_act), methods=["POST"]),
        Route("/requests", owner_only(reqs.requests_page), methods=["GET"]),
        Route("/requests/{rid}", owner_only(reqs.request_detail), methods=["GET"]),
        Route("/requests/{rid}/approve", csrf_protected(reqs.request_approve), methods=["POST"]),
        Route("/requests/{rid}/deny", csrf_protected(reqs.request_deny), methods=["POST"]),
        Route("/activity", owner_only(reqs.activity), methods=["GET"]),
        Route("/bridge", prefs.moved("/sharing", tab="people"), methods=["GET"]),
        Route("/bridge/webhook", csrf_protected(prefs.bridge_webhook), methods=["POST"]),
        Route("/bridge/{link_id}/{action}", csrf_protected(prefs.bridge_decide), methods=["POST"]),
        Route("/admin", safely(admin.admin_page), methods=["GET"]),
        Route("/admin/sign-records", csrf_protected(admin.admin_sign_records), methods=["POST"]),
        Route(
            "/admin/revoke-legacy-drive",
            csrf_protected(admin.admin_revoke_legacy),
            methods=["POST"],
        ),
        Route("/oauth/authorize", safely(consent.oauth_authorize), methods=["GET"]),
        Route("/oauth/authorize", csrf_protected(consent.oauth_decide), methods=["POST"]),
        Route("/oauth/continue", owner_only(consent.oauth_continue), methods=["GET"]),
        Route("/oauth/grants/revoke", csrf_protected(prefs.revoke_oauth_grant), methods=["POST"]),
        *legal_routes(),
        *(
            peer_request_routes(
                peer_requests,
                PeerRequestKit(
                    owner_only, csrf_protected, render, flash, ctx.ext_grants, _end_of_day
                ),
            )
            if peer_requests is not None
            else []
        ),
        *(
            ctx.terminal.page_routes(TerminalKit(owner_only, csrf_protected, render, flash))
            if ctx.terminal
            else []
        ),
        Route("/{path:path}", owner_only(not_found), methods=["GET"]),
    ]
    app = Starlette(
        routes=routes,
        middleware=[
            Middleware(SecurityHeadersMiddleware, hsts=settings.secure_cookies),
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
    app.state.terminal_tab = ctx.terminal is not None
    app.state.notion_create = ctx.notion_create
    # Mount("/") serves this app, so request.app is this app, not the outer one.
    app.state.dashboard = ctx
    return app


def human_size(size: int | None) -> str:
    if size is None:
        return ""
    value = float(size)
    for unit in ("bytes", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{int(value)} {unit}" if unit == "bytes" else f"{value:.1f} {unit}"
        value /= 1024
    return ""


def request_headline(
    req: Any, owner_meta: dict[str, Any] | None = None, apps: dict[str, str] | None = None
) -> str:
    """Plain-language summary of an access request. Technical fields stay out of this sentence."""
    who = assistant_label(getattr(req, "token_name", None), apps)
    name = None
    if owner_meta and owner_meta.get("name"):
        name = str(owner_meta["name"])
    elif getattr(req, "file_name", None):
        name = str(req.file_name)
    elif getattr(req, "description", None):
        name = str(req.description)
    item = name or "something in your Drive"
    tool = str(getattr(req, "tool", "") or "")
    actions = {
        "read_file": f"read {item}",
        "get_metadata": f"see the details of {item}",
        "list_folder": f"list {item}",
        "search_files": "search your Drive",
        "create_folder": f"create a folder in {item}",
        "create_doc": f"create a document in {item}",
        "upload_file": f"upload a file in {item}",
        "start_upload": f"upload a file in {item}",
        "export_file": f"export {item}",
        "save_export": f"save an export of {item}",
        "update_file_content": f"edit {item}",
        "rename_file": f"rename {item}",
        "trash_file": f"move {item} to trash",
        "request_access": f"use {item}",
    }
    action = actions.get(tool, f"use {item}")
    if str(getattr(req, "status", "pending") or "pending") != "pending":
        # Decided requests are history: "Grok asked to read notes.txt."
        return f"{who} asked to {action}."
    if tool == "request_access":
        return f"{who} is asking to {action}."
    return f"{who} wants to {action}."


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
        "start_upload": "Upload a file",
        "export_file": "Export a file",
        "save_export": "Export a file",
        "update_file_content": "Edit a file",
        "rename_file": "Rename a file",
        "trash_file": "Move to trash",
        "request_access": "Ask for access",
    }.get(tool, "Use a file")


_env.globals["request_headline"] = request_headline
_env.globals["status_label"] = status_label
_env.globals["tool_label"] = tool_label
_env.globals["describe_mime"] = describe_mime
_env.globals["shared_href"] = shared_href
_env.globals["human_size"] = human_size
_env.globals["assistant_label"] = assistant_label
_env.filters["when"] = when
_env.filters["epoch"] = epoch_iso
_env.globals["icon_kind"] = icon_kind
_env.globals["role_labels"] = ROLE_LABELS

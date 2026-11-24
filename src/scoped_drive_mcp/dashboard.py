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

import base64
import functools
import hashlib
import hmac
import html
import logging
import os
import re
import secrets
import time
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import date
from functools import partial
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

import anyio
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

from .access import (
    OWNER_INDEX,
    OWNER_INDEX_SINCE,
    PENDING,
    REQUEST_TTL,
    AccessRequests,
    validate_request_id,
)
from .audit import audit_owner
from .auth import current_actor
from .bridge import MailboxError
from .config import Settings
from .connections import CONNECTIONS, Connection, get_connection
from .drive_client import (
    FOLDER_MIME,
    SHORTCUT_MIME,
    DriveNotFoundError,
    LazyBotDriveClient,
    OwnerDriveClient,
)
from .drop_storage import BLOB_API_HOST, BLOB_API_PATH, PIECE_BYTES
from .errors import report_exception
from .external import SharedAccessError, normalize_email
from .grants import KEEP, OWNER_FIELDS, GrantError, GrantService
from .humanize import (
    ACTIVITY_FILTERS,
    MISSING,
    app_names,
    assistant_label,
    describe,
    group_repeats,
    item_ids,
    matches,
    parse_ts,
    when,
)
from .mcp_oauth import (
    APP_ROLES,
    DEFAULT_APP_ROLE,
    SCOPE,
    AuthorizeError,
    McpOAuth,
    QueryMapping,
)
from .notion_client import NotionApiError, NotionOAuthError
from .oauth import SIGN_IN_SCOPES, OAuthClient, OAuthError, refresh_access_token
from .policy import PayloadToolError
from .ratelimit import allow, ip_identity
from .scope import InvalidInputError, clean_search_text, parents_clause, validate_drive_id
from .shared_sources import VIA_DASHBOARD
from .store import (
    ACCESS_EDIT,
    ACCESS_READ,
    AUDIENCE_LINKED,
    EXTERNAL_ALLOWLIST_KEY,
    ActivityLog,
    Allowlist,
    SignedStore,
    TokenVault,
    sign_existing_records,
    usable_email,
)
from .terminal.feature import Kit as TerminalKit
from .terminal.feature import epoch_iso

logger = logging.getLogger(__name__)

SESSION_COOKIE = "sdm_session"
SESSION_MAX_AGE = 8 * 3600
STATE_MAX_AGE = 600
STATE_SALT = "sdm-oauth-state"
BROWSE_PAGE_SIZE = 200
ACTIVITY_PAGE = 50
# Drive lookups for names the activity page cannot find in the person's own lists.
ACTIVITY_LOOKUPS = 10
MAX_BREADCRUMBS = 25

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

# Connect Notion posts a form that redirects to Notion's consent screen, which may pass
# through Notion's sign-in. form-action is checked along that redirect chain.
NOTION_FORM_HOSTS = b"https://api.notion.com https://www.notion.so https://app.notion.com"

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
    b"form-action 'self' https://accounts.google.com " + NOTION_FORM_HOSTS + b"; "
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

_LOGIN_HINT = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# Searches per person per minute on "Shared with me". Each one reads every sharer's Drive.
SHARED_SEARCH_LIMIT = 20
# Files sent from the dashboard. Vercel refuses request bodies over 4.5 MB, so the form
# stays under it; an assistant's send_file has the larger MAX_BYTES limit.
DROP_UPLOAD_LIMIT = 4_000_000
DROP_UPLOAD_MB = DROP_UPLOAD_LIMIT // 1_000_000
# Room for the form's other fields and the multipart framing around the file.
DROP_FORM_OVERHEAD = 64_000
# With JavaScript, the page sends a larger file in pieces of this size (drop_storage), one
# request each, so every request stays under Vercel's 4.5 MB limit.
DROP_PIECE_LIMIT = PIECE_BYTES
# Files listed under "Sent to you" on the Shared with me page.
DROPS_SHOWN = 50
# Folder lookups one Files page may make to work out search-result paths and
# folder-inherited access. Past this, the remaining rows say to open their folder.
SEARCH_LOOKUPS = 40
# Name matches shown for one Browse search. More than this and the page says to narrow it.
SEARCH_PAGE = 100
# Item ids in "Shared with me" links. Drive ids fit; other sources must too.
_SHARED_ID = re.compile(r"[A-Za-z0-9_.:\-]{1,200}")


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
            None,
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
            None,
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


async def blocking[T](fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    return await anyio.to_thread.run_sync(partial(fn, *args, **kwargs))


# Drive lookups a page makes side by side (the Allowed tab's folder checks). One pool for
# the process, so its threads and their Drive connections are reused between requests.
DRIVE_LOOKUP_WORKERS = 8
_drive_pool = ThreadPoolExecutor(DRIVE_LOOKUP_WORKERS, thread_name_prefix="drive-lookup")


def fetch_parents(drive: Any, ids: list[str]) -> dict[str, dict[str, Any] | None | Exception]:
    """files.get("id,parents") for each id, in parallel. None for not found, else the
    error a lookup raised, so one failure does not lose the other answers."""

    def one(fid: str) -> dict[str, Any] | None | Exception:
        try:
            return drive.get_file(fid, fields="id,parents")
        except DriveNotFoundError:
            return None
        except Exception as exc:
            return exc

    if len(ids) == 1:
        return {ids[0]: one(ids[0])}
    return dict(zip(ids, _drive_pool.map(one, ids), strict=True))


WAKE_HOME = "/settings#assistants"
LIST_FIELDS = OWNER_FIELDS + ",modifiedTime"
COVER_CHECK_LIMIT = 25
# The action bar on Files and Sharing. Each item is one Drive lookup at most, run in turn,
# so a batch stays well inside one function call.
BATCH_ACTIONS = ("allow", "remove", "share", "unshare", "forget")
BATCH_LIMIT = 50
# How each app role is named on the consent page and in Settings.
ROLE_LABELS = {
    "viewer": "Read only",
    "editor": "Read and edit",
    "admin": "Full (read, edit and trash)",
}


def _end_of_day(day: str) -> str | None:
    """A date from the Sharing form ("2026-12-31") as the last second of that day, UTC,
    in the same ISO form as utc_now() so the two compare as strings."""
    day = day.strip()
    if not day:
        return None
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", day):
        raise ValueError(day)
    date.fromisoformat(day)
    return f"{day}T23:59:59+00:00"


def _dupes(rows: list[dict[str, Any]]) -> set[str]:
    seen: dict[str, int] = {}
    for row in rows:
        key = str(row.get("name") or "").strip().casefold()
        seen[key] = seen.get(key, 0) + 1
    return {name for name, n in seen.items() if n > 1}


def icon_kind(mime: str) -> str:
    """Which small icon a row gets: folder, doc, sheet, slides, pdf, image, video, file."""
    if mime == FOLDER_MIME:
        return "folder"
    if mime == SHORTCUT_MIME:
        return "shortcut"
    if mime.endswith(".document") or "wordprocessing" in mime or mime == "application/msword":
        return "doc"
    if (
        mime.endswith(".spreadsheet")
        or "spreadsheetml" in mime
        or mime
        in (
            "application/vnd.ms-excel",
            "text/csv",
        )
    ):
        return "sheet"
    if mime.endswith(".presentation") or "presentationml" in mime or "powerpoint" in mime:
        return "slides"
    if mime == "application/pdf":
        return "pdf"
    if mime.startswith("image/"):
        return "image"
    if mime.startswith("video/"):
        return "video"
    return "file"


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
    ctx.setdefault("terminal_tab", getattr(request.app.state, "terminal_tab", False))
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


async def privacy_page(_: Request) -> Response:
    return render_plain("privacy.html")


@functools.lru_cache(maxsize=16)
def _asset(name: str) -> tuple[bytes, str]:
    data = (TEMPLATES_DIR / name).read_bytes()
    return data, '"' + hashlib.sha256(data).hexdigest()[:32] + '"'


def _file_response(request: Request, name: str, media: str, cache: str = "no-cache") -> Response:
    """A bundled asset. `no-cache` still lets the browser keep it: it revalidates with the
    ETag and gets a 304, so a new deployment's CSS and JS are picked up at once."""
    data, etag = _asset(name)
    headers = {"etag": etag, "cache-control": cache}
    if etag in (request.headers.get("if-none-match") or ""):
        return Response(status_code=304, headers=headers)
    return Response(data, media_type=media, headers=headers)


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
    return _file_response(request, rel, "font/woff2", "public, max-age=2592000")


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
        """The nav badges for this page, off the event loop. The three lookups are
        independent store reads, so they run side by side rather than one after another."""
        actor = current_actor.get()
        request.state.pending_count = 0
        request.state.reconsent = False
        request.state.mailbox_count = 0

        async def pending() -> None:
            try:
                request.state.pending_count = await blocking(ctx.requests.pending_count)
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
            email = session_user(request)
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
                return refused(request, 502, "A Google Drive request failed. Try again.")
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
            audit_owner("connect", "deny", reason="different_account")
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
        limited = await login_rate_limited(request)
        if limited is not None:
            return limited
        request.session["oauth_next"] = safe_next(form.get("next"))
        if connection.provider == "notion":
            return start_notion(request)
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
        back = "/files?tab=notion"
        if entry is None:
            return action_done(request, "ok", "That page was not allowed.", back, changed=False)
        audit_owner("notion_remove", page_id=entry.id, name=entry.name)
        return action_done(
            request, "ok", f"Removed “{entry.name}”. Assistants can no longer read it.", back
        )

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
                # Step 2 done for this person. Browse, Allow and Sharing need it, even
                # when the deployment's own bot token (bot.connected) is set.
                "drive_connected": ctx.drive_connected(),
                "connections": ctx.connection_rows(),
                "allow_count": len(entries),
                "grants": (ctx.mcp_oauth.list_grants(current_actor.get()) if ctx.mcp_oauth else []),
                "missing_wakeups": (
                    ctx.mailbox.missing_wakeups(str(current_actor.get() or ""))
                    if ctx.mailbox is not None
                    else []
                ),
                **people_summary(str(current_actor.get() or "")),
                "first_reads": ctx.first_reads.recent() if ctx.first_reads else [],
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

    def people_summary(email: str) -> dict[str, Any]:
        """Mailbox and Shared with me counts for Overview. Store reads only, no Drive call."""
        mailbox = None
        if ctx.mailbox is not None and email:
            try:
                mailbox = ctx.mailbox.summary(email)
            except Exception:
                logger.exception("mailbox summary failed")
        shared = None
        if ctx.shared_with_me is not None and email:
            try:
                people = ctx.shared_with_me.overview(email)
                shared = {
                    "people": len(people),
                    "item_count": sum(p.item_count for p in people),
                }
            except Exception:
                logger.exception("shared with me summary failed")
        return {"mailbox_summary": mailbox, "shared_summary": shared}

    def browse_data(folder: str, q: str | None, page_token: str | None) -> dict[str, Any]:
        drive, token = ctx.owner_drive_and_token()
        # drive.file cannot files.get("root") until the app has opened My Drive.
        # The alias still works in a parents query, which is enough to list files
        # this app created or the user picked.
        root_id = ctx.owner_root_id(drive, token)
        entries = ctx.allowlist.entries()
        shared = ctx.ext_ids()
        crumbs: list[dict[str, str]] = []
        # The nearest allowed folder at or above the one being browsed, and its id so
        # the breadcrumb can offer to remove that folder's own entry.
        covered_by: str | None = None
        covered_id: str | None = None
        # The nearest folder on the Sharing list above the one being browsed. Everything
        # inside it is readable by paired people's assistants, as the guest guard allows.
        shared_by: str | None = None
        shared_id: str | None = None
        next_token: str | None = None
        more_matches = False
        current: dict[str, Any] | None = None
        if q:
            term = clean_search_text(q)
            query = f"trashed=false and name contains '{term}'"
            resp = drive.list_files(query, fields=LIST_FIELDS, page_size=SEARCH_PAGE)
            items = resp.get("files", [])
            more_matches = bool(resp.get("nextPageToken"))
        else:
            if folder == "root":
                folder_id = root_id or "root"
            else:
                folder_id = validate_drive_id(folder, "folder")
            if folder_id == "root" or folder_id == root_id:
                # My Drive itself: its name and place are known, so no lookup.
                current = {
                    "id": folder_id,
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
                    covered_by, covered_id = name, nid
                if shared_by is None and nid in shared:
                    shared_by, shared_id = name, nid
                parents = node.get("parents") or []
                if nid == root_id or nid == "root" or not parents:
                    break
                try:
                    node = drive.get_file(str(parents[0]), fields=OWNER_FIELDS)
                except DriveNotFoundError:
                    node = None
            at_top = folder == "root"
            if at_top:
                # Google opens a file to this app only once it is picked (drive.file), and
                # picked files can sit anywhere in the Drive, not just in My Drive's top
                # level. So the top of Files lists everything the app can open: the
                # picked items and the files it created, each with Allow and Share.
                # That "everything" is bounded by the OAuth scope, which is always
                # drive.file: a wider token is refused at connect and on every refresh.
                query = "trashed=false"
            else:
                query = f"{parents_clause([folder_id])} and trashed=false"
            resp = drive.list_files(
                query,
                fields=LIST_FIELDS,
                page_size=BROWSE_PAGE_SIZE,
                page_token=page_token,
                # Folders first, then by name, across every page (not just within one).
                order_by="folder,name",
            )
            items = resp.get("files", [])
            # Drive's parents filter can echo a file that merely mentions the folder.
            # The alias "root" is not the id Drive returns on a file, so it cannot be
            # used for that check.
            if not at_top and folder_id != "root":
                items = [i for i in items if folder_id in (i.get("parents") or [])]
            next_token = resp.get("nextPageToken")
        items.sort(key=lambda i: (i.get("mimeType") != FOLDER_MIME, str(i.get("name", "")).lower()))

        # Folder metadata looked up while working out search results and shortcut
        # targets. Many results share folders, so each folder is fetched once.
        metas: dict[str, dict[str, Any] | None] = {}
        if current is not None:
            metas[str(current["id"])] = current

        lookups = [0]

        class _OutOfLookups(Exception):
            pass

        def meta_of(fid: str) -> dict[str, Any] | None:
            if fid not in metas:
                if lookups[0] >= SEARCH_LOOKUPS:
                    raise _OutOfLookups
                lookups[0] += 1
                try:
                    metas[fid] = drive.get_file(fid, fields=OWNER_FIELDS)
                except DriveNotFoundError:
                    metas[fid] = None
            return metas[fid]

        def lineage(item: dict[str, Any]) -> list[tuple[str, str]] | None:
            """(id, name) of the folders above `item`, nearest first, up to My Drive.
            Follows the first parent, as the breadcrumbs do. None when the page's lookup
            budget ran out before reaching the top, so the answer would be a guess."""
            out: list[tuple[str, str]] = []
            seen_ids = {str(item.get("id", ""))}
            parents = item.get("parents") or []
            try:
                while parents and len(out) < MAX_BREADCRUMBS:
                    pid = str(parents[0])
                    if pid in seen_ids or pid == root_id or pid == "root":
                        break
                    seen_ids.add(pid)
                    node_meta = meta_of(pid)
                    if node_meta is None:
                        break
                    out.append((pid, str(node_meta.get("name", ""))))
                    parents = node_meta.get("parents") or []
            except _OutOfLookups:
                return None
            return out

        def nearest(chain: list[tuple[str, str]], ids: Any) -> tuple[str, str] | None:
            return next(((fid, name) for fid, name in chain if fid in ids), None)

        # In a folder view every row sits under the same folders, so the folder-level
        # answer applies. Search results come from anywhere, so each works out its own.
        folder_cover = (covered_id, covered_by) if covered_by and covered_id else None
        folder_share = (shared_id, shared_by) if shared_by and shared_id else None
        # Removed from Bot RBAC: left out of My Drive's list and search, the two places a
        # picked item shows up on its own. Inside a folder everything is still listed.
        hidden = ctx.hidden.ids() if ctx.hidden is not None and (q or folder == "root") else set()
        hidden_count = sum(1 for item in items if str(item["id"]) in hidden)
        rows = []
        for item in items:
            iid = str(item["id"])
            if iid in hidden:
                continue
            mime = str(item.get("mimeType", ""))
            is_shortcut = mime == SHORTCUT_MIME
            path: str | None = None
            unsure = False
            if q:
                chain = lineage(item)
                if chain is None:
                    # Too many folders to look up on one page: don't guess the status.
                    unsure, cover, share, parent_id = True, None, None, None
                else:
                    cover = nearest(chain, entries)
                    share = nearest(chain, shared)
                    path = " / ".join(["My Drive", *(name for _, name in reversed(chain))])
                    parent_id = chain[0][0] if chain else "root"
            else:
                cover, share = folder_cover, folder_share
                parent_id = None
            # A shortcut is not on the lists itself: Allow stores its target. So the row
            # shows the target's state, and Remove / Stop sharing act on the target.
            acts_on = iid
            target: dict[str, Any] | None = None
            if is_shortcut:
                target_id = str((item.get("shortcutDetails") or {}).get("targetId") or "")
                try:
                    target_meta = meta_of(target_id) if target_id else None
                except _OutOfLookups:
                    target_meta, unsure = None, True
                tchain = lineage(target_meta) if target_meta is not None else None
                if target_meta is not None and tchain is None:
                    unsure = True
                if unsure and target_id:
                    # Out of lookups: still act on the target (Allow stores the target),
                    # but don't guess its folder state from the shortcut's own folder.
                    acts_on, cover, share = target_id, None, None
                if target_meta is not None and tchain is not None:
                    # The row's state is the target's, and that is known.
                    acts_on, unsure = target_id, False
                    cover = nearest(tchain, entries)
                    share = nearest(tchain, shared)
                    item_parents = [str(p) for p in item.get("parents") or []]
                    target_parents = [str(p) for p in target_meta.get("parents") or []]
                    target = {
                        "id": target_id,
                        "name": str(target_meta.get("name", "")),
                        "folder": tchain[0][1] if tchain else "My Drive",
                        "elsewhere": not set(item_parents) & set(target_parents),
                    }
            rows.append(
                {
                    "id": iid,
                    "acts_on": acts_on,
                    "name": str(item.get("name", "")),
                    "is_folder": mime == FOLDER_MIME,
                    "is_shortcut": is_shortcut,
                    "target": target,
                    "kind": describe_mime(mime),
                    "icon": icon_kind(mime),
                    "modified": item.get("modifiedTime"),
                    "link": item.get("webViewLink"),
                    "path": path,
                    "parent_id": parent_id,
                    "unsure": unsure,
                    "granted": acts_on in entries,
                    "covered_by": cover[1] if cover else None,
                    "ext_shared": acts_on in shared,
                    "shared_by": share[1] if share else None,
                }
            )
        return {
            "rows": rows,
            # Same-named rows ("Untitled document" three times) show when each changed.
            "dupes": _dupes(rows),
            "crumbs": crumbs,
            "covered_by": covered_by,
            "covered_id": covered_id,
            "shared_by": shared_by,
            "current": current,
            "current_granted": current is not None and str(current["id"]) in entries,
            "is_root": current is not None
            and (
                str(current["id"]) == root_id or (root_id is None and str(current["id"]) == "root")
            ),
            "next_token": next_token,
            "more_matches": more_matches,
            "hidden_count": hidden_count,
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
            if page_token:
                # Most often a page link that went stale (Back, or a bookmark). Show the
                # folder's first page instead of an error.
                first = {"folder": folder}
                if q:
                    first["q"] = q
                if picking:
                    first["request"] = picking.id
                return RedirectResponse(f"/files?{urlencode(first)}", status_code=303)
            data = {
                "rows": [],
                "crumbs": [{"id": "root", "name": "My Drive"}],
                "covered_by": None,
                "covered_id": None,
                "shared_by": None,
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
        email = str(current_actor.get() or "")
        has_pairing = bool(
            ctx.mailbox is not None
            and ctx.ext_allowlist is not None
            and await blocking(ctx.mailbox.active_peers, email)
        )
        return render(
            request,
            "browse.html",
            has_pairing=has_pairing,
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
            logger.warning("picker token not issued: %s", exc)
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
        next_url = safe_next(form.get("next"))
        try:
            entry = await blocking(ctx.grants().grant, file_id)
        except GrantError as exc:
            return action_done(request, "error", str(exc), next_url)
        await unhide(file_id, entry.id)
        what = f"\u201c{entry.name}\u201d"
        if entry.id != file_id:
            what += ", the shortcut\u2019s target,"
        return action_done(
            request,
            "ok",
            f"Allowed {what} for the assistant.",
            next_url,
            extra=await allow_count_extra(request),
        )

    async def revoke(request: Request, form: dict[str, str]) -> Response:
        file_id = validate_drive_id(form.get("file_id"))
        next_url = safe_next(form.get("next"))
        grants = ctx.grants()
        entry = await blocking(ctx.allowlist.get, file_id)
        try:
            await blocking(grants.revoke, file_id)
        except GrantError as exc:
            gone = await blocking(lambda: ctx.allowlist.get(file_id) is None)
            return action_done(
                request,
                "error",
                str(exc),
                next_url,
                changed=gone,
                extra=await allow_count_extra(request) if gone else None,
            )
        root = ctx.visible_root_folder_id()
        extra = {root: "the folder set on the server"} if root else None
        cover = await still_covered(grants, file_id, extra)
        name = (entry.name if entry else "") or "it"
        if cover is None:
            message = f"Removed “{name}”. The assistant can no longer use it."
        elif cover:
            message = (
                f"Removed “{name}”, but the assistant can still use it "
                f"because “{cover}” is allowed."
            )
        else:
            message = (
                f"Removed “{name}”. If a folder above it is allowed, "
                "the assistant can still use it through that folder."
            )
        return action_done(request, "ok", message, next_url, extra=await allow_count_extra(request))

    async def unhide(*file_ids: str) -> None:
        """Picking or allowing an item again brings it back onto Files."""
        if ctx.hidden is not None:
            for fid in set(file_ids):
                await blocking(ctx.hidden.unhide, fid)

    def plural(n: int, one: str = "item", many: str = "items") -> str:
        return f"{n} {one if n == 1 else many}"

    async def files_batch(request: Request, form: dict[str, str]) -> Response:
        """One action on several ticked items: the action bar on Files and Sharing.

        Each item goes through the same GrantService call as its own row button, so the
        allowlist checks, audit records and cache invalidation are unchanged. An item the
        action does not apply to (Remove on an item that is not allowed) is skipped.
        """
        action = form.get("action") or ""
        next_url = safe_next(form.get("next") or "/files")
        if action not in BATCH_ACTIONS:
            return action_done(request, "error", "Choose what to do with the items.", next_url)
        raw = (await request.form()).getlist("file_id")
        try:
            ids = list(dict.fromkeys(validate_drive_id(str(v)) for v in raw))
        except InvalidInputError:
            # Only a hand-made request carries one: the page renders real ids. Refuse the
            # whole batch rather than act on part of it.
            return action_done(
                request, "error", "One of the ticked items is not a Drive item.", next_url
            )
        if not ids:
            return action_done(request, "error", "Tick at least one item first.", next_url)
        if len(ids) > BATCH_LIMIT:
            return action_done(
                request, "error", f"Choose at most {BATCH_LIMIT} items at a time.", next_url
            )
        if action in ("share", "unshare") and ctx.ext_allowlist is None:
            return action_done(request, "error", "Sharing is not set up on this server.", next_url)
        own = ctx.grants()
        ext = ctx.ext_grants() if ctx.ext_allowlist is not None else None

        def run() -> tuple[int, list[str], list[str], list[str]]:
            done = 0
            errors: list[str] = []
            names: list[str] = []
            # Ids actually taken off a list, for the folder check below. Skipped items
            # (Remove on something that was not allowed) must not be reported on.
            changed: list[str] = []
            hidden = ctx.hidden

            def unhide(*fids: str) -> None:
                if hidden is not None:
                    for one in set(fids):
                        hidden.unhide(one)

            for fid in ids:
                try:
                    if action == "allow":
                        entry = own.grant(fid)
                        names.append(entry.name)
                        unhide(fid, entry.id)
                    elif action == "share":
                        assert ext is not None
                        entry = ext.grant(fid)
                        names.append(entry.name)
                        unhide(fid, entry.id)
                    elif action == "remove":
                        entry = ctx.allowlist.get(fid)
                        if entry is None:
                            continue
                        names.append(entry.name)
                        own.revoke(fid)
                        changed.append(fid)
                    elif action == "unshare":
                        assert ext is not None and ctx.ext_allowlist is not None
                        entry = ctx.ext_allowlist.get(fid)
                        if entry is None:
                            continue
                        names.append(entry.name)
                        ext.revoke(fid)
                        changed.append(fid)
                    else:  # forget: off both lists, then off this list
                        mine = ctx.allowlist.get(fid)
                        theirs = ctx.ext_allowlist.get(fid) if ctx.ext_allowlist else None
                        listed = mine or theirs
                        if listed is not None and listed.name:
                            names.append(listed.name)
                        if mine is not None:
                            own.revoke(fid)
                        shared = ctx.ext_allowlist
                        if ext is not None and shared is not None and shared.get(fid) is not None:
                            ext.revoke(fid)
                        if hidden is not None:
                            hidden.hide(fid)
                    done += 1
                except GrantError as exc:
                    errors.append(str(exc))
            return done, errors, names, changed

        done, errors, names, changed = await blocking(run)
        if action == "remove":
            # Same check as one row's Remove, bounded: an allowed folder above an item
            # still includes it, so the message must not say the item is unreachable.
            root = ctx.visible_root_folder_id()
            extra = {root: "the folder set on the server"} if root else None
        else:
            extra = None
        # still: the folder that still covers each removed item. unknown: removed items
        # whose folders were not checked, because Drive did not answer ("") or the batch
        # was past COVER_CHECK_LIMIT. Then the message must not say they are unreachable.
        still: list[str] = []
        unknown = 0
        checker = own if action == "remove" else ext if action == "unshare" else None
        if checker is not None:
            unknown = max(0, len(changed) - COVER_CHECK_LIMIT)
            for fid in changed[:COVER_CHECK_LIMIT]:
                cover = await still_covered(checker, fid, extra)
                if cover:
                    still.append(cover)
                elif cover == "":
                    unknown += 1
        what = f"\u201c{names[0]}\u201d" if done == 1 and names else plural(done)
        message = {
            "allow": f"Allowed {what} for your assistants.",
            "remove": f"Removed {what}. Your assistants can no longer use "
            f"{'it' if done == 1 else 'them'}.",
            "share": f"Shared {what} with the assistants of people you are paired with.",
            "unshare": f"Stopped sharing {what}. Paired people\u2019s assistants can no longer "
            f"read {'it' if done == 1 else 'them'}.",
            "forget": f"Removed {what} from Bot RBAC. No assistant can open "
            f"{'it' if done == 1 else 'them'}. Google still lists Bot RBAC as able to open "
            f"{'it' if done == 1 else 'them'} until you remove the app in your Google Account.",
        }[action]
        if unknown and not still:
            # Same wording as one row's Remove when Drive could not be asked.
            them = "it" if done == 1 else "them"
            if action == "remove":
                message = (
                    f"Removed {what}. If a folder above {them} is allowed, your assistants "
                    f"can still use {them} through that folder."
                )
            else:
                message = (
                    f"Stopped sharing {what}. If a folder above {them} is on your Sharing "
                    f"list, paired people\u2019s assistants can still read {them} through it."
                )
        if still:
            folders = ", ".join(f"\u201c{c}\u201d" for c in dict.fromkeys(still))
            stays = "stays" if len(set(still)) == 1 else "stay"
            if action == "remove":
                message = (
                    f"Removed {what}, but your assistants can still use "
                    f"{len(still)} of them through {folders}, "
                    f"which {stays} allowed."
                    if done > 1
                    else f"Removed {what}, but your assistants can still use it because "
                    f"{folders} is allowed."
                )
            else:
                message += f" Still readable through {folders}, which {stays} shared."
        if errors:
            first = errors[0].replace("allowlist", "list")
            failed = plural(len(errors))
            if done:
                message += f" {failed} could not be changed: {first}"
            else:
                return action_done(
                    request, "error", f"{failed} could not be changed: {first}", next_url
                )
        if done == 0:
            return action_done(
                request, "error", "None of the ticked items needed that change.", next_url
            )
        return action_done(request, "ok", message, next_url)

    async def allow_count_extra(request: Request) -> dict[str, int] | None:
        """The new number for the Allowed tab, so ui.js can update it without a reload."""
        if not wants_json(request):
            return None
        return {"allow_count": len(await blocking(ctx.allowlist.entries))}

    async def still_covered(
        grants: GrantService, file_id: str, extra: dict[str, str] | None = None
    ) -> str | None:
        """Name of an allowed folder that still includes `file_id`.

        None means no folder on the list includes it. An empty string means Drive could
        not be asked; only the wording depends on this, so the completed removal is not
        turned into an error, and the message does not claim the item is unreachable.
        """
        try:
            found = await blocking(grants.covering_entry, file_id, extra)
        except Exception as exc:
            report_exception(exc, where="covering_entry")
            return ""
        return found[1] if found else None

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
            allow, ctx.store, "shared_search", "user:" + email, SHARED_SEARCH_LIMIT, 60
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

    async def access(request: Request) -> Response:
        def gather() -> dict[str, Any]:
            return {
                "entries": ctx.allowlist.entries(),
                "bot": ctx.bot_status(),
                "drive_connected": ctx.drive_connected(),
            }

        data = await blocking(gather)
        rows = sorted(data["entries"].values(), key=lambda e: e.granted_at, reverse=True)

        def entry_status() -> tuple[dict[str, str], set[str]]:
            # covered: an entry inside another allowed folder. Removing it alone changes
            # nothing, so the list says so. needs_pick: Google opens a file to this app
            # only once it is picked (drive.file); an entry from an older connection
            # stays on the list but can't be opened until it is picked again.
            # One pass for both, with each level of folder lookups run in parallel.
            # Bounded, since each check walks up the folder tree.
            if not data["drive_connected"] or not rows:
                return {}, set()
            try:
                drive = ctx.owner_drive()
            except Exception:
                return {}, set()
            ids = [entry.id for entry in rows[:COVER_CHECK_LIMIT]]
            failed = [0]

            def fetch(batch: list[str]) -> dict[str, dict[str, Any] | None | Exception]:
                found = fetch_parents(drive, batch)
                failed[0] += sum(isinstance(v, Exception) for v in found.values())
                return found

            try:
                covers, not_found = ctx.grants().entry_status(ids, fetch)
            except Exception:
                logger.exception("allowed list status check failed")
                return {}, set()
            if failed[0]:
                # Those items get no note rather than a guess. Logged so a burst of rate
                # limits or Drive errors shows up instead of quietly hiding the notes.
                logger.warning("allowed list status check: %d Drive lookups failed", failed[0])
            if len(rows) < 2:
                # One entry can't be inside another. The walk above still ran, because
                # it also finds the entries Drive no longer opens (needs_pick).
                covers = {}
            return {fid: c[1] for fid, c in covers.items() if c[0] != fid}, not_found

        covered, needs_pick = await blocking(entry_status)
        return render(
            request,
            "access.html",
            covered=covered,
            needs_pick=needs_pick,
            picker_ready=settings.picker_configured,
            rows=rows,
            root_folder_id=ctx.visible_root_folder_id(),
            describe_mime=describe_mime,
            bot=data["bot"],
            drive_connected=data["drive_connected"],
        )

    def my_app_names() -> dict[str, str]:
        if ctx.mcp_oauth is None:
            return {}
        return app_names(ctx.mcp_oauth.list_grants(current_actor.get()))

    async def requests_page(request: Request) -> Response:
        reqs = await blocking(ctx.requests.recent, 100)
        pending = [r for r in reqs if r.status == PENDING]
        decided = [r for r in reqs if r.status != PENDING]
        apps = await blocking(my_app_names)
        return render(request, "requests.html", pending=pending, decided=decided, apps=apps)

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

    async def request_detail(request: Request) -> Response:
        rid = request.path_params["rid"]
        req = await blocking(ctx.requests.get, rid)
        if req is None:
            return await missing_request(request, rid)
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
            # Under drive.file Google also answers 404 for real files this app never
            # opened, so a 404 proves nothing: don't call them missing.
            limited = True
            try:
                drive = ctx.owner_drive()
                for item in unknown:
                    try:
                        meta = drive.get_file(item, fields="id,name")
                    except DriveNotFoundError:
                        if not limited:
                            names[item] = MISSING
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
            params = {"view": view, "checks": "1" if show_checks else "", "show": ""}
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
        )

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
        signing = None
        if isinstance(ctx.store, SignedStore):
            signing = {"required": ctx.store.require}
        legacy = sum(1 for person in people if person["legacy"])
        return render(request, "admin.html", people=people, signing=signing, legacy=legacy)

    async def admin_revoke_legacy(request: Request, form: dict[str, str]) -> Response:
        """Revoke and delete every stored full-Drive (or unstamped) token, for everyone.

        Those tokens are already never used. This removes them from the store and asks
        Google to end them, so a copy of the store cannot be used to reach anyone's Drive.
        Each person reconnects with per-file access when they next visit."""
        if session_user(request) != settings.owner_email or ctx.directory is None:
            return render(request, "error.html", 404, message="Page not found.")

        def run() -> tuple[int, int]:
            assert ctx.directory is not None
            done = failed = 0
            for person in ctx.directory.known_users():
                vault = ctx.directory.vault_for(person)
                record = vault.legacy_owner()
                if not record:
                    continue
                try:
                    ok = oauth.revoke(record["t"])
                except Exception:
                    logger.exception("revoking an old Drive connection failed")
                    ok = False
                if not ok:
                    # Kept so the next run can try again. It is never used meanwhile.
                    failed += 1
                    continue
                current = vault.legacy_owner()
                if current and current.get("t") == record["t"]:
                    vault.clear_owner()
                ctx.forget_drive(person)
                done += 1
            return done, failed

        done, failed = await blocking(run)
        audit_owner("revoke_legacy_drive", count=str(done), failed=str(failed))
        if failed:
            flash(
                request,
                "error",
                f"Revoked {done}. Google didn’t confirm {failed}; those are kept (and still "
                "unused). Run this again.",
            )
        else:
            flash(
                request,
                "ok",
                f"Revoked {done} old full-Drive connection{'' if done == 1 else 's'}."
                if done
                else "No old full-Drive connections are stored.",
            )
        return RedirectResponse("/admin", status_code=303)

    async def admin_sign_records(request: Request, form: dict[str, str]) -> Response:
        """Sign the allowlist, app and pairing records saved before records were signed."""
        if session_user(request) != settings.owner_email or ctx.directory is None:
            return render(request, "error.html", 404, message="Page not found.")
        if isinstance(ctx.store, SignedStore) and ctx.store.require:
            # Signing is for records from before. Once unsigned ones are ignored, signing
            # whatever is in the store would bring back one that was planted since.
            flash(
                request,
                "error",
                "REQUIRE_SIGNED_RECORDS is on, so nothing was signed. Unsigned records are "
                "ignored now.",
            )
            return RedirectResponse("/admin", status_code=303)

        def run() -> tuple[int, int]:
            people = ctx.directory.known_users()
            everyone = list(dict.fromkeys([*people, settings.owner_email or ""]))
            # First the two records whose older form says less than it should: an
            # approval that does not name who joined, and an app with no written role.
            if ctx.mailbox is not None:
                known = [e for e in everyone if e]
                ctx.mailbox.seal_ended_pairings(known)
                ctx.mailbox.bind_legacy_approvals(known)
            unpinned = 0
            if ctx.mcp_oauth is not None:
                _pinned, unpinned = ctx.mcp_oauth.pin_legacy_roles()
            signed, failed = sign_existing_records(ctx.store, people, settings.owner_email)
            return signed, failed + unpinned

        signed, failed = await blocking(run)
        audit_owner("sign_records", count=str(signed), failed=str(failed))
        if failed:
            flash(
                request,
                "error",
                f"Signed {signed}, but {failed} could not be signed because they changed "
                "at that moment or the store refused. Run this again, and keep "
                "REQUIRE_SIGNED_RECORDS=0 until it reports none left.",
            )
        else:
            flash(
                request,
                "ok",
                f"Signed {signed} stored record{'' if signed == 1 else 's'}. Every record "
                "this server knows of is now signed."
                if signed
                else "Every record this server knows of was already signed.",
            )
        return RedirectResponse("/admin", status_code=303)

    def _directory_rows() -> list[dict[str, Any]]:
        if ctx.directory is None:
            return []
        rows: list[dict[str, Any]] = []
        for person in ctx.directory.known_users():
            grants = ctx.mcp_oauth.list_grants(person) if ctx.mcp_oauth else []
            # The sign-in index is newer than some accounts, so its date can be later
            # than an app the person connected. Show the earliest date we know of.
            known = [ctx.directory.created_at(person), *(g.created_at for g in grants)]
            moments = [(parse_ts(v), v) for v in known if v]
            earliest = min((m for m in moments if m[0] is not None), default=None)
            rows.append(
                {
                    "email": person,
                    "created_at": earliest[1] if earliest else None,
                    "grants": grants,
                    "legacy": ctx.directory.vault_for(person).legacy_owner() is not None,
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
            # The form carries this id back, so Allow only ever approves the request this
            # page describes. A second authorize request in another tab replaces it.
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
                mailbox_on=ctx.mailbox is not None,
                shared_on=ctx.shared_with_me is not None,
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

    def assistant_rows(email: str, links: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """Connected assistants with their wake-up, for Settings. Two connections can share
        a name (two "Cursor"s), so each row also says which of your assistants it is
        paired with, when it was added and last used, and a short id that never changes."""
        box = ctx.mailbox
        grants = ctx.mcp_oauth.list_grants(email) if ctx.mcp_oauth else []
        if links is None:
            links = box.list_links(email)["links"] if box is not None else []
        # Who each assistant talks to: your own assistants it is paired with (a grant
        # can be in several pairings). Other people's assistants never reach yours.
        names = {g.id: f"{g.client_name} …{g.id[-5:]}" for g in grants}
        mates: dict[str, list[dict[str, Any]]] = {}
        for link in links:
            status = link["status"]
            if not link.get("same_account"):
                continue
            if status not in ("active", "pending_approval"):
                continue
            (grant_a, grant_b), (label_a, label_b) = link["grant_ids"], link["assistants"]
            for me, other, label in ((grant_a, grant_b, label_b), (grant_b, grant_a, label_a)):
                mates.setdefault(str(me), []).append(
                    {
                        "name": names.get(str(other), label),
                        "pending": status == "pending_approval",
                    }
                )
        wake_on = box is not None and bool(box.get_webhook(email, "").get("available"))
        # One row per (pairing, assistant): an assistant in two pairings has two senders.
        missing_rows = box.missing_wakeups(email) if wake_on else []
        rows = []
        for g in grants:
            rows.append(
                {
                    "id": g.id,
                    "short_id": g.id[-5:],
                    "name": g.client_name,
                    "app_name": g.app_name or g.client_name,
                    "renamed": g.renamed,
                    "created_at": g.created_at,
                    "last_used": g.last_used,
                    "paired_with": ", ".join(m["name"] for m in mates.get(g.id, [])) or None,
                    "mates": mates.get(g.id, []),
                    "hook": box.get_webhook(email, g.id) if wake_on else None,
                    "role": g.role,
                    "legacy_full": g.legacy_full,
                }
            )
        return {
            "assistants": rows,
            "wake_on": wake_on,
            # Left from when mail from other people existed. It is never woken now; the
            # page only offers to move it to an assistant or remove it.
            "account_hook": box.get_webhook(email, "") if wake_on else None,
            "missing_wakeups": missing_rows,
        }

    async def bridge_page(request: Request) -> Response:
        if ctx.mailbox is None:
            return render(request, "error.html", 404, message="Pairing is not configured.")
        email = str(request.session.get("owner") or "")
        data = await blocking(ctx.mailbox.list_links, email)
        data["missing_wakeups"] = await blocking(ctx.mailbox.missing_wakeups, email)
        # Approving a pairing lets that person's assistant read the Sharing list, so each
        # card that asks for approval says what that list holds right now.
        ext = ctx.ext_allowlist
        data["sharing_on"] = ext is not None
        data["shared_items"] = []
        data["visible_to"] = {}
        if ext is not None:
            entries = await blocking(ext.entries)
            ordered = sorted(entries.values(), key=lambda e: e.granted_at, reverse=True)
            # A new person is never named on an item yet: approving shows them only what
            # is shared with everyone paired.
            data["shared_items"] = [e for e in ordered if e.for_everyone and not e.expired()]
            # Each person you share with: exactly what their assistant can read now.
            for link in data["links"]:
                peer = link.get("peer_email")
                if peer and not link.get("same_account"):
                    data["visible_to"][peer] = [e for e in ordered if e.readable_by(peer)]
        data["drops_on"] = ctx.drops is not None
        data["drops_off"] = await blocking(ctx.drops.off_list) if ctx.drops is not None else set()
        return render(request, "bridge.html", tab="people", **data)

    async def settings_page(request: Request) -> Response:
        email = str(request.session.get("owner") or "")

        def gather() -> dict[str, Any]:
            return {
                "rows": ctx.connection_rows(),
                **assistant_rows(email),
            }

        data = await blocking(gather)
        return render(
            request,
            "settings.html",
            mcp_url=f"{settings.app_base_url}/mcp",
            drive_connected=drive_row_connected(data["rows"]),
            next="/settings",
            missing=settings.missing_settings(),
            store_kind=getattr(ctx.store, "kind", "custom"),
            root_folder_id=ctx.visible_root_folder_id(),
            picker_ready=settings.picker_configured,
            env_token_set=bool(
                settings.env_bot_refresh_token and session_user(request) == settings.owner_email
            ),
            **data,
        )

    async def files_page(request: Request) -> Response:
        request.state.allow_count = len(await blocking(ctx.allowlist.entries))
        request.state.notion_tab = ctx.notion is not None
        if request.query_params.get("tab") == "notion" and ctx.notion is not None:
            # Notion does not need Google Drive, so this tab works without it.
            return await notion_files(request)
        if request.query_params.get("tab") == "allowed":
            return await access(request)
        return await browse(request)

    async def sharing_hub(request: Request) -> Response:
        tab = request.query_params.get("tab") or "people"
        if tab == "by-me":
            return await sharing(request)
        if tab == "with-me":
            return await shared_overview(request)
        return await bridge_page(request)

    def moved(path: str, **extra: str) -> Handler:
        """An old address. Keep its query string so bookmarks and links still land."""

        async def go(request: Request) -> Response:
            params = [(k, v) for k, v in request.query_params.multi_items() if k not in extra]
            params = [*extra.items(), *params]
            target = path + (f"?{urlencode(params)}" if params else "")
            return RedirectResponse(target, status_code=308)

        return go

    def _bridge_act(
        request: Request,
        link_id: str,
        action: str,
        purge: bool = False,
        expect_peer: str | None = None,
    ) -> str:
        email = str(request.session.get("owner") or "")
        if action == "cancel":
            ctx.mailbox.cancel_invite(email, link_id)
            return "Invite cancelled. That code no longer works."
        if action == "dismiss":
            ctx.mailbox.dismiss(email, link_id)
            return "Removed from your list."
        if action == "purge":
            count = ctx.mailbox.delete_messages(email, link_id)["purged_messages"]
            return f"Deleted {count} stored message{'' if count == 1 else 's'} for both of you."
        if action == "revoke":
            peer = next(
                (
                    link["peer_email"]
                    for link in ctx.mailbox.list_links(email)["links"]
                    if link["link_id"] == link_id
                ),
                None,
            )
            same = next(
                (
                    link.get("same_account", False)
                    for link in ctx.mailbox.list_links(email)["links"]
                    if link["link_id"] == link_id
                ),
                False,
            )
            ctx.mailbox.revoke(email, link_id, purge)
            if not same:
                message = (
                    "Pairing turned off. Neither of you can read the other's Sharing list "
                    "through it any more."
                )
                if peer and ctx.mailbox.is_linked(email, peer):
                    message += f" You still have another active pairing with {peer}."
                return message
            message = "Pairing turned off. Your two assistants can no longer message each other."
            if purge:
                return message + " Stored messages were deleted."
            return message + " Messages already delivered stay readable until they expire."
        same = next(
            (
                link.get("same_account", False)
                for link in ctx.mailbox.list_links(email)["links"]
                if link["link_id"] == link_id
            ),
            False,
        )
        # Approving another person is approving that account. The form names the account
        # the page showed, and the approval is refused if someone else is joined by now.
        if action == "approve" and not same and not expect_peer:
            raise MailboxError(
                "peer_changed",
                "Reload the page and check who is asking before you approve.",
            )
        result = ctx.mailbox.decide(
            email, link_id, action, expect_peer if action == "approve" else None
        )
        if same and result["status"] == "active":
            return "Approved. Your two assistants can message each other now."
        if action == "deny" or result["status"] == "revoked":
            return "Pairing declined. Nothing is shared through it."
        if result["status"] == "active":
            return "You approved. You can now share documents with each other."
        return "You approved. Nothing is shared until the other person approves."

    async def bridge_decide(request: Request, form: dict[str, str]) -> Response:
        if ctx.mailbox is None:
            return render(request, "error.html", 404, message="The mailbox is not configured.")
        link_id = request.path_params["link_id"]
        action = request.path_params["action"]
        if action not in ("approve", "deny", "revoke", "cancel", "dismiss", "purge"):
            return render(request, "error.html", 404, message="That page is not available.")
        purge = form.get("purge") == "on"
        try:
            message = await blocking(
                _bridge_act, request, link_id, action, purge, form.get("peer") or None
            )
        except MailboxError as exc:
            flash(request, "error", exc.message)
        else:
            flash(request, "ok", message)
        return RedirectResponse("/sharing?tab=people", status_code=303)

    async def bridge_webhook(request: Request, form: dict[str, str]) -> Response:
        if ctx.mailbox is None:
            return render(request, "error.html", 404, message="The mailbox is not configured.")
        email = str(request.session.get("owner") or "")
        back = safe_next(form.get("next") or WAKE_HOME)
        # "account" (or "" from older pages) is the account-wide slot, left from when mail
        # from other people existed; otherwise one of this person's connected apps.
        raw_app = (form.get("app") or "").strip()
        app = "" if raw_app == "account" else raw_app
        from_app = (form.get("from_app") or "").strip()
        from_app = "" if from_app == "account" else from_app
        action = form.get("action")
        grants = await blocking(ctx.mcp_oauth.list_grants, email) if ctx.mcp_oauth else []
        ids = {g.id for g in grants}
        if (app and app not in ids) or (from_app and from_app not in ids):
            return action_done(request, "error", "That app is not connected.", back)
        if action in (None, "", "save") and not app:
            # The account slot never fires: mail only goes between your own assistants,
            # each to its own wake-up. Make the person say which assistant it starts.
            return action_done(
                request, "error", "Choose which assistant this wake-up starts.", back
            )
        if action == "primary":
            return action_done(
                request,
                "error",
                "Mail from other people is turned off, so there is nothing to answer.",
                back,
            )
        # A failed test wake still changes what the page shows (the last wake), so the
        # settings page refreshes those sections even when the test reports an error.
        changed: bool | None = None
        try:
            if action == "remove":
                await blocking(ctx.mailbox.clear_webhook, email, app)
                kind, message = "ok", "Wake-up removed. Mail still waits for check_messages."
            elif action == "test":
                result = await blocking(ctx.mailbox.test_webhook, email, app)
                changed = True
                if result.get("ok"):
                    kind, message = (
                        "ok",
                        f"Test wake sent (HTTP {result.get('http')}). The assistant should "
                        "start in a few seconds and find no new mail.",
                    )
                else:
                    code = f" (HTTP {result['http']})" if result.get("http") else ""
                    kind, message = (
                        "error",
                        f"Test wake failed{code}: {result.get('error')}. Check the URL and "
                        "key in the assistant that gave them to you, then save them again.",
                    )
            elif action == "move":
                await blocking(ctx.mailbox.move_webhook, email, app, from_app)
                kind, message = "ok", "Wake-up moved to that assistant. Its key moved with it."
            else:
                enabled = form.get("enabled", "true") != "false"
                await blocking(
                    ctx.mailbox.set_webhook,
                    email,
                    form.get("url") or "",
                    sender_key=form.get("sender_key") or None,
                    auth_scheme=form.get("auth_scheme") or "bearer",
                    enabled=enabled,
                    app=app,
                )
                kind, message = "ok", "Wake-up saved. Use Send test wake to check it works."
        except MailboxError as exc:
            kind, message, changed = "error", exc.message, False
        return action_done(request, kind, message, back, changed=changed)

    async def oauth_grant_role(request: Request, form: dict[str, str]) -> Response:
        """The owner changes what one of their connected apps may do."""
        email = str(request.session.get("owner") or "")
        grant_id = form.get("grant_id") or ""
        role = form.get("role") or ""
        back = "/settings#assistants"
        if ctx.mcp_oauth is None or role not in APP_ROLES:
            return action_done(request, "error", "Choose what this app may do.", back)
        if not await blocking(ctx.mcp_oauth.set_role, grant_id, email, role):
            return action_done(request, "error", "That app is not connected.", back)
        names = {g.id: g.client_name for g in ctx.mcp_oauth.list_grants(email)}
        audit_owner(
            "oauth_role", grant=grant_id[-5:], role=role, client=names.get(grant_id, "an app")
        )
        return action_done(
            request, "ok", f"Saved. Its next call runs as {ROLE_LABELS[role]}.", back
        )

    async def oauth_grant_rename(request: Request, form: dict[str, str]) -> Response:
        """The owner gives one of their connected apps a name of their own ("Grok Bot"
        instead of the "Cursor" it registered as). Empty goes back to the app's name."""
        email = str(request.session.get("owner") or "")
        grant_id = form.get("grant_id") or ""
        back = f"/settings#app-{grant_id}" if grant_id else "/settings#assistants"
        if ctx.mcp_oauth is None:
            return action_done(request, "error", "That app is not connected.", back)
        before = {g.id: g.client_name for g in await blocking(ctx.mcp_oauth.list_grants, email)}
        shown = await blocking(ctx.mcp_oauth.set_label, grant_id, email, form.get("name"))
        if shown is None:
            return action_done(request, "error", "That app is not connected.", back)
        if ctx.mailbox is not None:
            try:
                await blocking(ctx.mailbox.relabel_assistant, email, grant_id, shown)
            except Exception:  # noqa: BLE001 - the new name is saved either way
                logging.getLogger(__name__).warning("relabel_pairings_failed", exc_info=True)
        old = before.get(grant_id, "an app")
        if shown != old:
            audit_owner("oauth_rename", grant=grant_id[-5:], client=old, label=shown)
        return action_done(request, "ok", f"Saved. It is now called {shown}.", back)

    async def revoke_oauth_grant(request: Request, form: dict[str, str]) -> Response:
        grant_id = form.get("grant_id") or ""
        if ctx.mcp_oauth is None or not await blocking(
            ctx.mcp_oauth.revoke, grant_id, email=str(request.session.get("owner") or "")
        ):
            return action_done(
                request, "error", "That connection was not found.", "/settings#assistants"
            )
        audit_owner("oauth_revoke")
        return action_done(
            request,
            "ok",
            "Disconnected the assistant. Its tokens no longer work.",
            "/settings#assistants",
        )

    async def confirm_js(_: Request) -> Response:
        return Response(
            b"document.addEventListener('submit',function(e){"
            b"var f=e.target;if(!f||!f.getAttribute)return;"
            # ui.js asks for confirmation itself on background (data-async) forms.
            b"if(window.__asyncForms&&f.hasAttribute('data-async'))return;"
            b"var m=f.getAttribute('data-confirm');if(!m)return;"
            b"if(f.__confirmed){f.__confirmed=false;return;}"
            b"e.preventDefault();var s=e.submitter;"
            # ui.js's in-page dialog when it loaded, else the browser's own confirm().
            b"var ask=window.__askConfirm||function(x){"
            b"return Promise.resolve(window.confirm(x.getAttribute('data-confirm')));};"
            b"ask(f).then(function(ok){if(!ok)return;f.__confirmed=true;"
            b"if(f.requestSubmit)f.requestSubmit(s||undefined);else f.submit();});});",
            media_type="text/javascript",
            headers={"cache-control": "no-store"},
        )

    routes = [
        Route("/confirm.js", confirm_js, methods=["GET"]),
        Route("/login", safely(login), methods=["GET"]),
        Route("/auth/login", safely(auth_login), methods=["GET"]),
        Route("/auth/callback", safely(auth_callback), methods=["GET"]),
        Route("/connect", owner_only(connect_page), methods=["GET"]),
        Route("/connect/{key}", csrf_protected(connect_start), methods=["POST"]),
        Route("/connect/{key}/disconnect", csrf_protected(connect_remove), methods=["POST"]),
        Route("/connect/notion/callback", owner_only(notion_callback), methods=["GET"]),
        Route("/notion/allow", csrf_protected(notion_allow), methods=["POST"]),
        Route("/notion/remove", csrf_protected(notion_remove), methods=["POST"]),
        Route("/logout", csrf_protected(logout), methods=["POST"]),
        Route("/", safely(home), methods=["GET"]),
        Route("/files", owner_only(files_page), methods=["GET"]),
        Route("/browse", moved("/files"), methods=["GET"]),
        Route("/picker/session", owner_only(picker_session), methods=["GET"]),
        Route("/grant", csrf_protected(grant), methods=["POST"]),
        Route("/revoke", csrf_protected(revoke), methods=["POST"]),
        Route("/files/batch", csrf_protected(files_batch), methods=["POST"]),
        Route("/access", moved("/files", tab="allowed"), methods=["GET"]),
        Route("/sharing", owner_only(sharing_hub), methods=["GET"]),
        Route("/settings", owner_only(settings_page), methods=["GET"]),
        Route("/sharing/add", csrf_protected(share_add), methods=["POST"]),
        Route("/sharing/remove", csrf_protected(share_remove), methods=["POST"]),
        Route("/sharing/audience", csrf_protected(share_audience), methods=["POST"]),
        Route("/first-reads/clear", csrf_protected(first_reads_clear), methods=["POST"]),
        Route("/oauth/grants/role", csrf_protected(oauth_grant_role), methods=["POST"]),
        Route("/oauth/grants/rename", csrf_protected(oauth_grant_rename), methods=["POST"]),
        Route("/shared", moved("/sharing", tab="with-me"), methods=["GET"]),
        Route("/shared/search", owner_only(shared_search), methods=["GET"]),
        Route("/shared/browse", owner_only(shared_browse), methods=["GET"]),
        Route("/shared/open", owner_only(shared_open), methods=["GET"]),
        Route("/shared/download", owner_only(shared_download), methods=["GET"]),
        Route(
            "/shared/send",
            body_limited(csrf_protected(drop_send), DROP_UPLOAD_LIMIT + DROP_FORM_OVERHEAD),
            methods=["POST"],
        ),
        Route("/shared/send/start", csrf_protected(drop_begin), methods=["POST"]),
        Route(
            "/shared/send/{upload_id}/piece/{n}",
            body_limited(csrf_protected(drop_piece_put), DROP_PIECE_LIMIT + DROP_FORM_OVERHEAD),
            methods=["POST"],
        ),
        Route("/shared/send/{upload_id}/finish", csrf_protected(drop_finish), methods=["POST"]),
        Route("/drops/allow", csrf_protected(drop_allow), methods=["POST"]),
        Route("/drops/{drop_id}/download", owner_only(drop_download), methods=["GET"]),
        Route("/drops/{drop_id}/piece/{n}", owner_only(drop_piece_get), methods=["GET"]),
        Route("/drops/{drop_id}/piece/{n}/url", owner_only(drop_piece_link), methods=["GET"]),
        Route("/drops/{drop_id}/{action}", csrf_protected(drop_act), methods=["POST"]),
        Route("/requests", owner_only(requests_page), methods=["GET"]),
        Route("/requests/{rid}", owner_only(request_detail), methods=["GET"]),
        Route("/requests/{rid}/approve", csrf_protected(request_approve), methods=["POST"]),
        Route("/requests/{rid}/deny", csrf_protected(request_deny), methods=["POST"]),
        Route("/activity", owner_only(activity), methods=["GET"]),
        Route("/bridge", moved("/sharing", tab="people"), methods=["GET"]),
        Route("/bridge/webhook", csrf_protected(bridge_webhook), methods=["POST"]),
        Route("/bridge/{link_id}/{action}", csrf_protected(bridge_decide), methods=["POST"]),
        Route("/admin", safely(admin_page), methods=["GET"]),
        Route("/admin/sign-records", csrf_protected(admin_sign_records), methods=["POST"]),
        Route("/admin/revoke-legacy-drive", csrf_protected(admin_revoke_legacy), methods=["POST"]),
        Route("/oauth/authorize", safely(oauth_authorize), methods=["GET"]),
        Route("/oauth/authorize", csrf_protected(oauth_decide), methods=["POST"]),
        Route("/oauth/continue", owner_only(oauth_continue), methods=["GET"]),
        Route("/oauth/grants/revoke", csrf_protected(revoke_oauth_grant), methods=["POST"]),
        *legal_routes(),
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
    return "/files?" + urlencode(pairs)


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


def shared_href(view: str, source: str, owner: str, item_id: str | None = None) -> str:
    """Link inside "Shared with me". view is "browse", "open" or "download"."""
    pairs = [("source", source), ("owner", owner)]
    if item_id:
        pairs.append(("id", item_id))
    return f"/shared/{view}?" + urlencode(pairs)


def attachment_disposition(filename: str) -> str:
    """Content-Disposition for a download. The name was typed by another person."""
    cleaned = (
        "".join(
            ch for ch in filename if ord(ch) >= 32 and ord(ch) != 127 and ch not in '"\\/;'
        ).strip()[:200]
        or "download"
    )
    ascii_name = cleaned.encode("ascii", "ignore").decode("ascii").strip() or "download"
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(cleaned, safe='')}"


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
        "application/vnd.google-apps.form": "Google Form",
        "application/vnd.google-apps.drawing": "Google Drawing",
        "application/pdf": "PDF",
        "application/msword": "Word",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "Word",
        "application/vnd.ms-excel": "Excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "Excel",
        "application/vnd.ms-powerpoint": "PowerPoint",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation": "PowerPoint",
        "application/rtf": "Rich text",
        "application/zip": "ZIP",
        "application/json": "JSON",
        "text/csv": "CSV",
    }
    if mime in known:
        return known[mime]
    if mime.startswith("image/"):
        return "Image"
    if mime.startswith("text/"):
        return "Text"
    if mime.startswith("video/"):
        return "Video"
    if mime.startswith("audio/"):
        return "Audio"
    sub = mime.rsplit("/", 1)[-1]
    # Vendor types like "vnd.foo.bar-baz" mean nothing to a person and break narrow layouts.
    return sub if sub and len(sub) <= 16 and not sub.startswith(("vnd.", "x-")) else "File"


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

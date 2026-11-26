"""FastMCP server, tool registration and the ASGI app.

The MCP endpoint creates a fresh stateless `StreamableHTTPSessionManager` per
request and runs it inside that request. FastMCP's own `streamable_http_app()`
needs its session manager started by the ASGI lifespan; that works under uvicorn,
but on serverless runtimes the lifespan may be skipped or may not have finished
before the first request arrives. In stateless JSON mode no state is shared
between requests, so a per-request manager behaves identically and does not
depend on lifespan at all.
"""

import hashlib
import hmac
import logging
import os
from collections.abc import Callable, Mapping
from functools import partial
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import Tool as MCPTool
from pydantic import ValidationError
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route
from starlette.types import Receive, Scope, Send

from . import audit as audit_module
from .access import OWNER_INDEX, REQUEST_TTL, AccessRequests, AccessService
from .agent_roles import ROLE_PATH_PARAM, AgentRoleMiddleware, AgentRoles, current_agent_role
from .audit import audit_owner
from .auth import (
    BearerAuthMiddleware,
    current_actor,
    current_guest,
    current_principal,
    guest_partition,
)
from .bridge import Mailbox
from .config import Settings
from .dashboard import (
    DashboardContext,
    SecurityHeadersMiddleware,
    build_dashboard,
    legal_routes,
    render_plain,
)
from .drive_client import (
    BotNotConnectedError,
    DriveClient,
    GoogleDriveClient,
    GoogleOwnerDriveClient,
    LazyBotDriveClient,
    OwnerDriveClient,
    RoutingDriveClient,
    drive_not_connected_message,
    oauth_credentials,
)
from .drop_storage import (
    BlobApi,
    BlobBudget,
    BlobParts,
    BlobSigner,
    VercelBlobApi,
    blob_configured,
    blob_signer_from_env,
)
from .drops import DropBox, drop_partition
from .external import ExternalShares, acting_as
from .mcp_oauth import McpOAuth, protected_resource_metadata_url
from .notion import NotionService
from .notion_client import HttpNotionApi, NotionApi, NotionOAuth
from .oauth import GoogleOAuthClient, OAuthClient
from .onedrive import OneDriveService
from .onedrive_client import HttpOneDriveApi, OneDriveApi, OneDriveOAuth
from .ops import readiness_route, sweep_route, usable_cron_secret
from .policy import guarded_tool, may_call, require
from .ratelimit import AuthFailureLimitApp, RateLimitApp
from .scope import ScopeGuard
from .service import DriveService
from .shared_sources import DriveSharedSource, SharedWithMe
from .store import (
    EXTERNAL_ALLOWLIST_KEY,
    KEY_PREFIX,
    NOTION_ALLOWLIST_KEY,
    ONEDRIVE_ALLOWLIST_KEY,
    ActivityLog,
    Allowlist,
    FirstReads,
    HiddenFiles,
    KeyValueStore,
    MemoryStore,
    PostgresStore,
    PrefixedStore,
    SignedStore,
    TenantDirectory,
    TokenVault,
    build_store,
    signing_key,
)
from .terminal import TerminalFeature
from .tools import access as access_tools
from .tools import drive as drive_tools
from .tools import drops as drop_tools
from .tools import mailbox as mailbox_tools
from .tools import notion as notion_tools
from .tools import onedrive as onedrive_tools
from .tools import shared as shared_tools
from .tools import uploads as upload_tools
from .tools.instructions import (
    INSTRUCTIONS,
    NOTION_CREATE_INSTRUCTIONS,
    NOTION_INSTRUCTIONS,
    ONEDRIVE_INSTRUCTIONS,
)
from .tools.instructions import WATCH_MAIL as WATCH_MAIL  # imported from here by tests
from .uploads import UploadSessions
from .wake import DEFAULT_ALLOWLIST, WakeSettings, decode_kek

logger = logging.getLogger(__name__)


MCP_PATH = "/mcp"
# The same endpoint, narrowed to one of the caller's named roles (agent_roles.py).
ROLE_MCP_PATH = f"{MCP_PATH}/role/{{{ROLE_PATH_PARAM}}}"
HEALTH_PATH = "/health"


class UnguardedToolError(TypeError):
    """A tool was registered without the role check for its own name."""


class ScopedFastMCP(FastMCP):
    """FastMCP that only lists the tools the caller's role may use, and only registers
    tools that check that role.

    The role check, the audit row and the error mapping all live in `policy.require`.
    Registration is the one place every tool passes through, so it is where a tool
    without that wrapper (or wrapped for another tool's name) is refused: the app fails
    to start instead of serving a tool nothing checks.
    """

    def add_tool(self, fn: Callable[..., Any], name: str | None = None, **kwargs: Any) -> None:
        tool = name or fn.__name__
        if guarded_tool(fn) != tool:
            raise UnguardedToolError(
                f"tool {tool!r} must be wrapped with policy.require({tool!r}) "
                "below @mcp.tool, so its role check and audit row cannot be skipped"
            )
        super().add_tool(fn, name=name, **kwargs)

    def _guarded(self, name: str) -> bool:
        """Registration through `add_tool` already refuses an unchecked tool. This is
        the same test at the point of use, for one put into the tool manager directly."""
        tool = self._tool_manager.get_tool(name)
        return tool is not None and guarded_tool(tool.fn) == name

    async def list_tools(self) -> list[MCPTool]:
        principal = current_principal.get()
        tools = await super().list_tools()
        if principal is None:
            return []
        return [t for t in tools if self._guarded(t.name) and may_call(principal, t.name)]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        if self._tool_manager.get_tool(name) is not None and not self._guarded(name):
            logger.error("refused tool %r: it has no role check", name)
            raise ToolError(f"Permission denied: '{name}' is not available")
        return await super().call_tool(name, arguments)


def create_mcp(
    service: DriveService,
    access: AccessService | None = None,
    mailbox: Mailbox | None = None,
    shares: ExternalShares | None = None,
    notion: NotionService | None = None,
    drops: DropBox | None = None,
    onedrive: OneDriveService | None = None,
    uploads: UploadSessions | None = None,
    notion_create: bool = False,
) -> ScopedFastMCP:
    mcp = ScopedFastMCP(
        "scoped-drive",
        instructions=INSTRUCTIONS
        + (NOTION_INSTRUCTIONS if notion is not None else "")
        + (NOTION_CREATE_INSTRUCTIONS if notion is not None and notion_create else "")
        + (ONEDRIVE_INSTRUCTIONS if onedrive is not None else ""),
        stateless_http=True,
        json_response=True,
        streamable_http_path=MCP_PATH,
        log_level="WARNING",
        # Requests are authenticated with bearer tokens and the server is reached through
        # a public hostname, so the localhost-only Host check would just reject them.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    handler = access.handle_denial if access is not None else None
    guarded = partial(require, on_scope_denied=handler)
    box = mailbox or Mailbox(MemoryStore())
    sessions = uploads or UploadSessions(MemoryStore(), service.max_bytes)
    run_shared = shared_tools.shared_runner(shares)

    # Clients see the tools in the order they are registered here.
    drive_tools.register(mcp, guarded, service)
    access_tools.register(mcp, access)
    mailbox_tools.register(mcp, guarded, box)
    shared_tools.register(mcp, run_shared)
    upload_tools.register(mcp, guarded, service, sessions, run_shared)
    drop_tools.register(mcp, drops)
    notion_tools.register(mcp, notion, notion_create)
    onedrive_tools.register(mcp, onedrive)

    return mcp


class StatelessMCPEndpoint:
    """ASGI endpoint that runs a one-shot stateless session manager per request."""

    def __init__(self, mcp: FastMCP):
        self.mcp = mcp

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # A stateless server has no stream to resume (GET) or session to end (DELETE); a
        # per-request manager would hold a GET open until the platform timeout.
        if scope.get("method") != "POST":
            response = JSONResponse(
                {"error": "method not allowed; send JSON-RPC requests with POST"},
                status_code=405,
                headers={"Allow": "POST"},
            )
            await response(scope, receive, send)
            return
        manager = StreamableHTTPSessionManager(
            app=self.mcp._mcp_server,
            json_response=True,
            stateless=True,
            security_settings=self.mcp.settings.transport_security,
        )
        async with manager.run():
            await manager.handle_request(scope, receive, send)


def _misconfigured_app(exc: ValidationError) -> Starlette:
    problems = [
        {"setting": ".".join(str(p) for p in err["loc"]).upper() or "settings", "error": err["msg"]}
        for err in exc.errors(include_input=False, include_url=False)
    ]
    logger.error("scoped-drive-mcp is misconfigured: %s", problems)

    async def health(_: Request) -> JSONResponse:
        # Names and messages stay in the log. The public body is only a status.
        return JSONResponse({"status": "unavailable"}, status_code=503)

    async def unavailable(_: Request) -> JSONResponse:
        return JSONResponse({"error": "server misconfigured"}, status_code=503)

    async def dashboard_unavailable(_: Request) -> Response:
        return Response("Server misconfigured; see /health.", status_code=503)

    return Starlette(
        routes=[
            Route(HEALTH_PATH, health, methods=["GET"]),
            Route(MCP_PATH, unavailable, methods=["GET", "POST", "DELETE"]),
            *legal_routes(),
            Route("/{path:path}", dashboard_unavailable, methods=["GET", "POST"]),
        ]
    )


def running_on_vercel() -> bool:
    return bool(os.environ.get("VERCEL", "").strip())


STORAGE_MISSING = (
    "Redis is not configured. On Vercel, memory does not survive between requests, so grants, "
    "requests and stored sign-ins would be lost. Connect an Upstash Redis database (it sets "
    "KV_REST_API_URL and KV_REST_API_TOKEN) or set UPSTASH_REDIS_REST_URL and "
    "UPSTASH_REDIS_REST_TOKEN, or connect Neon (it sets DATABASE_URL or POSTGRES_URL), "
    "then redeploy."
)


def _storage_missing_app(settings: Settings) -> Starlette:
    """On Vercel without Redis: refuse to serve instead of silently using per-instance memory."""
    logger.error("scoped-drive-mcp: %s", STORAGE_MISSING)

    async def health(_: Request) -> JSONResponse:
        return JSONResponse({"status": "unavailable"}, status_code=503)

    async def unavailable(_: Request) -> JSONResponse:
        return JSONResponse(
            {"error": "server storage is not configured; see /health"}, status_code=503
        )

    async def dashboard_unavailable(_: Request) -> Response:
        return render_plain("setup.html", status_code=503, missing=[], problem=STORAGE_MISSING)

    return Starlette(
        routes=[
            Route(HEALTH_PATH, health, methods=["GET"]),
            Route(MCP_PATH, unavailable, methods=["GET", "POST", "DELETE"]),
            *legal_routes(),
            Route("/{path:path}", dashboard_unavailable, methods=["GET", "POST"]),
        ]
    )


GuardFactory = Callable[[DriveClient, Settings, Callable[[], Mapping[str, str]]], ScopeGuard]


def _bot_factory(settings: Settings) -> Callable[[str], DriveClient]:
    def factory(refresh_token: str) -> DriveClient:
        if not settings.oauth_client_configured:
            raise BotNotConnectedError("GOOGLE_OAUTH_CLIENT_ID/SECRET are not set")
        return GoogleDriveClient(oauth_credentials(settings, refresh_token))

    return factory


def _owner_factory(settings: Settings) -> Callable[[str], OwnerDriveClient]:
    def factory(refresh_token: str) -> OwnerDriveClient:
        return GoogleOwnerDriveClient(oauth_credentials(settings, refresh_token))

    return factory


def _guest_read_guard(
    routed: DriveClient, settings: Settings, ext_allowlist: Allowlist
) -> ScopeGuard:
    # Guest reads use their own guard. Its only allowlist is the owner's external list,
    # with no ROOT_FOLDER_ID, so the owner's own-bot items never satisfy a guest's check.
    # It is built directly (not with guard_factory) so a test or phase-1 root cannot leak in.
    return ScopeGuard(
        routed,
        None,
        ttl=settings.scope_cache_ttl,
        # Only what this guest may read: shared with everyone paired, or with them by
        # name, and not expired. Cached per (owner, guest).
        allowlist=lambda: ext_allowlist.mime_map_for(current_guest.get()),
        allowlist_ttl=settings.allowlist_cache_ttl,
        admin_email=settings.owner_email,
        partition=lambda: guest_partition(current_actor.get(), current_guest.get()),
    )


def _guest_write_guard(
    routed: DriveClient, settings: Settings, ext_allowlist: Allowlist
) -> ScopeGuard:
    # Writes by a paired person's assistant use their own guard: its only allowlist is what
    # the owner marked editable for that person. Cached apart from reads (same owner key
    # prefix, so the owner's changes clear it too).
    return ScopeGuard(
        routed,
        None,
        ttl=settings.scope_cache_ttl,
        allowlist=lambda: ext_allowlist.edit_map_for(current_guest.get()),
        allowlist_ttl=settings.allowlist_cache_ttl,
        admin_email=settings.owner_email,
        partition=lambda: guest_partition(current_actor.get(), f"w:{current_guest.get() or ''}"),
    )


def _drop_guard(
    routed: DriveClient, settings: Settings, allowed: Callable[[], Mapping[str, str]]
) -> ScopeGuard:
    # Files a paired person sends: held for a while, write-only for the sender. A recipient
    # who saves one writes it into one folder this app makes in their Drive; this guard's
    # only allowlist is that folder.
    return ScopeGuard(
        routed,
        None,
        ttl=settings.scope_cache_ttl,
        allowlist=allowed,
        allowlist_ttl=settings.allowlist_cache_ttl,
        admin_email=settings.owner_email,
        partition=drop_partition,
    )


def _drop_storage(
    settings: Settings,
    kv: KeyValueStore,
    enc_key: str | None,
    blob_api: BlobApi | None,
    blob_signer: BlobSigner | None,
) -> tuple[BlobParts | None, BlobBudget | None, BlobSigner | None]:
    # Held files go to Vercel Blob when a store is connected (tests pass `blob_api`).
    drop_blob: BlobParts | None = None
    drop_budget: BlobBudget | None = None
    if blob_api is None and blob_configured():
        try:
            blob_api = VercelBlobApi()
        except ImportError:
            logger.warning("a Blob store is connected but vercel-blob is not installed")
    if blob_api is not None:
        drop_blob = BlobParts(blob_api, enc_key)
        drop_budget = BlobBudget(
            kv,
            drop_blob,
            monthly_uploads=settings.drop_blob_monthly_uploads,
            held_bytes=settings.drop_blob_storage_mb * 1024 * 1024,
            hold_hours=settings.drop_hold_hours,
        )
        # With the signer (on Vercel, with ENCRYPTION_KEY), the browser moves the bytes
        # to and from Blob itself, sealed with a key per file, through URLs
        # api/blob-sign.mjs signs. Without it every piece goes through this app
        # (tests pass `blob_signer`).
        if blob_signer is None:
            blob_signer = blob_signer_from_env(enc_key, settings.app_base_url)
    else:
        blob_signer = None
    return drop_blob, drop_budget, blob_signer


def _notion_service(
    settings: Settings,
    vault: TokenVault,
    actor_kv: KeyValueStore,
    api_factory: Callable[[str], NotionApi] | None,
    notion_oauth: NotionOAuth | None,
) -> NotionService | None:
    # Notion: offered only when its OAuth client is configured (or a test injects one).
    if notion_oauth is None and settings.notion_configured:
        assert settings.notion_oauth_client_id is not None
        assert settings.notion_oauth_client_secret is not None
        notion_oauth = NotionOAuth(
            settings.notion_oauth_client_id.get_secret_value().strip(),
            settings.notion_oauth_client_secret.get_secret_value().strip(),
            f"{settings.app_base_url}/connect/notion/callback",
        )
    return (
        NotionService(
            lambda: vault,
            Allowlist(actor_kv, NOTION_ALLOWLIST_KEY),
            api_factory or HttpNotionApi,
            notion_oauth,
            base_url=settings.app_base_url,
            max_chars=settings.max_chars,
        )
        if notion_oauth is not None
        else None
    )


def _onedrive_service(
    settings: Settings,
    vault: TokenVault,
    actor_kv: KeyValueStore,
    api_factory: Callable[[str], OneDriveApi] | None,
    onedrive_oauth: OneDriveOAuth | None,
) -> OneDriveService | None:
    # OneDrive: offered only when its OAuth client is configured (or a test injects one).
    if onedrive_oauth is None and settings.onedrive_configured:
        assert settings.onedrive_oauth_client_id is not None
        assert settings.onedrive_oauth_client_secret is not None
        onedrive_oauth = OneDriveOAuth(
            settings.onedrive_oauth_client_id.get_secret_value().strip(),
            settings.onedrive_oauth_client_secret.get_secret_value().strip(),
            f"{settings.app_base_url}/connect/onedrive/callback",
        )
    return (
        OneDriveService(
            lambda: vault,
            Allowlist(actor_kv, ONEDRIVE_ALLOWLIST_KEY),
            api_factory or HttpOneDriveApi,
            onedrive_oauth,
            base_url=settings.app_base_url,
            max_chars=settings.max_chars,
            max_bytes=settings.max_bytes,
            extract_isolation=settings.extract_isolation,
            extract_memory_mb=settings.extract_memory_mb,
        )
        if onedrive_oauth is not None
        else None
    )


def _mcp_endpoint(
    mcp: FastMCP,
    settings: Settings,
    kv: KeyValueStore,
    agent_roles: AgentRoles,
    mcp_oauth: McpOAuth | None,
    base_url: str | None,
) -> AuthFailureLimitApp:
    # Outside auth: bearers that are refused (401) are counted per address, and only
    # those are turned away once an address keeps failing. Inside auth: every accepted
    # caller is counted per connection, so a shared address never throttles a valid token.
    return AuthFailureLimitApp(
        BearerAuthMiddleware(
            RateLimitApp(
                AgentRoleMiddleware(StatelessMCPEndpoint(mcp), agent_roles),
                kv,
                name="mcp",
                limit=settings.mcp_rate_limit,
                window=settings.mcp_rate_window_seconds,
            ),
            tokens=settings.api_tokens,
            exempt_paths=(),
            oauth_resolve=None if mcp_oauth is None else mcp_oauth.resolve_access,
            resource_metadata=(
                None if mcp_oauth is None else protected_resource_metadata_url(base_url)
            ),
            owner_email=settings.owner_email,
        ),
        kv,
        name="mcp",
        limit=settings.mcp_rate_limit,
        window=settings.mcp_rate_window_seconds,
    )


def build_app(
    settings: Settings | None = None,
    drive_client: DriveClient | None = None,
    *,
    guard_factory: GuardFactory | None = None,
    store: KeyValueStore | None = None,
    owner_drive_factory: Callable[[str], OwnerDriveClient] | None = None,
    oauth: OAuthClient | None = None,
    bot_drive_factory: Callable[[str], DriveClient] | None = None,
    notion_api_factory: Callable[[str], NotionApi] | None = None,
    notion_oauth: NotionOAuth | None = None,
    onedrive_api_factory: Callable[[str], OneDriveApi] | None = None,
    onedrive_oauth: OneDriveOAuth | None = None,
    blob_api: BlobApi | None = None,
    blob_signer: BlobSigner | None = None,
) -> Starlette:
    """Build the ASGI app. Tests inject `settings`, fake Drive clients, a store and OAuth."""
    if settings is None:
        try:
            settings = Settings()  # type: ignore[call-arg]
        except ValidationError as exc:
            return _misconfigured_app(exc)

    if (
        store is None
        and not settings.redis_configured
        and not settings.postgres_configured
        and running_on_vercel()
    ):
        return _storage_missing_app(settings)

    kv = PrefixedStore(store) if store is not None else build_store(settings)
    backend = kv.inner  # the store itself, under the key prefix and the signing
    enc_key = settings.encryption_key.get_secret_value() if settings.encryption_key else None
    if enc_key:
        # Everything below reads and writes through this, whichever account it is for.
        kv = SignedStore(kv, signing_key(enc_key), require=settings.require_signed_records)
    directory = TenantDirectory(kv, settings.owner_email, enc_key)
    actor_kv = directory.actor_store()
    allowlist = Allowlist(actor_kv)
    agent_roles = AgentRoles(actor_kv)

    def own_allowlist() -> dict[str, str]:
        """The allowlist, or under a named role only the entries that role lists."""
        items = allowlist.mime_map()
        role = current_agent_role.get()
        if role is None:
            return items
        return {fid: mime for fid, mime in items.items() if fid in role.items}

    def own_partition() -> str:
        actor = current_actor.get() or ""
        role = current_agent_role.get()
        return actor if role is None else guest_partition(actor, f"r:{role.slug}")

    def own_protected() -> frozenset[str]:
        # Under a role, items the owner allowed one by one keep their protection even
        # when the role reaches them through a folder it lists.
        return frozenset(allowlist.mime_map()) if current_agent_role.get() else frozenset()

    ext_allowlist = Allowlist(actor_kv, EXTERNAL_ALLOWLIST_KEY)
    vault = TokenVault(
        actor_kv, enc_key, expected=lambda: current_actor.get() or settings.owner_email
    )

    def note_request_owner(rid: str) -> None:
        who = current_actor.get() or settings.owner_email
        if who:
            kv.set(f"{OWNER_INDEX}{rid}", who, ex=REQUEST_TTL)

    requests = AccessRequests(actor_kv, on_create=note_request_owner)
    activity = ActivityLog(actor_kv)
    first_reads = FirstReads(actor_kv)
    hidden_files = HiddenFiles(actor_kv)
    audit_module.set_sinks([activity])

    def stored_owner_token() -> str | None:
        # Tools act as the signed-in user, limited only by the allowlist.
        # The actor is the admin here; other people never use this client.
        if not vault.enabled:
            return None
        record = vault.owner()
        return record.get("t") if record else None

    def user_owner_token(email: str) -> str | None:
        record = directory.vault_for(email).owner()
        return record.get("t") if record else None

    not_connected = drive_not_connected_message(settings.app_base_url)
    if drive_client is None:
        drive_client = LazyBotDriveClient(
            settings.env_bot_refresh_token,
            stored_owner_token,
            bot_drive_factory or _bot_factory(settings),
            not_connected_message=not_connected,
        )
    routed = RoutingDriveClient(
        drive_client,
        settings.owner_email,
        user_owner_token,
        bot_drive_factory or _bot_factory(settings),
        not_connected_message=not_connected,
    )

    if guard_factory is None:
        guard = ScopeGuard(
            routed,
            settings.root_folder_id,
            ttl=settings.scope_cache_ttl,
            allowlist=own_allowlist,
            allowlist_ttl=settings.allowlist_cache_ttl,
            admin_email=settings.owner_email,
        )
    else:
        guard = guard_factory(routed, settings, own_allowlist)
    # A role sees part of the list, so it must not share the whole list's cache.
    guard.partition_by(own_partition, protected=own_protected)
    service = DriveService(routed, guard, settings)
    webhook_hosts = (
        tuple(
            host.strip().lower()
            for host in settings.webhook_host_allowlist.split(",")
            if host.strip()
        )
        or DEFAULT_ALLOWLIST
    )
    mailbox = Mailbox(
        kv,
        base_url=settings.app_base_url or "",
        strict=isinstance(kv, SignedStore) and kv.require,
        encryption_key=enc_key,
        wake=WakeSettings(
            kek=decode_kek(
                settings.webhook_kek.get_secret_value() if settings.webhook_kek else None
            ),
            allowlist=webhook_hosts,
        ),
    )
    ext_guard = _guest_read_guard(routed, settings, ext_allowlist)

    def forget_each_other(a: str, b: str) -> None:
        """Two people are no longer paired: neither Sharing list names the other any more,
        so approving a new pairing later starts from what is shared with everyone."""
        failed = None
        for owner, guest in ((a, b), (b, a)):
            # Each side on its own: one failing must not leave the other side's names.
            try:
                with acting_as(owner):
                    changed = ext_allowlist.forget_person(guest)
                    if changed:
                        invalidate_ext_guards()
                        audit_owner("share_unpaired", count=str(len(changed)))
            except Exception as exc:  # noqa: BLE001 - re-raised below, after both sides
                failed = exc
        if failed is not None:
            raise failed

    mailbox.on_unpaired = forget_each_other
    ext_write_guard = _guest_write_guard(routed, settings, ext_allowlist)

    def invalidate_ext_guards() -> None:
        ext_guard.invalidate_allowlist()
        ext_write_guard.invalidate_allowlist()

    shares = ExternalShares(
        ext_allowlist,
        DriveService(routed, ext_guard, settings),
        is_linked=mailbox.is_linked,
        active_peers=mailbox.active_peers,
        is_known_user=directory.is_known_user,
        once=lambda key, ttl: actor_kv.set_if_absent(f"once:{key}", "1", ex=ttl),
        first_read=first_reads.add,
        write_service=DriveService(
            routed, ext_write_guard, settings, writer=lambda: current_guest.get()
        ),
        charge_write=lambda guest: actor_kv.incr(f"guestwrites:{guest}", 3600),
        # Read as the owner: what the owner's own assistants were given (plus the admin's
        # ROOT_FOLDER_ID). A paired person may not rename or overwrite those.
        owner_protected=lambda: set(guard.allowed()),
    )
    # The human side of the same shares: the dashboard's "Shared with me" page. Each
    # source runs through the same guest checks as the MCP tools above.
    shared_with_me = SharedWithMe([DriveSharedSource(shares)], mailbox.active_peers)
    drop_guard = _drop_guard(routed, settings, lambda: drop_box.allowed_map())

    def drop_folder_changed() -> None:
        drop_guard.invalidate_allowlist()
        guard.invalidate_allowlist()

    drop_blob, drop_budget, blob_signer = _drop_storage(
        settings, kv, enc_key, blob_api, blob_signer
    )

    drop_box = DropBox(
        actor_kv,
        routed,
        DriveService(
            routed,
            drop_guard,
            settings,
            writer=lambda: current_guest.get(),
            created_note="Sent by {who} through Bot RBAC, saved by its recipient.",
        ),
        allowlist,
        is_linked=mailbox.is_linked,
        is_known_user=directory.is_known_user,
        once=lambda key, ttl: actor_kv.set_if_absent(f"once:{key}", "1", ex=ttl),
        on_folder_change=drop_folder_changed,
        encryption_key=enc_key,
        hold_hours=settings.drop_hold_hours,
        max_bytes=settings.drop_max_mb * 1024 * 1024,
        blob=drop_blob,
        budget=drop_budget,
        signer=blob_signer,
    )
    if not enc_key:
        logger.warning(
            "ENCRYPTION_KEY is not set: files paired people send are held unencrypted "
            "until they are saved or expire"
        )

    def caller_email() -> str | None:
        principal = current_principal.get()
        return (principal.email if principal else None) or settings.owner_email

    def sharer_of(file_id: str) -> str | None:
        email = caller_email()
        return shares.sharer_of(email, file_id) if email else None

    def limited_sign_in() -> bool:
        # Drive access is per file (drive.file): a file this app cannot see may still
        # exist, so the approval page offers to pick it.
        return True

    access = (
        AccessService(
            requests,
            settings.app_base_url,
            guard,
            service.peek_name,
            probe=service.probe,
            sharer_of=sharer_of,
            limited_sign_in=limited_sign_in,
            max_pending=settings.max_pending_requests,
        )
        if settings.app_base_url
        else None
    )
    notion = _notion_service(settings, vault, actor_kv, notion_api_factory, notion_oauth)
    onedrive = _onedrive_service(settings, vault, actor_kv, onedrive_api_factory, onedrive_oauth)
    uploads = UploadSessions(kv, settings.max_bytes)
    mcp = create_mcp(
        service,
        access,
        mailbox,
        shares,
        notion,
        drop_box,
        onedrive,
        uploads,
        notion_create=settings.notion_allow_create,
    )

    if oauth is None and settings.oauth_client_configured and settings.app_base_url:
        assert settings.google_oauth_client_id is not None
        assert settings.google_oauth_client_secret is not None
        oauth = GoogleOAuthClient(
            settings.google_oauth_client_id.get_secret_value(),
            settings.google_oauth_client_secret.get_secret_value(),
            f"{settings.app_base_url}/auth/callback",
        )
    base_url = settings.app_base_url
    mcp_oauth = (
        McpOAuth(
            kv,
            base_url,
            settings.owner_email,
            # Removing someone from ALLOWED_EMAILS also ends their assistants' access.
            signed_in=lambda email: (
                settings.sign_in_allowed(email) and directory.has_owner_refresh(email)
            ),
            rate_limit=(settings.mcp_rate_limit, settings.mcp_rate_window_seconds),
            test_callback=settings.oauth_test_callback,
            loopback_callback=settings.oauth_loopback_callback,
            strict=isinstance(kv, SignedStore) and kv.require,
            encryption_key=enc_key,
            # Client ids are signed, not stored. Derived, so the session key is never used
            # for two things.
            client_key=hmac.new(
                settings.session_secret.get_secret_value().encode(),
                b"botrbac oauth client id v1",
                hashlib.sha256,
            ).digest()
            if settings.session_secret
            else None,
        )
        if base_url and not settings.dashboard_missing()
        else None
    )
    if mcp_oauth is not None:
        # Disconnecting an app (or its grant being dropped) ends its own-assistant pairings.
        mcp_oauth.on_revoke = mailbox.end_assistant_links
    terminal = TerminalFeature(
        kv,
        base_url,
        signed_in=lambda email: settings.sign_in_allowed(email) and directory.is_known_user(email),
        signing_secret=enc_key,
    )
    ctx = DashboardContext(
        settings=settings,
        store=kv,
        allowlist=allowlist,
        vault=vault,
        requests=requests,
        activity=activity,
        first_reads=first_reads,
        hidden=hidden_files,
        oauth=oauth,
        owner_drive_factory=owner_drive_factory or _owner_factory(settings),
        bot_drive=drive_client,
        on_allowlist_change=guard.invalidate_allowlist,
        mcp_oauth=mcp_oauth,
        directory=directory,
        drive_router=routed,
        mailbox=mailbox,
        agent_roles=agent_roles,
        ext_allowlist=ext_allowlist,
        on_ext_change=invalidate_ext_guards,
        shared_with_me=shared_with_me,
        sharer_of=shares.sharer_of,
        notion=notion,
        notion_create=notion is not None and settings.notion_allow_create,
        onedrive=onedrive,
        drops=drop_box,
        terminal=terminal,
    )
    dashboard = build_dashboard(ctx)

    async def health(_: Request) -> JSONResponse:
        # Liveness only. Configuration and connection flags stay off this public route.
        return JSONResponse({"status": "ok"})

    mcp_endpoint = _mcp_endpoint(mcp, settings, kv, agent_roles, mcp_oauth, base_url)
    routes: list[Any] = [
        Route(HEALTH_PATH, health, methods=["GET"]),
        readiness_route(lambda: backend.get(f"{KEY_PREFIX}meta:ready")),
        Route(MCP_PATH, mcp_endpoint),
        Route(ROLE_MCP_PATH, mcp_endpoint),
    ]
    cron_secret = usable_cron_secret(
        settings.cron_secret.get_secret_value() if settings.cron_secret else None
    )
    if cron_secret:
        # Each of these also runs inside ordinary requests. The cron covers a deployment
        # nobody is writing to: expired rows, held-file pieces and dead approvals still go.
        jobs: dict[str, Callable[[], int | None]] = {}
        if isinstance(backend, PostgresStore):
            jobs["expired_rows"] = backend.sweep_all
        if drop_budget is not None:
            jobs["held_file_pieces"] = drop_budget.sweep_now
        if mcp_oauth is not None:
            jobs["unused_approvals"] = mcp_oauth.prune
        routes.append(sweep_route(cron_secret, jobs))
    if mcp_oauth is not None:
        routes.extend(mcp_oauth.routes())
    routes.extend(terminal.api_routes())
    routes.append(Mount("/", app=dashboard))
    # The dashboard sets these on its own pages. /mcp, /health, the OAuth endpoints and
    # the discovery documents sit outside it and get the same headers here.
    app = Starlette(
        routes=routes,
        middleware=[Middleware(SecurityHeadersMiddleware, hsts=settings.secure_cookies)],
    )
    app.state.mcp = mcp
    app.state.mailbox = mailbox
    app.state.service = service
    app.state.dashboard = ctx
    app.state.guard = guard
    app.state.ext_guard = ext_guard
    app.state.shares = shares
    app.state.shared_with_me = shared_with_me
    app.state.drops = drop_box
    app.state.terminal = terminal
    return app

"""OAuth 2.1 authorization server for the MCP endpoint.

Grok Bot, Muse, and other remote MCP clients authenticate only with OAuth (PKCE S256,
RFC 8414 / RFC 7591 / RFC 9728, MCP authorization 2025-06-18). This module is
the authorization server and the protected-resource metadata. It does not replace
pre-shared `API_TOKENS` bearers; those are checked first in `BearerAuthMiddleware`
and never looked up here.

Only hashes of authorization codes, access tokens and refresh tokens are stored.
Redirect URIs are an exact allow list (no open redirects). Issued access tokens
act with role admin on `/mcp` only, and only on the Drive of the person who approved.
"""

import base64
import hashlib
import hmac
import html
import json
import logging
import re
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import anyio.to_thread
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

from .auth import Principal, hash_token
from .config import Role
from .ratelimit import allow, ip_identity
from .store import KeyValueStore, utc_now

logger = logging.getLogger(__name__)

SCOPE = "drive"
CODE_TTL = 300
ACCESS_TTL = 3600
REFRESH_TTL = 30 * 24 * 3600
MAX_ACCESS_TOKENS = 20
MAX_REDIRECTS = 16

CLIENTS_KEY = "oauth:clients"
GRANTS_KEY = "oauth:grants"

# Exact strings. Subdomains, extra paths, queries and trailing-slash variants are rejected.
ALLOWED_REDIRECT_URIS = frozenset(
    {
        "cursor://anysphere.cursor-mcp/oauth/callback",
        "https://www.cursor.com/agents/mcp/oauth/callback",
        "https://www.cursor.com/bot/mcp/oauth/callback",
        "https://cursor.com/agents/mcp/oauth/callback",
        "https://cursor.com/bot/mcp/oauth/callback",
        "https://grok.com/connectors-oauth-exchange-code/",
        # Meta Muse chat. muse.ai is the current host; agent.meta.ai is the older
        # one Muse still sends. The platform callback is used when Muse tests the
        # credential. A registration that includes any other URL is still rejected.
        "https://muse.ai/api/hatch/oauth/callback",
        "https://agent.meta.ai/api/hatch/oauth/callback",
        "https://platform.muse.ai/oauth/credential-test/callback",
        # Claude (claude.ai, Claude Desktop, Claude mobile). Custom connectors are
        # brokered by Anthropic and always send one of these callbacks.
        "https://claude.ai/api/mcp/auth_callback",
        "https://claude.com/api/mcp/auth_callback",
        # ChatGPT apps/connectors, which OpenAI dots also use. ChatGPT sends this stable
        # callback because the metadata below advertises RFC 9207 `iss` support.
        "https://chatgpt.com/connector_platform_oauth_redirect",
        "http://localhost:8787/callback",
        "http://127.0.0.1:8787/callback",
    }
)

_VERIFIER = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
_CHALLENGE = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
_GRANT_ID = re.compile(r"^[A-Za-z0-9_-]{8,128}$")

PRM_PATHS = (
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
    # Some clients append the well-known suffix to the resource path.
    "/mcp/.well-known/oauth-protected-resource",
)
AS_PATHS = (
    "/.well-known/oauth-authorization-server",
    # Canonical issuer has no path. This alias covers clients that append /mcp.
    "/.well-known/oauth-authorization-server/mcp",
)

_NO_STORE = {"cache-control": "no-store", "x-content-type-options": "nosniff"}


class RegistrationError(Exception):
    def __init__(self, error: str, description: str, status: int = 400):
        super().__init__(description)
        self.error = error
        self.description = description
        self.status = status


class TokenError(Exception):
    def __init__(self, error: str, description: str, status: int = 400):
        super().__init__(description)
        self.error = error
        self.description = description
        self.status = status


class AuthorizeError(Exception):
    """`redirect_uri` is set only when it is already known to be an allowed, registered URI."""

    def __init__(
        self,
        error: str,
        description: str,
        redirect_uri: str | None = None,
        state: str | None = None,
    ):
        super().__init__(description)
        self.error = error
        self.description = description
        self.redirect_uri = redirect_uri
        self.state = state


@dataclass
class OAuthClientRecord:
    client_id: str
    client_name: str
    redirect_uris: list[str]
    created_at: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> "OAuthClientRecord":
        data = json.loads(raw)
        uris = data.get("redirect_uris")
        if not isinstance(uris, list) or not all(isinstance(u, str) for u in uris):
            raise ValueError("client record is corrupt")
        return cls(
            client_id=str(data["client_id"]),
            client_name=str(data.get("client_name") or "MCP client"),
            redirect_uris=list(uris),
            created_at=str(data.get("created_at") or ""),
        )


@dataclass
class OAuthGrant:
    id: str
    client_id: str
    client_name: str
    email: str
    created_at: str
    last_used: str | None = None
    access_hashes: list[str] = field(default_factory=list)
    refresh_hash: str | None = None
    code_hash: str | None = None
    refresh_until: int = 0
    # Set on every approval since apps have roles. A grant without it predates roles and
    # keeps full access; a grant with it whose role key is missing fails closed to read.
    roles: bool = False

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> "OAuthGrant":
        data = json.loads(raw)
        hashes = data.get("access_hashes") or []
        if not isinstance(hashes, list):
            raise ValueError("grant record is corrupt")
        return cls(
            id=str(data["id"]),
            client_id=str(data["client_id"]),
            client_name=str(data.get("client_name") or "MCP client"),
            email=str(data.get("email") or ""),
            created_at=str(data.get("created_at") or ""),
            last_used=data.get("last_used"),
            access_hashes=[str(h) for h in hashes],
            refresh_hash=data.get("refresh_hash"),
            code_hash=data.get("code_hash"),
            refresh_until=int(data.get("refresh_until") or 0),
            roles=bool(data.get("roles", False)),
        )


@dataclass(frozen=True)
class GrantView:
    id: str
    client_name: str
    created_at: str
    last_used: str | None
    role: str = Role.ADMIN.value
    # Full only because it was connected before apps had roles; the owner never chose it.
    legacy_full: bool = False
    # The name the app registered with. `client_name` above is what to show: the owner's
    # own name for the connection when they gave it one, otherwise this.
    app_name: str = ""
    renamed: bool = False


# What a connected app may do, chosen by the owner on the consent page and changeable
# later. A connection approved before roles existed has no stored role: it stays admin.
APP_ROLES: tuple[str, ...] = (Role.VIEWER.value, Role.EDITOR.value, Role.ADMIN.value)
DEFAULT_APP_ROLE = Role.VIEWER.value


@dataclass(frozen=True)
class AuthorizeRequest:
    client_id: str
    client_name: str
    redirect_uri: str
    state: str
    code_challenge: str
    resource: str
    requested_scope: str

    def to_dict(self) -> dict[str, str]:
        return {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "state": self.state,
            "code_challenge": self.code_challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
            "resource": self.resource,
            "scope": self.requested_scope,
        }


def done_redirect(base_url: str) -> str:
    return f"{base_url.rstrip('/')}/oauth/done"


def resource_identifier(base_url: str) -> str:
    return f"{base_url.rstrip('/')}/mcp"


def protected_resource_metadata_url(base_url: str) -> str:
    """Path-scoped metadata for the `/mcp` resource (RFC 9728)."""
    return f"{base_url.rstrip('/')}/.well-known/oauth-protected-resource/mcp"


def redirect_allowlist(base_url: str, test_callback: bool = False) -> frozenset[str]:
    """Where an authorization code may be sent. This server's own `/oauth/done` page is
    not one of them unless OAUTH_TEST_CALLBACK is on: a code sent there lands in front of
    the person who clicked Allow, and anyone who registered the app could ask them for it."""
    if test_callback:
        return ALLOWED_REDIRECT_URIS | {done_redirect(base_url)}
    return ALLOWED_REDIRECT_URIS


def pkce_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _same(left: str, right: str) -> bool:
    # Bytes, not str: compare_digest raises TypeError on non-ASCII text.
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


# Marks a parked redirect URL that is encrypted (see park_completion).
_SEALED = "enc1."

# set_if_absent takes a lifetime. Ten years stands in for "does not expire".
_FOR_GOOD = 10 * 365 * 24 * 3600


def _expired(saved: dict[str, Any]) -> bool:
    """A token record past the time it carries. Records from before that have none.
    Checked for access tokens. A refresh token is held to `refresh_until` on its grant,
    which is signed, so the time on its own record is only there for the reader."""
    exp = saved.get("exp")
    return isinstance(exp, (int, float)) and time.time() >= exp


def _safe_state(value: str) -> bool:
    if not 1 <= len(value) <= 1024:
        return False
    return all(ch.isprintable() and ch not in "\r\n" for ch in value)


def _safe_scope(value: str) -> bool:
    if len(value) > 200:
        return False
    return all(ch.isprintable() and ch not in "\r\n" for ch in value)


def _clean_name(value: object) -> str:
    if not isinstance(value, str):
        return "MCP client"
    cleaned = "".join(ch for ch in value.strip() if ch.isprintable())
    cleaned = cleaned[:100].strip()
    return cleaned or "MCP client"


def _with_query(uri: str, params: Mapping[str, str]) -> str:
    parts = urlsplit(uri)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query.update(params)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


def _listed(params: Any, key: str) -> list[str] | None:
    if hasattr(params, "getlist"):
        values = params.getlist(key)
    elif isinstance(params, Mapping) and key in params and params[key] is not None:
        values = [params[key]]
    else:
        values = []
    if any(not isinstance(value, str) for value in values):
        return None
    return list(values)


def _only(params: Any, key: str) -> str | None:
    values = _listed(params, key)
    if values is None or len(values) != 1:
        return None
    return values[0]


MAX_LABEL = 60


def clean_label(value: object) -> str | None:
    """The owner's name for a connection, or None to go back to the app's own name."""
    if not isinstance(value, str):
        return None
    cleaned = " ".join("".join(ch for ch in value if ch.isprintable()).split())
    return cleaned[:MAX_LABEL].strip() or None


def _principal_name(client_name: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", client_name).strip("_.-")[:40]
    if not slug:
        slug = "client"
    return f"oauth:{slug}"[:64]


# The activity log and access requests name an OAuth app by this; the dashboard maps it back.
principal_name = _principal_name


def _at_key(digest: str) -> str:
    return f"oauth:at:{digest}"


def _rt_key(digest: str) -> str:
    return f"oauth:rt:{digest}"


def _code_key(digest: str) -> str:
    return f"oauth:code:{digest}"


def _retired_key(digest: str) -> str:
    return f"oauth:rtused:{digest}"


def _role_key(grant_id: str) -> str:
    return f"oauth:role:{grant_id}"


def _chosen_key(grant_id: str) -> str:
    """Set once the owner picked a role for an app from before roles existed."""
    return f"oauth:rolechosen:{grant_id}"


def _pinned_key(grant_id: str) -> str:
    """Set when the role of an app from before roles existed was written down for it."""
    return f"oauth:rolepinned:{grant_id}"


def _label_key(grant_id: str) -> str:
    """The owner's own name for a connection. A side key, like the role, so a token refresh
    rewriting the grant record never loses it."""
    return f"oauth:label:{grant_id}"


def _seen_key(grant_id: str) -> str:
    return f"oauth:seen:{grant_id}"


def _bounce_key(digest: str) -> str:
    return f"oauth:bounce:{digest}"


def _code_used_key(digest: str) -> str:
    return f"oauth:codeused:{digest}"


def _revoked_key(grant_id: str) -> str:
    return f"oauth:revoked:{grant_id}"


class McpOAuth:
    def __init__(
        self,
        store: KeyValueStore,
        base_url: str,
        owner_email: str | None,
        signed_in: Callable[[str], bool] | None = None,
        *,
        rate_limit: tuple[int, int] | None = None,
        test_callback: bool = False,
        strict: bool = False,
        encryption_key: str | None = None,
    ):
        # Encrypts the one value kept here that is a usable secret as it stands: the
        # redirect URL parked between Allow and the redirect, which carries the code.
        self._fernet = None
        if encryption_key:
            from cryptography.fernet import Fernet

            self._fernet = Fernet(encryption_key.strip().encode())
        else:
            logger.warning(
                "ENCRYPTION_KEY is not set: a sign-in code waiting for its redirect is "
                "readable in the store for up to two minutes"
            )
        self.test_callback = test_callback
        # REQUIRE_SIGNED_RECORDS is on: a record that is missing is never read as
        # permission, because someone who can write to the store can also delete from it.
        self.strict = strict
        # (requests, window seconds) per address for the two unauthenticated endpoints.
        self.rate_limit = rate_limit
        self.store = store
        self.base_url = base_url.rstrip("/")
        self.owner_email = owner_email
        # A person may approve, finish, exchange and refresh only after they have
        # signed in and connected Google Drive (a stored owner refresh token, step 2).
        # Signing in alone, or a forged session with no token, still fails.
        # `signed_in` is optional so a caller can keep the old owner-only check.
        self.signed_in = signed_in
        self.resource = resource_identifier(self.base_url)
        self.metadata_url = protected_resource_metadata_url(self.base_url)
        # Called with (email, grant_id) after any grant is removed, whatever the reason.
        self.on_revoke: Callable[[str, str], None] | None = None

    def _may_act(self, email: str | None) -> bool:
        if not email:
            return False
        if self.signed_in is not None:
            return self.signed_in(email)
        return bool(self.owner_email and email == self.owner_email)

    def redirect_allowed(self, uri: str) -> bool:
        if not uri or any(ch in uri for ch in ("\r", "\n", "\t", " ", "\\")):
            return False
        return uri in redirect_allowlist(self.base_url, self.test_callback)

    def completion_url_ok(self, url: str) -> bool:
        """True when `url` is an allowlisted redirect plus an optional query string."""
        if not url or any(ch in url for ch in ("\r", "\n", "\t", " ", "\\", "#", '"', "<", ">")):
            return False
        base, _, _query = url.partition("?")
        return self.redirect_allowed(base)

    def park_completion(self, url: str, email: str) -> str:
        """Store a one-time same-origin handoff. The authorization code stays server-side."""
        if not self._may_act(email) or not self.completion_url_ok(url):
            raise AuthorizeError("invalid_request", "That redirect URL is not allowed.")
        ticket = secrets.token_urlsafe(32)
        payload = json.dumps({"url": url, "email": email}, separators=(",", ":"))
        if self._fernet is not None:
            # Someone who can read the store must not be able to read the code out of it.
            payload = _SEALED + self._fernet.encrypt(payload.encode()).decode()
        self.store.set(_bounce_key(hash_token(ticket)), payload, ex=120)
        return ticket

    def take_completion(self, ticket: str, email: str | None) -> str | None:
        if not self._may_act(email):
            return None
        if not ticket or len(ticket) > 200:
            return None
        raw = self._consume(_bounce_key(hash_token(ticket)))
        if not raw:
            return None
        if raw.startswith(_SEALED):
            if self._fernet is None:
                logger.warning("parked redirect is encrypted but ENCRYPTION_KEY is not set")
                return None
            from cryptography.fernet import InvalidToken

            try:
                raw = self._fernet.decrypt(raw[len(_SEALED) :].encode()).decode()
            except (InvalidToken, ValueError):
                logger.warning("parked redirect could not be decrypted; Allow has to be redone")
                return None
        elif self._fernet is not None:
            # With a key every parked URL is encrypted. This one is from just before a
            # deploy, or was planted. Either way the person clicks Allow again.
            logger.warning("unencrypted parked redirect refused; Allow has to be redone")
            return None
        try:
            saved = json.loads(raw)
        except ValueError:
            return None
        url = saved.get("url")
        if (
            not isinstance(url, str)
            or saved.get("email") != email
            or not self.completion_url_ok(url)
        ):
            return None
        return url

    # ---- metadata --------------------------------------------------------

    def protected_resource_metadata(self) -> dict[str, Any]:
        return {
            "resource": self.resource,
            "authorization_servers": [self.base_url],
            "bearer_methods_supported": ["header"],
            "scopes_supported": [SCOPE],
        }

    def authorization_server_metadata(self) -> dict[str, Any]:
        return {
            "issuer": self.base_url,
            "authorization_endpoint": f"{self.base_url}/oauth/authorize",
            "token_endpoint": f"{self.base_url}/oauth/token",
            "registration_endpoint": f"{self.base_url}/oauth/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": [SCOPE],
            "response_modes_supported": ["query"],
            # Every authorization response (success or error) carries `iss`.
            "authorization_response_iss_parameter_supported": True,
        }

    def routes(self) -> list[Route]:
        return [
            *[Route(path, self._prm, methods=["GET"]) for path in PRM_PATHS],
            *[Route(path, self._asm, methods=["GET"]) for path in AS_PATHS],
            Route("/oauth/register", self._register, methods=["POST"]),
            Route("/oauth/token", self._token, methods=["POST"]),
            *([Route("/oauth/done", self._done, methods=["GET"])] if self.test_callback else []),
        ]

    async def _prm(self, _: Request) -> JSONResponse:
        return JSONResponse(
            self.protected_resource_metadata(),
            headers={
                "cache-control": "public, max-age=300",
                "access-control-allow-origin": "*",
                "x-content-type-options": "nosniff",
            },
        )

    async def _asm(self, _: Request) -> JSONResponse:
        return JSONResponse(
            self.authorization_server_metadata(),
            headers={
                "cache-control": "public, max-age=300",
                "access-control-allow-origin": "*",
                "x-content-type-options": "nosniff",
            },
        )

    async def _limited(self, request: Request, name: str) -> JSONResponse | None:
        if self.rate_limit is None:
            return None
        limit, window = self.rate_limit
        ident = ip_identity(request.scope)
        if await anyio.to_thread.run_sync(allow, self.store, name, ident, limit, window):
            return None
        response = _oauth_error("slow_down", "Too many requests. Try again shortly.", 429)
        response.headers["retry-after"] = str(window)
        return response

    async def _register(self, request: Request) -> JSONResponse:
        limited = await self._limited(request, "oauth-register")
        if limited is not None:
            return limited
        try:
            payload = await _json_object(request)
            body = await anyio.to_thread.run_sync(self.register, payload)
        except RegistrationError as exc:
            return _oauth_error(exc.error, exc.description, exc.status)
        except Exception:
            logger.exception("oauth registration failed")
            return _oauth_error("server_error", "registration failed", 500)
        return JSONResponse(body, status_code=201, headers=_NO_STORE)

    async def _token(self, request: Request) -> JSONResponse:
        limited = await self._limited(request, "oauth-token")
        if limited is not None:
            return limited
        try:
            form = await _token_form(request)
            body = await anyio.to_thread.run_sync(self.exchange, form)
        except TokenError as exc:
            return _oauth_error(exc.error, exc.description, exc.status)
        except Exception:
            logger.exception("oauth token request failed")
            return _oauth_error("server_error", "token request failed", 500)
        return JSONResponse(body, headers=_NO_STORE)

    async def _done(self, request: Request) -> HTMLResponse:
        # Test deployments only (OAUTH_TEST_CALLBACK). The code is never shown.
        error = html.escape(request.query_params.get("error", ""))
        page = (
            "<!doctype html><meta charset=utf-8><title>OAuth</title>"
            f"<p>error: {error}</p><p>Test callback. Do not give this page's address to anyone.</p>"
        )
        return HTMLResponse(page, headers=_NO_STORE)

    # ---- clients ---------------------------------------------------------

    def register(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        method = payload.get("token_endpoint_auth_method", "none")
        if method != "none":
            raise RegistrationError(
                "invalid_client_metadata",
                "Only public clients (token_endpoint_auth_method=none) are supported.",
            )
        response_types = payload.get("response_types", ["code"])
        if response_types != ["code"]:
            raise RegistrationError("invalid_client_metadata", "response_types must be ['code'].")
        grant_types = payload.get("grant_types", ["authorization_code", "refresh_token"])
        if not isinstance(grant_types, list) or not grant_types:
            raise RegistrationError("invalid_client_metadata", "grant_types is invalid.")
        allowed_grants = {"authorization_code", "refresh_token"}
        if any(not isinstance(item, str) or item not in allowed_grants for item in grant_types):
            raise RegistrationError("invalid_client_metadata", "unsupported grant_types.")
        if "authorization_code" not in grant_types:
            raise RegistrationError("invalid_client_metadata", "authorization_code is required.")
        uris = payload.get("redirect_uris")
        if not isinstance(uris, list) or not uris or len(uris) > MAX_REDIRECTS:
            raise RegistrationError(
                "invalid_redirect_uri", f"redirect_uris must list 1 to {MAX_REDIRECTS} URLs."
            )
        cleaned: list[str] = []
        for uri in uris:
            if not isinstance(uri, str) or not self.redirect_allowed(uri):
                raise RegistrationError("invalid_redirect_uri", "A redirect URL is not allowed.")
            if uri not in cleaned:
                cleaned.append(uri)
        client_id = self._new_client_id()
        record = OAuthClientRecord(
            client_id=client_id,
            client_name=_clean_name(payload.get("client_name")),
            redirect_uris=cleaned,
            created_at=utc_now(),
        )
        self.store.hset(CLIENTS_KEY, client_id, record.to_json())
        return {
            "client_id": record.client_id,
            "client_name": record.client_name,
            "redirect_uris": record.redirect_uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "scope": SCOPE,
        }

    def client(self, client_id: str | None) -> OAuthClientRecord | None:
        if not client_id or len(client_id) > 200:
            return None
        raw = self.store.hget(CLIENTS_KEY, client_id)
        if not raw:
            return None
        try:
            record = OAuthClientRecord.from_json(raw)
        except (ValueError, KeyError, TypeError):
            return None
        if not _same(record.client_id, client_id):
            return None
        return record

    def _new_client_id(self) -> str:
        for _ in range(3):
            client_id = secrets.token_urlsafe(32)
            if self.store.hget(CLIENTS_KEY, client_id) is None:
                return client_id
        raise RegistrationError("server_error", "could not allocate a client id", 500)

    # ---- authorize -------------------------------------------------------

    def parse_authorize(self, params: Any) -> AuthorizeRequest:
        client_id = _only(params, "client_id")
        redirect_uri = _only(params, "redirect_uri")
        record = self.client(client_id)
        redirect_ok = bool(
            record
            and redirect_uri
            and self.redirect_allowed(redirect_uri)
            and redirect_uri in record.redirect_uris
        )
        if not redirect_ok or record is None or redirect_uri is None:
            if record is None:
                description = "Unknown client."
            elif not redirect_uri or not self.redirect_allowed(redirect_uri):
                description = "That redirect URL is not allowed."
            else:
                description = "That redirect URL is not registered for this client."
            raise AuthorizeError("invalid_request", description)

        state = _only(params, "state")
        if state is None or not _safe_state(state):
            raise AuthorizeError(
                "invalid_request", "Missing or invalid state.", redirect_uri=redirect_uri
            )
        if _only(params, "response_type") != "code":
            raise AuthorizeError(
                "unsupported_response_type",
                "Only response_type=code is supported.",
                redirect_uri=redirect_uri,
                state=state,
            )
        if _only(params, "code_challenge_method") != "S256":
            raise AuthorizeError(
                "invalid_request",
                "code_challenge_method must be S256.",
                redirect_uri=redirect_uri,
                state=state,
            )
        challenge = _only(params, "code_challenge")
        if challenge is None or _CHALLENGE.fullmatch(challenge) is None:
            raise AuthorizeError(
                "invalid_request",
                "code_challenge is missing or not S256.",
                redirect_uri=redirect_uri,
                state=state,
            )
        resource = _only(params, "resource")
        if resource != self.resource:
            raise AuthorizeError(
                "invalid_target",
                "resource must be the MCP endpoint.",
                redirect_uri=redirect_uri,
                state=state,
            )
        scopes = _listed(params, "scope")
        if scopes is None or len(scopes) > 1:
            raise AuthorizeError(
                "invalid_request", "Invalid scope.", redirect_uri=redirect_uri, state=state
            )
        requested = scopes[0] if scopes else ""
        if not _safe_scope(requested):
            raise AuthorizeError(
                "invalid_request", "Invalid scope.", redirect_uri=redirect_uri, state=state
            )
        return AuthorizeRequest(
            client_id=record.client_id,
            client_name=record.client_name,
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=challenge,
            resource=resource,
            requested_scope=requested,
        )

    def error_redirect(self, exc: AuthorizeError) -> str:
        if not exc.redirect_uri or not self.redirect_allowed(exc.redirect_uri):
            raise AuthorizeError(exc.error, exc.description)
        params = {
            "error": exc.error,
            "error_description": exc.description,
            "iss": self.base_url,
        }
        if exc.state and _safe_state(exc.state):
            params["state"] = exc.state
        return _with_query(exc.redirect_uri, params)

    def approve(self, email: str, pending: AuthorizeRequest, role: str = DEFAULT_APP_ROLE) -> str:
        if not self._may_act(email):
            raise AuthorizeError("access_denied", "This account cannot approve connections.")
        if role not in APP_ROLES:
            raise AuthorizeError("invalid_request", "Choose what this app may do.")
        # Re-check the client and redirect before sending the browser anywhere.
        self.parse_authorize(QueryMapping(pending.to_dict()))
        grant = OAuthGrant(
            id=secrets.token_urlsafe(16),
            client_id=pending.client_id,
            client_name=pending.client_name,
            email=email,
            created_at=utc_now(),
            roles=True,
        )
        code = secrets.token_urlsafe(32)
        digest = hash_token(code)
        payload = json.dumps(
            {
                "grant_id": grant.id,
                "client_id": pending.client_id,
                "redirect_uri": pending.redirect_uri,
                "code_challenge": pending.code_challenge,
                "resource": pending.resource,
            },
            separators=(",", ":"),
        )
        grant.code_hash = digest
        # The role first, so the grant is never visible without it.
        self.store.set(_role_key(grant.id), role)
        self._save_grant(grant)
        self.store.set(_code_key(digest), payload, ex=CODE_TTL)
        return _with_query(
            pending.redirect_uri,
            {"code": code, "state": pending.state, "iss": self.base_url},
        )

    def deny(self, pending: AuthorizeRequest) -> str:
        self.parse_authorize(QueryMapping(pending.to_dict()))
        return _with_query(
            pending.redirect_uri,
            {
                "error": "access_denied",
                "error_description": "The user denied access.",
                "state": pending.state,
                "iss": self.base_url,
            },
        )

    # ---- tokens ----------------------------------------------------------

    def exchange(self, form: Mapping[str, str]) -> dict[str, Any]:
        grant_type = form.get("grant_type")
        if grant_type == "authorization_code":
            return self._exchange_code(form)
        if grant_type == "refresh_token":
            return self._refresh(form)
        raise TokenError("unsupported_grant_type", "unsupported grant_type")

    def _exchange_code(self, form: Mapping[str, str]) -> dict[str, Any]:
        client = self._require_client(form.get("client_id"))
        code = form.get("code") or ""
        if not code:
            raise TokenError("invalid_request", "code is required")
        code_digest = hash_token(code)
        raw = self._consume(_code_key(code_digest))
        if not raw:
            # A code presented twice may have been stolen: end whatever the first use got.
            used = self.store.get(_code_used_key(code_digest))
            if used:
                self.revoke(used)
            raise TokenError("invalid_grant", "code is invalid or expired")
        try:
            saved = json.loads(raw)
        except ValueError:
            raise TokenError("invalid_grant", "code is invalid or expired") from None
        grant = self._grant(str(saved.get("grant_id", "")))
        if grant is None:
            raise TokenError("invalid_grant", "code is invalid or expired")
        try:
            if not self._may_act(grant.email):
                raise TokenError("invalid_grant", "code is invalid or expired")
            if not _same(str(saved.get("client_id", "")), client.client_id):
                raise TokenError("invalid_grant", "code was issued to a different client")
            if not _same(str(saved.get("redirect_uri", "")), form.get("redirect_uri") or ""):
                raise TokenError("invalid_grant", "redirect_uri does not match")
            if (
                str(saved.get("resource", "")) != self.resource
                or form.get("resource") != self.resource
            ):
                raise TokenError("invalid_target", "resource must be the MCP endpoint")
            verifier = form.get("code_verifier") or ""
            challenge = str(saved.get("code_challenge", ""))
            if not _pkce_ok(verifier, challenge):
                raise TokenError("invalid_grant", "PKCE verification failed")
        except TokenError:
            # The code is spent, so this grant can never get tokens. Do not leave it listed.
            self.revoke(grant.id)
            raise
        grant.code_hash = None
        self.store.set(_code_used_key(code_digest), grant.id, ex=CODE_TTL)
        return self._issue_tokens(grant)

    def _refresh(self, form: Mapping[str, str]) -> dict[str, Any]:
        client = self._require_client(form.get("client_id"))
        token = form.get("refresh_token") or ""
        if not token:
            raise TokenError("invalid_request", "refresh_token is required")
        if form.get("resource") != self.resource:
            raise TokenError("invalid_target", "resource must be the MCP endpoint")
        digest = hash_token(token)
        raw = self._consume(_rt_key(digest))
        if raw is None:
            retired = self.store.get(_retired_key(digest))
            if retired:
                self.revoke(retired)
            raise TokenError("invalid_grant", "refresh token is not valid")
        try:
            saved = json.loads(raw)
        except ValueError:
            raise TokenError("invalid_grant", "refresh token is not valid") from None
        grant = self._grant(str(saved.get("grant_id", "")))
        if (
            grant is None
            or not self._may_act(grant.email)
            or not _same(grant.client_id, client.client_id)
            or grant.refresh_hash is None
            or not _same(grant.refresh_hash, digest)
        ):
            if grant is not None and grant.refresh_hash is not None:
                if not _same(grant.refresh_hash, digest):
                    self.revoke(grant.id)
                else:
                    # The token itself is current; the request was wrong (another client's
                    # id, or Drive is disconnected right now). Put it back so the grant is
                    # not left listed with a refresh token nobody can use.
                    left = grant.refresh_until - int(time.time())
                    if left > 0:
                        self.store.set(_rt_key(digest), raw, ex=left)
            raise TokenError("invalid_grant", "refresh token is not valid")
        remaining = grant.refresh_until - int(time.time())
        if remaining <= 0:
            self.revoke(grant.id)
            raise TokenError("invalid_grant", "refresh token is expired")
        self.store.set(_retired_key(digest), grant.id, ex=remaining)
        grant.refresh_hash = None
        return self._issue_tokens(grant, remaining=remaining)

    def _issue_tokens(self, grant: OAuthGrant, remaining: int | None = None) -> dict[str, Any]:
        now = int(time.time())
        if grant.refresh_until <= 0:
            grant.refresh_until = now + REFRESH_TTL
        if remaining is None:
            remaining = grant.refresh_until - now
        if remaining <= 0:
            self.revoke(grant.id)
            raise TokenError("invalid_grant", "refresh token is expired")
        access = secrets.token_urlsafe(32)
        refresh = secrets.token_urlsafe(32)
        access_digest = hash_token(access)
        refresh_digest = hash_token(refresh)
        access_ttl = min(ACCESS_TTL, remaining)
        claims = {"grant_id": grant.id, "client_id": grant.client_id, "email": grant.email}
        # The record says when it ends, as well as the store dropping it then: a signed
        # record put back in the store without an expiry is still over at that time.
        payload = json.dumps({**claims, "exp": now + access_ttl}, separators=(",", ":"))
        self.store.set(_at_key(access_digest), payload, ex=access_ttl)
        payload = json.dumps({**claims, "exp": now + remaining}, separators=(",", ":"))
        self.store.set(_rt_key(refresh_digest), payload, ex=remaining)
        grant.access_hashes.append(access_digest)
        while len(grant.access_hashes) > MAX_ACCESS_TOKENS:
            self.store.delete(_at_key(grant.access_hashes.pop(0)))
        grant.refresh_hash = refresh_digest
        grant.last_used = utc_now()
        self._save_grant(grant)
        if self.store.get(_revoked_key(grant.id)):
            # Revoked while these tokens were being written: that save just put the
            # grant back. Remove it and the new tokens again.
            self.revoke(grant.id)
            raise TokenError("invalid_grant", "this connection was removed")
        return {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": access_ttl,
            "refresh_token": refresh,
            "scope": SCOPE,
        }

    def _require_client(self, client_id: str | None) -> OAuthClientRecord:
        record = self.client(client_id)
        if record is None:
            raise TokenError("invalid_client", "unknown client", 401)
        return record

    # ---- access tokens and grants ---------------------------------------

    def resolve_access(self, token: str) -> Principal | None:
        """Map an OAuth access token to an admin principal. Not used for API_TOKENS."""
        if not token:
            return None
        digest = hash_token(token)
        raw = self.store.get(_at_key(digest))
        if not raw:
            return None
        try:
            saved = json.loads(raw)
            grant = self._grant(str(saved.get("grant_id", "")))
        except (ValueError, TypeError):
            return None
        if (
            grant is None
            or not self._may_act(grant.email)
            or digest not in grant.access_hashes
            or not _same(str(saved.get("client_id", "")), grant.client_id)
            or _expired(saved)
        ):
            return None
        # Last-use is a side key. Rewriting the grant here races _issue_tokens and can
        # drop a refresh hash or access hash that was saved in between.
        self._note_use(grant.id)
        return Principal(
            # From the registered name, which never changes, so the activity log keeps
            # matching this app after the owner renames it.
            token_name=_principal_name(grant.client_name),
            role=Role(self.role_of(grant)),
            email=grant.email,
            grant_id=grant.id,
            client_name=self.display_name(grant),
        )

    def list_grants(self, email: str | None) -> list[GrantView]:
        if not email:
            return []
        views: list[GrantView] = []
        for raw in self.store.hgetall(GRANTS_KEY).values():
            try:
                grant = OAuthGrant.from_json(raw)
            except (ValueError, KeyError, TypeError):
                continue
            # A grant with no tokens is an approval whose code was never redeemed.
            if grant.email == email and (grant.refresh_hash or grant.access_hashes):
                label = self._label(grant.id)
                views.append(
                    GrantView(
                        id=grant.id,
                        client_name=label or grant.client_name,
                        created_at=grant.created_at,
                        last_used=self._displayed_last_used(grant),
                        role=self.role_of(grant),
                        legacy_full=self._legacy_full(grant),
                        app_name=grant.client_name,
                        renamed=label is not None,
                    )
                )
        views.sort(key=lambda item: item.created_at, reverse=True)
        return views

    def revoke(self, grant_id: str, email: str | None = None) -> bool:
        if _GRANT_ID.fullmatch(grant_id) is None:
            return False
        grant = self._grant(grant_id)
        if grant is None:
            return False
        if email is not None and grant.email != email:
            return False
        # Marker for a token request that loaded the grant before this ran (see _issue_tokens).
        self.store.set(_revoked_key(grant.id), "1", ex=ACCESS_TTL)
        for digest in grant.access_hashes:
            self.store.delete(_at_key(digest))
        if grant.refresh_hash:
            self.store.delete(_rt_key(grant.refresh_hash))
        if grant.code_hash:
            self.store.delete(_code_key(grant.code_hash))
        self.store.delete(_seen_key(grant.id))
        self.store.delete(_role_key(grant.id))
        self.store.delete(_chosen_key(grant.id))
        self.store.delete(_label_key(grant.id))
        self.store.hdel(GRANTS_KEY, grant.id)
        if self.on_revoke is not None:
            try:
                self.on_revoke(grant.email, grant.id)
            except Exception:  # noqa: BLE001 - the grant is gone either way
                logging.getLogger(__name__).exception("oauth_on_revoke_failed")
        return True

    def role_of(self, grant: "OAuthGrant") -> str:
        """The role this app's calls run with. A side key, like last-use, so changing it
        never races a token refresh rewriting the grant record. Only a grant approved
        before roles existed falls back to admin; any other missing or unknown value is
        read only, so a lost key never widens what an app can do."""
        stored = self.store.get(_role_key(grant.id))
        if stored in APP_ROLES:
            return str(stored)
        if grant.roles or self.strict or self.store.get(_chosen_key(grant.id)) is not None:
            return Role.VIEWER.value
        return Role.ADMIN.value

    def _legacy_full(self, grant: "OAuthGrant") -> bool:
        """Full access only because the app was connected before roles existed, and the
        owner has not chosen since. True both before and after that role is written down."""
        if self.store.get(_chosen_key(grant.id)) is not None:
            return False
        if self.store.get(_pinned_key(grant.id)) is not None:
            return self.store.get(_role_key(grant.id)) == Role.ADMIN.value
        return not grant.roles and self.store.get(_role_key(grant.id)) is None

    def pin_legacy_roles(self) -> tuple[int, int]:
        """Write down the role of every app from before apps had roles, and mark its
        grant as having one. Afterwards a role record that goes missing means read only
        for these apps too, as it already does for newer ones. Returns (changed, could not
        be changed): a grant a token refresh rewrote at that moment is left for the next
        run. Run before REQUIRE_SIGNED_RECORDS is turned on (the admin page does)."""
        changed = failed = 0
        for grant_id in list(self.store.hgetall(GRANTS_KEY)):
            grant = self._grant(grant_id)
            if grant is None or grant.roles:
                continue
            if self.store.get(_role_key(grant.id)) not in APP_ROLES:
                # Only if there is still none: a role the owner picks at this moment wins.
                self.store.set_if_absent(_role_key(grant.id), self.role_of(grant), ex=_FOR_GOOD)
                # Written down here, not chosen by the owner: Settings still says so.
                self.store.set(_pinned_key(grant.id), "1")
            if self._mark_roles(grant):
                changed += 1
            else:
                failed += 1
        return changed, failed

    def _mark_roles(self, grant: "OAuthGrant") -> bool:
        """Set `roles` on the stored grant, only if nothing else changed it meanwhile (a
        token refresh rewrites the same record). False when it lost that race."""
        replace = getattr(self.store, "hreplace", None)
        if replace is None:
            return False
        try:
            # The stored text, not this object written out again: an older record may
            # be spelled differently and would never compare equal.
            before = self.store.hget(GRANTS_KEY, grant.id)
            if not before:
                return False
            after = json.dumps({**json.loads(before), "roles": True}, separators=(",", ":"))
            if not replace(GRANTS_KEY, grant.id, before, after):
                return False
            grant.roles = True
            return True
        except Exception:
            logger.warning("could not mark a grant as having a role", exc_info=True)
            return False

    def set_role(self, grant_id: str, email: str, role: str) -> bool:
        """The owner changes what one of their apps may do. Applies on its next call."""
        if role not in APP_ROLES or _GRANT_ID.fullmatch(grant_id) is None:
            return False
        grant = self._grant(grant_id)
        if grant is None or grant.email != email:
            return False
        # The owner has now chosen. A side key (not the grant record, which a token refresh
        # rewrites) marks that, so a lost role key fails closed to read from here on.
        self.store.set(_chosen_key(grant.id), "1")
        self.store.set(_role_key(grant.id), role)
        if not grant.roles:
            # Best effort: also say so on the grant itself, which is signed, so deleting
            # the two side keys cannot bring full access back.
            self._mark_roles(grant)
        return True

    def display_name(self, grant: "OAuthGrant") -> str:
        """What to call this connection: the owner's name for it, else the app's own."""
        return self._label(grant.id) or grant.client_name

    def _label(self, grant_id: str) -> str | None:
        return clean_label(self.store.get(_label_key(grant_id)))

    def set_label(self, grant_id: str, email: str, label: str | None) -> str | None:
        """The owner names one of their connections. An empty name goes back to the name
        the app registered with. Returns the name now shown, or None if not theirs."""
        if _GRANT_ID.fullmatch(grant_id) is None:
            return None
        grant = self._grant(grant_id)
        if grant is None or grant.email != email:
            return None
        cleaned = clean_label(label)
        if cleaned is None or cleaned == grant.client_name:
            self.store.delete(_label_key(grant.id))
            return grant.client_name
        self.store.set(_label_key(grant.id), cleaned)
        return cleaned

    def _note_use(self, grant_id: str) -> None:
        now = utc_now()
        key = _seen_key(grant_id)
        current = self.store.get(key)
        if current is not None and current[:16] == now[:16]:
            return
        self.store.set(key, now, ex=REFRESH_TTL)

    def _displayed_last_used(self, grant: OAuthGrant) -> str | None:
        seen = self.store.get(_seen_key(grant.id))
        if seen and (grant.last_used or "") < seen:
            return seen
        return grant.last_used

    def _grant(self, grant_id: str) -> OAuthGrant | None:
        if not grant_id:
            return None
        raw = self.store.hget(GRANTS_KEY, grant_id)
        if not raw:
            return None
        try:
            grant = OAuthGrant.from_json(raw)
        except (ValueError, KeyError, TypeError):
            return None
        if not _same(grant.id, grant_id):
            return None
        return grant

    def _save_grant(self, grant: OAuthGrant) -> None:
        self.store.hset(GRANTS_KEY, grant.id, grant.to_json())

    def _consume(self, key: str) -> str | None:
        consume = getattr(self.store, "getdel", None)
        if consume is None:
            value = self.store.get(key)
            if value is not None:
                self.store.delete(key)
            return value
        return consume(key)


class QueryMapping:
    def __init__(self, data: Mapping[str, str]):
        self._data = data

    def getlist(self, key: str) -> list[str]:
        value = self._data.get(key)
        if value is None or value == "":
            return []
        return [value]


def _oauth_error(error: str, description: str, status: int) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status,
        headers=_NO_STORE,
    )


async def _json_object(request: Request) -> dict[str, Any]:
    content_type = request.headers.get("content-type", "")
    if "application/json" not in content_type.lower():
        raise RegistrationError("invalid_client_metadata", "Content-Type must be application/json.")
    try:
        payload = await request.json()
    except Exception:
        raise RegistrationError("invalid_client_metadata", "body must be JSON") from None
    if not isinstance(payload, dict):
        raise RegistrationError("invalid_client_metadata", "body must be a JSON object")
    return payload


async def _token_form(request: Request) -> dict[str, str]:
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type.lower():
        try:
            payload = await request.json()
        except Exception:
            raise TokenError("invalid_request", "body must be JSON") from None
        if not isinstance(payload, dict):
            raise TokenError("invalid_request", "body must be an object")
        return {str(k): v for k, v in payload.items() if isinstance(v, str)}
    form = await request.form()
    return {str(k): v for k, v in form.items() if isinstance(v, str)}


def _pkce_ok(verifier: str, challenge: str) -> bool:
    if _VERIFIER.fullmatch(verifier) is None or _CHALLENGE.fullmatch(challenge) is None:
        return False
    return _same(pkce_s256(verifier), challenge)

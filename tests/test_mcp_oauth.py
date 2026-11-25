"""MCP OAuth (no network): discovery, registration, consent, PKCE, tokens, revocation, and
the audit regressions on rate limits, signed client ids and abandoned approvals."""

import base64
import hashlib
import html
import json
import re
import secrets
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import itsdangerous
import pytest

from scoped_drive_mcp import mcp_oauth as mcp_oauth_module
from scoped_drive_mcp import ratelimit
from scoped_drive_mcp.config import Settings
from scoped_drive_mcp.dashboard import SESSION_COOKIE
from scoped_drive_mcp.mcp_oauth import (
    ACCESS_TTL,
    ALLOWED_REDIRECT_URIS,
    CLIENTS_KEY,
    GRANTS_KEY,
    LOOPBACK_REDIRECT_URIS,
    REFRESH_TTL,
    OAuthClientRecord,
    OAuthGrant,
    done_redirect,
)
from scoped_drive_mcp.server import build_app
from scoped_drive_mcp.store import MemoryStore
from tests.conftest import BASE_URL, OWNER_EMAIL, SESSION_SECRET, TOKENS, make_settings
from tests.dash import MCP_HEADERS, client, login, pending_consent_id, post

RESOURCE = f"{BASE_URL}/mcp"
METADATA = f"{BASE_URL}/.well-known/oauth-protected-resource/mcp"
DONE = done_redirect(BASE_URL)
GROK = "https://grok.com/connectors-oauth-exchange-code/"
CURSOR = "cursor://anysphere.cursor-mcp/oauth/callback"
CLAUDE = "https://claude.ai/api/mcp/auth_callback"
CHATGPT = "https://chatgpt.com/connector_platform_oauth_redirect"
LOOPBACK = "http://127.0.0.1:8787/callback"

INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "pytest", "version": "0"},
    },
}
LIST = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
_GRANT_ID = re.compile(r'name="grant_id" value="([^"]+)"')


def s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def register(c, uris: str | list[str], name: str = "Grok Bot", **extra):
    payload = {
        "client_name": name,
        "redirect_uris": [uris] if isinstance(uris, str) else uris,
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    }
    payload.update(extra)
    return c.post("/oauth/register", json=payload)


def auth_params(client_id: str, redirect: str, **extra) -> tuple[str, dict[str, str]]:
    verifier = secrets.token_urlsafe(32)
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect,
        "code_challenge": s256(verifier),
        "code_challenge_method": "S256",
        "state": "state-1",
        "resource": RESOURCE,
    }
    params.update(extra)
    return verifier, params


def exchange(c, client_id: str, code: str, verifier: str, redirect: str, **extra):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect,
        "client_id": client_id,
        "code_verifier": verifier,
        "resource": RESOURCE,
    }
    data.update(extra)
    return c.post("/oauth/token", data=data)


def refresh(c, client_id: str, refresh_token: str):
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
        "resource": RESOURCE,
    }
    return c.post("/oauth/token", data=data)


def bearer(token: str) -> dict[str, str]:
    return {**MCP_HEADERS, "Authorization": f"Bearer {token}"}


def tool_names(c, token: str) -> set[str]:
    init = c.post("/mcp", json=INIT, headers=bearer(token))
    assert init.status_code == 200, init.text
    listed = c.post("/mcp", json=LIST, headers=bearer(token))
    assert listed.status_code == 200, listed.text
    return {item["name"] for item in listed.json()["result"]["tools"]}


def call_tool(c, token: str, tool: str, **arguments) -> dict:
    body = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }
    r = c.post("/mcp", json=body, headers=bearer(token))
    assert r.status_code == 200, r.text
    return r.json()["result"]


def mcp_status(c, token: str) -> int:
    return c.post("/mcp", json=LIST, headers=bearer(token)).status_code


def code_from(location: str) -> str:
    query = parse_qs(urlparse(location).query)
    return query["code"][0]


def posted_redirect(c, response) -> str:
    """Follow the same-origin handoff that a consent POST returns."""
    assert response.status_code == 303, response.text
    location = response.headers["location"]
    assert location.startswith("/oauth/continue?"), location
    assert "code=" not in location
    assert "error=" not in location
    assert location.startswith("/") and not location.startswith("//")
    page = c.get(location)
    assert page.status_code == 200, page.text
    policy = page.headers["content-security-policy"]
    assert "form-action 'self' https://accounts.google.com" in policy
    assert "grok.com" not in policy
    assert "cursor.com" not in policy
    match = re.search(r'http-equiv="refresh" content="0;url=([^"]+)"', page.text)
    assert match, page.text
    target = html.unescape(match.group(1))
    assert "evil.example" not in target
    expired = c.get(location)
    assert expired.status_code == 400
    assert "http-equiv" not in expired.text
    return target


def approved(c, client_id: str, redirect: str = GROK, **decision) -> tuple[str, str]:
    """Open the consent page, click Allow, and return (code, verifier)."""
    verifier, params = auth_params(client_id, redirect)
    assert c.get("/oauth/authorize", params=params).status_code == 200
    allowed = post(c, "/oauth/authorize", decision="allow", **decision)
    return code_from(posted_redirect(c, allowed)), verifier


def connect(c, redirect: str = GROK, name: str = "Grok Bot", **decision) -> tuple[str, dict]:
    """Register, approve and exchange: (client_id, token response)."""
    client_id = register(c, redirect, name=name).json()["client_id"]
    code, verifier = approved(c, client_id, redirect, **decision)
    token = exchange(c, client_id, code, verifier, redirect)
    assert token.status_code == 200, token.text
    return client_id, token.json()


def forge_session(owner: str) -> str:
    signer = itsdangerous.TimestampSigner(SESSION_SECRET)
    payload = base64.b64encode(json.dumps({"owner": owner, "csrf": "tok"}).encode())
    return signer.sign(payload).decode()


def hash_in(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _app(world, memstore, oauth, **overrides):
    settings = make_settings(root_folder_id=None, allowlist_cache_ttl=0, **overrides)
    return build_app(
        settings,
        world.as_user(OWNER_EMAIL),
        store=memstore,
        owner_drive_factory=lambda _token: world.as_user(OWNER_EMAIL),
        oauth=oauth,
    )


@pytest.fixture
def c(p2_app):
    return client(p2_app)


@pytest.fixture
def owner_c(c):
    assert login(c).status_code == 303
    return c


@pytest.fixture
def behind_proxy(monkeypatch):
    """One trusted proxy, so X-Forwarded-For picks the caller's address."""
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "1")


class SpyStore(MemoryStore):
    def __init__(self) -> None:
        super().__init__()
        self.oauth_ops = 0

    def _watch(self, key: str) -> None:
        if "oauth:" in key:
            self.oauth_ops += 1

    def get(self, key: str) -> str | None:
        self._watch(key)
        return super().get(key)

    def hget(self, key: str, field: str) -> str | None:
        self._watch(key)
        return super().hget(key, field)

    def hgetall(self, key: str) -> dict[str, str]:
        self._watch(key)
        return super().hgetall(key)

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        self._watch(key)
        return super().set(key, value, ex)

    def hset(self, key: str, field: str, value: str) -> None:
        self._watch(key)
        return super().hset(key, field, value)


# ---- discovery and the 401 that points to it -------------------------------


def test_metadata_is_public(c) -> None:
    root = c.get("/.well-known/oauth-protected-resource")
    scoped = c.get("/.well-known/oauth-protected-resource/mcp")
    suffixed = c.get("/mcp/.well-known/oauth-protected-resource")
    assert root.status_code == scoped.status_code == suffixed.status_code == 200
    assert root.json() == scoped.json() == suffixed.json()
    body = root.json()
    assert body["resource"] == RESOURCE
    assert body["authorization_servers"] == [BASE_URL]
    assert "authorization" not in {k.lower() for k in root.request.headers}

    meta = c.get("/.well-known/oauth-authorization-server")
    alias = c.get("/.well-known/oauth-authorization-server/mcp")
    assert meta.status_code == alias.status_code == 200
    assert meta.json() == alias.json()
    document = meta.json()
    assert document["issuer"] == BASE_URL
    assert document["authorization_endpoint"] == f"{BASE_URL}/oauth/authorize"
    assert document["token_endpoint"] == f"{BASE_URL}/oauth/token"
    assert document["registration_endpoint"] == f"{BASE_URL}/oauth/register"
    assert document["response_types_supported"] == ["code"]
    assert document["grant_types_supported"] == ["authorization_code", "refresh_token"]
    assert document["code_challenge_methods_supported"] == ["S256"]
    assert document["token_endpoint_auth_methods_supported"] == ["none"]
    assert document["authorization_response_iss_parameter_supported"] is True


def test_mcp_without_token_advertises_metadata(owner_c) -> None:
    missing = owner_c.post("/mcp", json=INIT, headers=MCP_HEADERS)
    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == f'Bearer resource_metadata="{METADATA}"'
    # The dashboard session cookie (sent above) is never an MCP credential.
    assert owner_c.cookies.get(SESSION_COOKIE)
    bad = owner_c.post("/mcp", json=INIT, headers=bearer(secrets.token_urlsafe(32)))
    assert bad.status_code == 401
    assert bad.headers["www-authenticate"] == (
        f'Bearer resource_metadata="{METADATA}", error="invalid_token"'
    )


def test_preshared_api_token_is_not_an_oauth_lookup(world, p2_settings, oauth) -> None:
    spy = SpyStore()
    app = build_app(
        p2_settings,
        world.as_user(p2_settings.owner_email or ""),
        store=spy,
        oauth=oauth,
        owner_drive_factory=lambda _token: world.as_user(p2_settings.owner_email or ""),
    )
    c = client(app)
    names = tool_names(c, TOKENS["viewer"])
    assert names == {
        "search_files",
        "list_folder",
        "get_metadata",
        "read_file",
        "download_file",
        "request_access",
        "check_access_request",
        "request_link",
        "list_links",
        "send_message",
        "list_inbox",
        "check_messages",
        "reply",
        "mark_read",
        "get_webhook",
        "set_webhook",
        "clear_webhook",
        "list_shared_with_me",
        "search_shared_files",
        "list_shared_folder",
        "read_shared_file",
        "download_shared_file",
        "list_drops",
        "read_drop",
        "download_drop",
    }
    assert spy.oauth_ops == 0
    rejected = c.post("/mcp", json=INIT, headers=bearer("not-a-real-token"))
    assert rejected.status_code == 401
    assert spy.oauth_ops > 0


# ---- registration --------------------------------------------------------------


@pytest.mark.parametrize(
    "uri",
    [
        "https://evil.example/callback",
        "https://www.cursor.com.evil.example/agents/mcp/oauth/callback",
        "https://evil.cursor.com/agents/mcp/oauth/callback",
        "https://cursor.com/agents/mcp/oauth/callback/extra",
        "https://cursor.com/agents/mcp/oauth/callback.evil",
        "https://user@cursor.com/agents/mcp/oauth/callback",
        "https://cursor.com/agents/mcp/oauth/callback?next=https://evil.example",
        "https://grok.com/connectors-oauth-exchange-code",
        "https://grok.com/connectors-oauth-exchange-code/extra",
        "https://muse.ai/api/hatch/oauth/callback/",
        "https://www.muse.ai/api/hatch/oauth/callback",
        "https://muse.ai.evil.example/api/hatch/oauth/callback",
        "https://evil.muse.ai/api/hatch/oauth/callback",
        "https://agent.meta.ai/api/hatch/oauth/callback/extra",
        "https://platform.muse.ai/oauth/credential-test/callback/extra",
        "http://muse.ai/api/hatch/oauth/callback",
        "https://claude.ai/api/mcp/auth_callback/",
        "https://evil.claude.ai/api/mcp/auth_callback",
        "https://claude.ai.evil.example/api/mcp/auth_callback",
        "http://claude.ai/api/mcp/auth_callback",
        CHATGPT + "/",
        "http://chatgpt.com/connector_platform_oauth_redirect",
        "https://evil.chatgpt.com/connector_platform_oauth_redirect",
        "https://chatgpt.com.evil.example/connector_platform_oauth_redirect",
        CHATGPT + "?next=https://evil.example",
        # Per-connector callback ids are not on the exact allow list.
        "https://chatgpt.com/connector/oauth/abc123",
        # Loopback is off by default (OAUTH_LOOPBACK_CALLBACK), and exact when on.
        *sorted(LOOPBACK_REDIRECT_URIS),
        "http://localhost:8787/callback/extra",
        "http://localhost:8788/callback",
        "https://localhost:8787/callback",
        "http://127.0.0.1:8787/callback?x=1",
        CURSOR + "/extra",
        "javascript:alert(1)",
    ],
)
def test_registration_rejects_foreign_redirects(c, uri: str) -> None:
    alone = register(c, uri)
    assert alone.status_code == 400
    assert alone.json()["error"] == "invalid_redirect_uri"
    assert "client_id" not in alone.json()
    mixed = register(c, [DONE, uri])
    assert mixed.status_code == 400
    assert mixed.json()["error"] == "invalid_redirect_uri"


def test_registration_accepts_allowed_redirects(c) -> None:
    # Every supported assistant's exact callbacks: Cursor, Grok, Muse, Claude, ChatGPT.
    assert {CLAUDE, CHATGPT, "https://platform.muse.ai/oauth/credential-test/callback"} <= (
        ALLOWED_REDIRECT_URIS
    )
    uris = sorted(ALLOWED_REDIRECT_URIS | {DONE})
    response = register(c, uris, name="Cursor")
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["redirect_uris"] == uris
    assert body["token_endpoint_auth_method"] == "none"
    assert "client_secret" not in body
    assert body["client_id"]
    confidential = register(c, DONE, token_endpoint_auth_method="client_secret_basic")
    assert confidential.status_code == 400
    assert confidential.json()["error"] == "invalid_client_metadata"


def test_registration_is_rate_limited_per_address_and_ipv6_64(
    world, memstore, oauth, behind_proxy
) -> None:
    c = client(_app(world, memstore, oauth, mcp_rate_limit=2, mcp_rate_window_seconds=60))

    def from_(ip: str):
        payload = {
            "client_name": "x",
            "redirect_uris": [GROK],
            "token_endpoint_auth_method": "none",
        }
        return c.post("/oauth/register", json=payload, headers={"X-Forwarded-For": ip})

    assert from_("2001:db8:aa:bb::1").status_code == 201
    assert from_("2001:db8:aa:bb::2").status_code == 201
    # A new address from the same /64 is the same caller.
    blocked = from_("2001:db8:aa:bb:1:2:3:4")
    assert blocked.status_code == 429
    assert blocked.headers["retry-after"] == "60"
    assert from_("2001:db8:aa:bc::1").status_code == 201


def test_registering_stores_nothing_so_a_flood_cannot_block_anyone(owner_c) -> None:
    server = owner_c.app.state.dashboard.mcp_oauth
    waiting = register(owner_c, GROK).json()["client_id"]
    # Someone opens the consent page for it ...
    verifier, params = auth_params(waiting, GROK)
    assert owner_c.get("/oauth/authorize", params=params).status_code == 200
    # ... while a flood of registrations arrives. None of them is stored.
    for _ in range(50):
        assert register(owner_c, GROK).status_code == 201
    assert server.store.hgetall(CLIENTS_KEY) == {}
    # The first person is never cut off.
    code = code_from(posted_redirect(owner_c, post(owner_c, "/oauth/authorize", decision="allow")))
    assert exchange(owner_c, waiting, code, verifier, GROK).status_code == 200


def test_a_tampered_foreign_or_non_ascii_client_id_is_refused(owner_c) -> None:
    server = owner_c.app.state.dashboard.mcp_oauth
    client_id = register(owner_c, GROK).json()["client_id"]
    assert server.client(client_id).redirect_uris == [GROK]
    body, mac = client_id[len(mcp_oauth_module.CLIENT_ID_PREFIX) :].split(".")
    # Claim a different redirect with the old signature.
    forged_body = server._sign_client("Grok Bot", [CLAUDE], "x")[3:].split(".")[0]
    for bad in (
        f"c1.{forged_body}.{mac}",
        f"c1.{body}.{'A' * len(mac)}",
        f"c1.{body}",
        "c1.",
        "c1." + "A" * 3000,
        "c1.abc.é",
    ):
        assert server.client(bad) is None, bad
    # An id signed by another deployment's key is refused too.
    other = mcp_oauth_module.McpOAuth(
        server.store, server.base_url, OWNER_EMAIL, client_key=b"k" * 32
    )
    assert server.client(other._sign_client("Grok Bot", [GROK], "x")) is None
    _verifier, params = auth_params(f"c1.{forged_body}.{mac}", CLAUDE)
    assert owner_c.get("/oauth/authorize", params=params).status_code == 400
    # A non-ASCII id is a refusal, not a server error, at both endpoints.
    verifier, params = auth_params("c1.abc.é", GROK)
    assert owner_c.get("/oauth/authorize", params=params).status_code == 400
    r = owner_c.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": "x",
            "redirect_uri": GROK,
            "client_id": "c1.abc.é",
            "code_verifier": verifier,
        },
    )
    assert r.status_code in (400, 401), r.text


def test_a_client_registered_before_ids_were_signed_still_works(owner_c) -> None:
    server = owner_c.app.state.dashboard.mcp_oauth
    legacy = OAuthClientRecord(
        client_id="legacy-client-id-123",
        client_name="Grok Bot",
        redirect_uris=[GROK],
        created_at=_ago(86400 * 60),
    )
    server.store.hset(CLIENTS_KEY, legacy.client_id, legacy.to_json())
    code, verifier = approved(owner_c, legacy.client_id)
    assert exchange(owner_c, legacy.client_id, code, verifier, GROK).status_code == 200


def test_odd_client_input_is_a_400_not_a_500(owner_c) -> None:
    bad = register(owner_c, GROK, grant_types=[{"a": 1}])
    assert bad.status_code == 400
    client_id = register(owner_c, GROK).json()["client_id"]
    code, verifier = approved(owner_c, client_id)
    assert exchange(owner_c, client_id, code, verifier, "https://é.example/").status_code == 400


# ---- authorization and consent ----------------------------------------------------


def test_authorize_without_session_redirects_to_login(c) -> None:
    created = register(c, DONE)
    _verifier, params = auth_params(created.json()["client_id"], DONE)
    response = c.get("/oauth/authorize", params=params)
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith("/login?next=")
    assert "oauth" in location
    assert DONE not in location


def test_non_owner_session_cannot_open_or_post_consent(c) -> None:
    created = register(c, GROK)
    _verifier, params = auth_params(created.json()["client_id"], GROK)
    c.cookies.set(SESSION_COOKIE, forge_session("eve@example.com"))
    response = c.get("/oauth/authorize", params=params)
    assert response.status_code == 403
    assert "not allowed" in response.text
    assert "location" not in response.headers
    response = c.post("/oauth/authorize", data={"decision": "allow", "csrf": "tok"})
    assert response.status_code == 403
    assert "location" not in response.headers


def test_open_redirect_is_rejected(owner_c) -> None:
    client_id = register(owner_c, GROK).json()["client_id"]
    # Not registered for this client, whether foreign or another platform's callback.
    for redirect in ("https://evil.example/phish", "https://cursor.com/agents/mcp/oauth/callback"):
        _verifier, params = auth_params(client_id, redirect)
        response = owner_c.get("/oauth/authorize", params=params)
        assert response.status_code == 400
        assert "location" not in response.headers


def test_invalid_resource_redirects_with_error_not_a_code(owner_c) -> None:
    created = register(owner_c, GROK)
    _verifier, params = auth_params(
        created.json()["client_id"], GROK, resource="https://evil.example/mcp"
    )
    response = owner_c.get("/oauth/authorize", params=params)
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith(GROK)
    query = parse_qs(urlparse(location).query)
    assert query["error"] == ["invalid_target"]
    assert query["state"] == ["state-1"]
    assert "code" not in query


def test_continue_ignores_an_external_url_query(owner_c) -> None:
    response = owner_c.get(
        "/oauth/continue",
        params={"url": "https://evil.example/phish", "ticket": "nope"},
    )
    assert response.status_code == 400
    assert "evil.example" not in response.text
    assert "http-equiv" not in response.text
    assert "location" not in response.headers


def test_approve_issues_a_code_and_deny_does_not(owner_c) -> None:
    created = register(owner_c, CURSOR, name="Cursor")
    client_id = created.json()["client_id"]
    _verifier, params = auth_params(client_id, CURSOR, scope="something-else")
    page = owner_c.get("/oauth/authorize", params=params)
    assert page.status_code == 200
    assert "Cursor" in page.text
    assert "Drive trash" in page.text
    # Sign-in is identity only now; the Drive connection is what can see the Drive.
    assert "your connected Drive is visible" in page.text
    assert "can still reach the rest of your Drive" not in page.text
    assert "trash_file" not in page.text
    assert "something-else" in page.text
    denied = post(owner_c, "/oauth/authorize", decision="deny")
    target = posted_redirect(owner_c, denied)
    query = parse_qs(urlparse(target).query)
    assert target.startswith(CURSOR)
    assert query["error"] == ["access_denied"]
    assert query["state"] == ["state-1"]
    assert "code" not in query

    verifier, params = auth_params(client_id, CURSOR, state="returned-state")
    assert owner_c.get("/oauth/authorize", params=params).status_code == 200
    blocked = owner_c.post("/oauth/authorize", data={"decision": "allow", "csrf": "nope"})
    assert blocked.status_code == 403
    assert "location" not in blocked.headers
    allowed = post(owner_c, "/oauth/authorize", decision="allow")
    location = posted_redirect(owner_c, allowed)
    assert location.startswith(CURSOR + "?")
    query = parse_qs(urlparse(location).query)
    assert query["state"] == ["returned-state"]
    assert query["code"][0]
    assert query.get("iss") == [BASE_URL]


def test_allow_only_approves_the_request_the_page_showed(owner_c) -> None:
    shown = register(owner_c, GROK, name="Shown App").json()["client_id"]
    other = register(owner_c, GROK, name="Other App").json()["client_id"]
    _, params = auth_params(shown, GROK)
    assert "Shown App" in owner_c.get("/oauth/authorize", params=params).text
    shown_id = pending_consent_id(owner_c)
    # A second request (another tab, or a link someone sent) replaces the pending one.
    _, params = auth_params(other, GROK, state="other")
    assert "Other App" in owner_c.get("/oauth/authorize", params=params).text
    stale = post(owner_c, "/oauth/authorize", decision="allow", consent_id=shown_id)
    assert stale.status_code == 400
    assert "nothing was approved" in stale.text
    assert "No assistants connected" in owner_c.get("/settings").text
    # The page that is still current keeps working after the stale one was refused.
    live = post(owner_c, "/oauth/authorize", decision="allow")
    assert parse_qs(urlparse(posted_redirect(owner_c, live)).query)["state"] == ["other"]


def test_consent_headlines_the_platform_not_the_self_reported_name(owner_c) -> None:
    client_id = register(owner_c, GROK, name="Claude").json()["client_id"]
    _verifier, params = auth_params(client_id, GROK)
    page = owner_c.get("/oauth/authorize", params=params)
    assert page.status_code == 200
    assert "<h1>Allow Grok?</h1>" in page.text
    assert "Allow Claude?" not in page.text
    assert "Only allow this if you just started connecting from Grok yourself." in page.text
    # The name the app chose is still shown, but only as what it calls itself.
    assert "The app calls itself “Claude”" in page.text
    assert "What may Grok do" in page.text


def test_loopback_is_opt_in_and_its_consent_warns_it_is_a_local_program(
    world, memstore, oauth
) -> None:
    # Off by default: test_registration_rejects_foreign_redirects refuses both addresses.
    assert Settings.model_fields["oauth_loopback_callback"].default is False
    c = client(_app(world, memstore, oauth, oauth_loopback_callback=True))
    assert login(c).status_code == 303
    created = register(c, LOOPBACK, name="Claude")
    assert created.status_code == 201, created.text
    _verifier, params = auth_params(created.json()["client_id"], LOOPBACK)
    page = c.get("/oauth/authorize", params=params)
    assert page.status_code == 200
    assert "<h1>Allow a program on this computer?</h1>" in page.text
    assert "This sends access to a program on this computer" in page.text
    assert "127.0.0.1:8787" in page.text
    assert "Allow Claude?" not in page.text


# ---- tokens: the whole flow, PKCE, rotation, expiry ----------------------------------


def test_pkce_and_redirect_mismatch_fail_and_code_is_single_use(owner_c, memstore) -> None:
    """End to end as an MCP client meets it: register, PKCE code flow, call a tool, refresh."""
    client_id = register(owner_c, DONE, name="Local test").json()["client_id"]
    code, verifier = approved(owner_c, client_id, DONE)
    mismatch = exchange(owner_c, client_id, code, verifier, "http://127.0.0.1:8787/callback")
    assert mismatch.status_code == 400
    assert mismatch.json()["error"] == "invalid_grant"
    replay = exchange(owner_c, client_id, code, verifier, DONE)
    assert replay.status_code == 400

    code, verifier = approved(owner_c, client_id, DONE)
    bad_pkce = exchange(owner_c, client_id, code, secrets.token_urlsafe(32), DONE)
    assert bad_pkce.status_code == 400
    assert bad_pkce.json()["error"] == "invalid_grant"
    assert exchange(owner_c, client_id, code, verifier, DONE).status_code == 400

    code, verifier = approved(owner_c, client_id, DONE, role="admin")
    token = exchange(owner_c, client_id, code, verifier, DONE)
    assert token.status_code == 200, token.text
    body = token.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 3600
    assert body["scope"] == "drive"
    assert "client_secret" not in body
    access = body["access_token"]
    refresh_token = body["refresh_token"]
    assert access != refresh_token
    stored = repr(memstore._values)
    assert access not in stored
    assert refresh_token not in stored
    assert code not in stored
    assert hash_in(access) in stored

    names = tool_names(owner_c, access)
    assert len(names) == 38
    assert "trash_file" in names
    # A real tool call: an allowed file reads; one the owner did not allow does not.
    assert post(owner_c, "/grant", file_id="proj-notes").status_code in (200, 303)
    read = call_tool(owner_c, access, "read_file", file_id="proj-notes")
    assert read["isError"] is False
    assert read["structuredContent"]["content"] == "project notes alpha"
    refused = call_tool(owner_c, access, "read_file", file_id="priv-secret")
    assert refused["isError"] is True
    assert "TOP SECRET" not in json.dumps(refused)

    dashboard = owner_c.get("/settings", headers={"Authorization": f"Bearer {access}"})
    assert dashboard.status_code == 200
    assert "Local test" in dashboard.text
    logged_out = client(owner_c.app)
    opened = logged_out.get("/files", headers={"Authorization": f"Bearer {access}"})
    assert opened.status_code == 303
    assert opened.headers["location"].startswith("/login")

    rotated = refresh(owner_c, client_id, refresh_token)
    assert rotated.status_code == 200, rotated.text
    new_refresh = rotated.json()["refresh_token"]
    assert new_refresh != refresh_token
    assert tool_names(owner_c, rotated.json()["access_token"])
    # Reusing a rotated refresh token is theft: it fails and ends the whole grant.
    reused = refresh(owner_c, client_id, refresh_token)
    assert reused.status_code == 400
    assert reused.json()["error"] == "invalid_grant"
    assert refresh(owner_c, client_id, new_refresh).status_code == 400


def test_expired_access_and_refresh_tokens_are_refused(owner_c, monkeypatch) -> None:
    """The expiry is in the signed record itself, so a store that kept the key (or a record
    put back without a TTL) still cannot extend a token's life."""
    client_id, tokens = connect(owner_c)
    assert mcp_status(owner_c, tokens["access_token"]) == 200
    start = time.time()
    clock = SimpleNamespace(time=lambda: start + ACCESS_TTL + 1)
    monkeypatch.setattr(mcp_oauth_module, "time", clock)
    expired = owner_c.post("/mcp", json=LIST, headers=bearer(tokens["access_token"]))
    assert expired.status_code == 401
    assert 'error="invalid_token"' in expired.headers["www-authenticate"]
    # Within the refresh lifetime the app renews and carries on.
    renewed = refresh(owner_c, client_id, tokens["refresh_token"])
    assert renewed.status_code == 200, renewed.text
    assert renewed.json()["expires_in"] == ACCESS_TTL

    clock.time = lambda: start + REFRESH_TTL + 1
    late = refresh(owner_c, client_id, renewed.json()["refresh_token"])
    assert late.status_code == 400
    assert late.json()["error"] == "invalid_grant"
    # An expired connection is removed, not left listed.
    assert "No assistants connected" in owner_c.get("/settings").text


def test_replaying_a_code_ends_the_tokens_it_issued(owner_c) -> None:
    client_id = register(owner_c, GROK).json()["client_id"]
    code, verifier = approved(owner_c, client_id)
    access = exchange(owner_c, client_id, code, verifier, GROK).json()["access_token"]
    assert mcp_status(owner_c, access) == 200
    assert exchange(owner_c, client_id, code, verifier, GROK).status_code == 400
    assert mcp_status(owner_c, access) == 401


def test_a_failed_exchange_leaves_no_connected_app(owner_c) -> None:
    client_id = register(owner_c, GROK, name="Half Done").json()["client_id"]
    code, _ = approved(owner_c, client_id)
    assert "Half Done" not in owner_c.get("/settings").text  # approved, but no tokens yet
    assert exchange(owner_c, client_id, code, secrets.token_urlsafe(32), GROK).status_code == 400
    assert "Half Done" not in owner_c.get("/settings").text


def test_refresh_with_the_wrong_client_does_not_strand_the_grant(owner_c) -> None:
    client_id, tokens = connect(owner_c)
    stranger = register(owner_c, GROK, name="Stranger").json()["client_id"]
    assert refresh(owner_c, stranger, tokens["refresh_token"]).status_code == 400
    again = refresh(owner_c, client_id, tokens["refresh_token"])
    assert again.status_code == 200, again.text


def test_a_connected_app_keeps_refreshing_after_the_client_key_changes(owner_c) -> None:
    server = owner_c.app.state.dashboard.mcp_oauth
    client_id, tokens = connect(owner_c)
    # SESSION_SECRET rotated: this id no longer decodes ...
    server._client_key = b"rotated" * 5
    assert server.client(client_id) is None
    # ... but the connection already made keeps refreshing.
    refreshed = refresh(owner_c, client_id, tokens["refresh_token"])
    assert refreshed.status_code == 200, refreshed.text
    # Another client's id is still refused, and the token is kept for its own client.
    other = register(owner_c, GROK).json()["client_id"]
    assert refresh(owner_c, other, refreshed.json()["refresh_token"]).status_code != 200
    assert refresh(owner_c, client_id, refreshed.json()["refresh_token"]).status_code == 200


def test_access_check_does_not_clobber_rotated_grant(owner_c) -> None:
    _client_id, tokens = connect(owner_c, DONE, name="Local test")
    access = tokens["access_token"]
    oauth = owner_c.app.state.dashboard.mcp_oauth
    store = owner_c.app.state.dashboard.store
    grant_id = next(iter(store.hgetall(GRANTS_KEY)))
    before = store.hget(GRANTS_KEY, grant_id)
    assert oauth.resolve_access(access) is not None
    after = store.hget(GRANTS_KEY, grant_id)
    assert json.loads(after)["access_hashes"] == json.loads(before)["access_hashes"]
    assert json.loads(after)["refresh_hash"] == json.loads(before)["refresh_hash"]
    store.set(f"oauth:seen:{grant_id}", "2099-01-01T00:00:00+00:00", ex=3600)
    assert 'datetime="2099-01-01T00:00:00Z"' in owner_c.get("/settings").text

    original = oauth._grant
    issued: dict[str, str] = {}
    state = {"done": False}

    def hooked(gid: str):
        grant = original(gid)
        if grant is not None and not state["done"]:
            state["done"] = True
            fresh = OAuthGrant.from_json(grant.to_json())
            oauth._issue_tokens(fresh)
            assert fresh.refresh_hash is not None
            issued["hash"] = fresh.refresh_hash
        return grant

    oauth._grant = hooked
    try:
        assert oauth.resolve_access(access) is not None
    finally:
        oauth._grant = original
    assert original(grant_id) is not None
    assert original(grant_id).refresh_hash == issued["hash"]
    assert issued["hash"] != json.loads(before)["refresh_hash"]


# ---- revoking, and bearer tokens on the dashboard -----------------------------------


def test_revoked_grant_cannot_call_mcp(owner_c) -> None:
    client_id, tokens = connect(owner_c)
    access = tokens["access_token"]
    assert "list_folder" in tool_names(owner_c, access)
    page = owner_c.get("/settings")
    assert "Grok Bot" in page.text
    grant_id = _GRANT_ID.search(page.text)
    assert grant_id
    blocked = owner_c.post(
        "/oauth/grants/revoke", data={"grant_id": grant_id.group(1), "csrf": "nope"}
    )
    assert blocked.status_code == 403
    # An OAuth bearer is not a dashboard session, even with a csrf value.
    stranger = client(owner_c.app)
    denied = stranger.post(
        "/oauth/grants/revoke",
        data={"grant_id": grant_id.group(1), "csrf": "tok"},
        headers={"Authorization": f"Bearer {access}"},
    )
    assert denied.status_code == 403
    assert "list_folder" in tool_names(owner_c, access)
    revoked = post(owner_c, "/oauth/grants/revoke", grant_id=grant_id.group(1))
    assert revoked.status_code == 303
    page = owner_c.get("/settings").text
    assert "No assistants connected" in page
    assert grant_id.group(1) not in page
    denied = owner_c.post("/mcp", json=LIST, headers=bearer(access))
    assert denied.status_code == 401
    assert f'resource_metadata="{METADATA}"' in denied.headers["www-authenticate"]
    assert refresh(owner_c, client_id, tokens["refresh_token"]).status_code == 400


# ---- abandoned approvals are removed -----------------------------------------------


def _ago(seconds: int) -> str:
    return (datetime.now(UTC) - timedelta(seconds=seconds)).isoformat(timespec="seconds")


def _backdate_grant(server, grant_id: str, seconds: int) -> None:
    store = server.store
    grant = OAuthGrant.from_json(store.hget(GRANTS_KEY, grant_id))
    grant.created_at = _ago(seconds)
    store.hset(GRANTS_KEY, grant_id, grant.to_json())


def test_approval_whose_code_was_never_exchanged_is_removed(owner_c) -> None:
    server = owner_c.app.state.dashboard.mcp_oauth
    approved(owner_c, register(owner_c, GROK).json()["client_id"])  # never comes back
    (abandoned,) = server.store.hgetall(GRANTS_KEY)
    assert server.store.get(f"oauth:role:{abandoned}") is not None
    connect(owner_c)
    finished = next(g for g in server.store.hgetall(GRANTS_KEY) if g != abandoned)

    # Still inside the code's lifetime: the next approval keeps it.
    _backdate_grant(server, abandoned, 60)
    approved(owner_c, register(owner_c, GROK).json()["client_id"])
    assert abandoned in server.store.hgetall(GRANTS_KEY)

    old = mcp_oauth_module.CODE_TTL + 120
    _backdate_grant(server, abandoned, old)
    _backdate_grant(server, finished, old)
    approved(owner_c, register(owner_c, GROK).json()["client_id"])
    grants = server.store.hgetall(GRANTS_KEY)
    assert abandoned not in grants
    assert server.store.get(f"oauth:role:{abandoned}") is None
    # A connection that got its tokens is untouched.
    assert finished in grants


# ---- rate limits on /mcp follow the caller, not the bearer ----------------------------


def _mcp(c, token: str, ip: str | None = None):
    headers = bearer(token)
    if ip is not None:
        headers["X-Forwarded-For"] = ip
    return c.post("/mcp", json=INIT, headers=headers)


def test_bad_tokens_from_an_address_do_not_block_a_valid_token_there(
    world, memstore, oauth, behind_proxy
) -> None:
    c = client(_app(world, memstore, oauth, mcp_rate_limit=2, mcp_rate_window_seconds=60))
    office = "203.0.113.7"
    assert _mcp(c, "made-up-1", office).status_code == 401
    assert _mcp(c, "made-up-2", office).status_code == 401
    # The address used up its allowance for refused bearers ...
    blocked = _mcp(c, "made-up-3", office)
    assert blocked.status_code == 429
    assert blocked.json() == {"error": "rate_limited"}
    assert blocked.headers["retry-after"] == "60"
    # It still says the token was refused, so a client with an expired one refreshes.
    assert 'error="invalid_token"' in blocked.headers["www-authenticate"]
    # ... but a valid token from the same address still works.
    assert _mcp(c, TOKENS["viewer"], office).status_code == 200
    # Bad tokens from there are still refused ...
    assert _mcp(c, "made-up-4", office).status_code == 429
    # ... but a request with no token still gets the 401 that tells it where to sign in.
    for _ in range(3):
        missing = c.post("/mcp", json=INIT, headers={**MCP_HEADERS, "X-Forwarded-For": office})
        assert missing.status_code == 401
        assert "resource_metadata" in missing.headers["www-authenticate"]
    # Another address is not affected.
    assert _mcp(c, "made-up-5", "198.51.100.9").status_code == 401
    # Addresses in one IPv6 /64 share one count.
    assert _mcp(c, "bad-1", "2001:db8:5:6::1").status_code == 401
    assert _mcp(c, "bad-2", "2001:db8:5:6::2").status_code == 401
    assert _mcp(c, "bad-3", "2001:db8:5:6::3").status_code == 429


def test_refreshing_an_oauth_token_does_not_reset_the_mcp_limit(world, memstore, oauth) -> None:
    c = client(_app(world, memstore, oauth, mcp_rate_limit=3, mcp_rate_window_seconds=60))
    assert login(c).status_code == 303
    client_id, tokens = connect(c)
    for _ in range(3):
        assert _mcp(c, tokens["access_token"]).status_code == 200
    assert _mcp(c, tokens["access_token"]).status_code == 429
    renewed = refresh(c, client_id, tokens["refresh_token"])
    assert renewed.status_code == 200, renewed.text
    fresh = renewed.json()["access_token"]
    assert fresh != tokens["access_token"]
    # Same connection, same window: the new token does not start a new allowance.
    assert _mcp(c, fresh).status_code == 429
    # Another caller (an API token) has its own.
    assert _mcp(c, TOKENS["viewer"]).status_code == 200


def _scope(host: str) -> dict:
    return {"type": "http", "client": (host, 1234), "headers": []}


def test_ipv6_addresses_are_counted_per_64(monkeypatch) -> None:
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.delenv("TRUSTED_PROXY_HOPS", raising=False)
    one = ratelimit.ip_identity(_scope("2001:db8:1:2::1"))
    assert one == ratelimit.ip_identity(_scope("2001:db8:1:2:ffff:abcd:1234:5"))
    assert one == "ip:2001:db8:1:2::/64"
    assert one != ratelimit.ip_identity(_scope("2001:db8:1:3::1"))
    # An IPv4-mapped IPv6 address is the IPv4 address it carries.
    assert ratelimit.ip_identity(_scope("::ffff:192.0.2.5")) == ratelimit.ip_identity(
        _scope("192.0.2.5")
    )
    assert ratelimit.ip_identity(_scope("192.0.2.5")) == "ip:192.0.2.5"
    assert ratelimit.address_bucket("testclient") == "testclient"

"""Regression tests for the auth and rate-limit audit findings.

1. Bad bearers from a shared address must not lock out valid tokens from it.
2. The /mcp limit follows the connection, not the raw bearer; IPv6 counts per /64.
3. Abandoned registrations and approvals do not stay in the store for good.
4. The consent page names the app by where the approval goes; loopback is opt-in.
"""

from datetime import UTC, datetime, timedelta

import pytest

from scoped_drive_mcp import mcp_oauth as mcp_oauth_module
from scoped_drive_mcp import ratelimit
from scoped_drive_mcp.config import Settings
from scoped_drive_mcp.mcp_oauth import CLIENTS_KEY, GRANTS_KEY, OAuthClientRecord, OAuthGrant
from scoped_drive_mcp.server import build_app
from tests.conftest import OWNER_EMAIL, TOKENS, make_settings
from tests.dash import MCP_HEADERS, client, login
from tests.test_mcp_oauth import (
    GROK,
    INIT,
    _approved,
    _refresh,
    auth_params,
    code_from,
    exchange,
    post,
    posted_redirect,
    register,
)

LOOPBACK = "http://127.0.0.1:8787/callback"
CLAUDE = "https://claude.ai/api/mcp/auth_callback"


def _app(world, memstore, oauth, **overrides):
    settings = make_settings(root_folder_id=None, allowlist_cache_ttl=0, **overrides)
    return build_app(
        settings,
        world.as_user(OWNER_EMAIL),
        store=memstore,
        owner_drive_factory=lambda _token: world.as_user(OWNER_EMAIL),
        oauth=oauth,
    )


def _mcp(c, token: str, ip: str | None = None):
    headers = {**MCP_HEADERS, "Authorization": f"Bearer {token}"}
    if ip is not None:
        headers["X-Forwarded-For"] = ip
    return c.post("/mcp", json=INIT, headers=headers)


@pytest.fixture
def behind_proxy(monkeypatch):
    """One trusted proxy, so X-Forwarded-For picks the caller's address."""
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "1")


# ---- 1. bad bearers do not lock out valid tokens behind the same address ----


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


# ---- 2. the /mcp limit follows the connection, not the bearer ----


def test_refreshing_an_oauth_token_does_not_reset_the_mcp_limit(world, memstore, oauth) -> None:
    c = client(_app(world, memstore, oauth, mcp_rate_limit=3, mcp_rate_window_seconds=60))
    assert login(c).status_code == 303
    client_id = register(c, GROK).json()["client_id"]
    code, verifier = _approved(c, client_id)
    tokens = exchange(c, client_id, code, verifier, GROK).json()
    for _ in range(3):
        assert _mcp(c, tokens["access_token"]).status_code == 200
    assert _mcp(c, tokens["access_token"]).status_code == 429
    renewed = _refresh(c, client_id, tokens["refresh_token"])
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


def test_registration_limit_covers_the_whole_ipv6_64(world, memstore, oauth, behind_proxy) -> None:
    c = client(_app(world, memstore, oauth, mcp_rate_limit=2, mcp_rate_window_seconds=60))

    def from_(ip: str):
        return c.post(
            "/oauth/register",
            json={
                "client_name": "x",
                "redirect_uris": [GROK],
                "token_endpoint_auth_method": "none",
            },
            headers={"X-Forwarded-For": ip},
        )

    assert from_("2001:db8:aa:bb::1").status_code == 201
    assert from_("2001:db8:aa:bb::2").status_code == 201
    # A new address from the same /64 is the same caller.
    assert from_("2001:db8:aa:bb:1:2:3:4").status_code == 429
    assert from_("2001:db8:aa:bc::1").status_code == 201


def test_bad_tokens_from_one_ipv6_64_share_one_count(world, memstore, oauth, behind_proxy) -> None:
    c = client(_app(world, memstore, oauth, mcp_rate_limit=2, mcp_rate_window_seconds=60))
    assert _mcp(c, "bad-1", "2001:db8:5:6::1").status_code == 401
    assert _mcp(c, "bad-2", "2001:db8:5:6::2").status_code == 401
    assert _mcp(c, "bad-3", "2001:db8:5:6::3").status_code == 429


# ---- 3. registering stores nothing; abandoned approvals are removed ----


def _ago(seconds: int) -> str:
    return (datetime.now(UTC) - timedelta(seconds=seconds)).isoformat(timespec="seconds")


def _backdate_grant(server, grant_id: str, seconds: int) -> None:
    store = server.store
    grant = OAuthGrant.from_json(store.hget(GRANTS_KEY, grant_id))
    grant.created_at = _ago(seconds)
    store.hset(GRANTS_KEY, grant_id, grant.to_json())


def test_registering_stores_nothing_so_a_flood_cannot_block_anyone(
    world, memstore, oauth, monkeypatch
) -> None:
    app = _app(world, memstore, oauth)
    server = app.state.dashboard.mcp_oauth
    c = client(app)
    assert login(c).status_code == 303
    waiting = register(c, GROK).json()["client_id"]
    # Someone opens the consent page for it ...
    verifier, params = auth_params(waiting, GROK)
    assert c.get("/oauth/authorize", params=params).status_code == 200
    # ... while a flood of registrations arrives. None of them is stored.
    for _ in range(200):
        assert register(c, GROK).status_code == 201
    assert server.store.hgetall(CLIENTS_KEY) == {}
    # The first person is never cut off.
    code = code_from(posted_redirect(c, post(c, "/oauth/authorize", decision="allow")))
    assert exchange(c, waiting, code, verifier, GROK).status_code == 200


def test_a_tampered_or_foreign_client_id_is_refused(world, memstore, oauth) -> None:
    app = _app(world, memstore, oauth)
    server = app.state.dashboard.mcp_oauth
    c = client(app)
    client_id = register(c, GROK).json()["client_id"]
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
    ):
        assert server.client(bad) is None, bad
    # An id signed by another deployment's key is refused too.
    other = mcp_oauth_module.McpOAuth(
        server.store, server.base_url, OWNER_EMAIL, client_key=b"k" * 32
    )
    assert server.client(other._sign_client("Grok Bot", [GROK], "x")) is None
    verifier, params = auth_params(f"c1.{forged_body}.{mac}", CLAUDE)
    assert login(c).status_code == 303
    assert c.get("/oauth/authorize", params=params).status_code == 400


def test_a_client_registered_before_ids_were_signed_still_works(world, memstore, oauth) -> None:
    app = _app(world, memstore, oauth)
    server = app.state.dashboard.mcp_oauth
    legacy = OAuthClientRecord(
        client_id="legacy-client-id-123",
        client_name="Grok Bot",
        redirect_uris=[GROK],
        created_at=_ago(86400 * 60),
    )
    server.store.hset(CLIENTS_KEY, legacy.client_id, legacy.to_json())
    c = client(app)
    assert login(c).status_code == 303
    code, verifier = _approved(c, legacy.client_id)
    assert exchange(c, legacy.client_id, code, verifier, GROK).status_code == 200


def test_approval_whose_code_was_never_exchanged_is_removed(world, memstore, oauth) -> None:
    app = _app(world, memstore, oauth)
    server = app.state.dashboard.mcp_oauth
    c = client(app)
    assert login(c).status_code == 303
    client_id = register(c, GROK).json()["client_id"]
    _approved(c, client_id)  # Allow clicked; the app never comes back for its code.
    (abandoned,) = server.store.hgetall(GRANTS_KEY)
    assert server.store.get(f"oauth:role:{abandoned}") is not None
    finished_client = register(c, GROK).json()["client_id"]
    code, verifier = _approved(c, finished_client)
    assert exchange(c, finished_client, code, verifier, GROK).status_code == 200
    finished = next(g for g in server.store.hgetall(GRANTS_KEY) if g != abandoned)

    # Still inside the code's lifetime: the next approval keeps it.
    _backdate_grant(server, abandoned, 60)
    _approved(c, register(c, GROK).json()["client_id"])
    assert abandoned in server.store.hgetall(GRANTS_KEY)

    old = mcp_oauth_module.CODE_TTL + 120
    _backdate_grant(server, abandoned, old)
    _backdate_grant(server, finished, old)
    _approved(c, register(c, GROK).json()["client_id"])
    grants = server.store.hgetall(GRANTS_KEY)
    assert abandoned not in grants
    assert server.store.get(f"oauth:role:{abandoned}") is None
    # A connection that got its tokens is untouched.
    assert finished in grants


# ---- 4. the consent page names the app by its redirect; loopback is opt-in ----


def test_consent_headlines_the_platform_not_the_self_reported_name(world, memstore, oauth) -> None:
    c = client(_app(world, memstore, oauth))
    assert login(c).status_code == 303
    client_id = register(c, GROK, name="Claude").json()["client_id"]
    from tests.test_mcp_oauth import auth_params

    _verifier, params = auth_params(client_id, GROK)
    page = c.get("/oauth/authorize", params=params)
    assert page.status_code == 200
    assert "<h1>Allow Grok?</h1>" in page.text
    assert "Allow Claude?" not in page.text
    assert "Only allow this if you just started connecting from Grok yourself." in page.text
    # The name the app chose is still shown, but only as what it calls itself.
    assert "The app calls itself “Claude”" in page.text
    assert "What may Grok do" in page.text


def test_loopback_redirects_are_off_by_default(world, memstore, oauth) -> None:
    assert Settings.model_fields["oauth_loopback_callback"].default is False
    c = client(_app(world, memstore, oauth))
    refused = register(c, LOOPBACK)
    assert refused.status_code == 400
    assert refused.json()["error"] == "invalid_redirect_uri"
    assert register(c, "http://localhost:8787/callback").status_code == 400
    assert register(c, CLAUDE).status_code == 201


def test_loopback_consent_warns_it_is_a_local_program(world, memstore, oauth) -> None:
    c = client(_app(world, memstore, oauth, oauth_loopback_callback=True))
    assert login(c).status_code == 303
    created = register(c, LOOPBACK, name="Claude")
    assert created.status_code == 201, created.text
    from tests.test_mcp_oauth import auth_params

    _verifier, params = auth_params(created.json()["client_id"], LOOPBACK)
    page = c.get("/oauth/authorize", params=params)
    assert page.status_code == 200
    assert "<h1>Allow a program on this computer?</h1>" in page.text
    assert "This sends access to a program on this computer" in page.text
    assert "127.0.0.1:8787" in page.text
    assert "Allow Claude?" not in page.text


def test_a_connected_app_keeps_refreshing_after_the_client_key_changes(
    world, memstore, oauth
) -> None:
    app = _app(world, memstore, oauth)
    server = app.state.dashboard.mcp_oauth
    c = client(app)
    assert login(c).status_code == 303
    client_id = register(c, GROK).json()["client_id"]
    code, verifier = _approved(c, client_id)
    tokens = exchange(c, client_id, code, verifier, GROK).json()
    # SESSION_SECRET rotated: this id no longer decodes ...
    server._client_key = b"rotated" * 5
    assert server.client(client_id) is None
    # ... but the connection already made keeps refreshing.
    refreshed = _refresh(c, client_id, tokens["refresh_token"])
    assert refreshed.status_code == 200, refreshed.text
    # Another client's id is still refused, and the token is kept for its own client.
    other = register(c, GROK).json()["client_id"]
    assert _refresh(c, other, refreshed.json()["refresh_token"]).status_code != 200
    assert _refresh(c, client_id, refreshed.json()["refresh_token"]).status_code == 200

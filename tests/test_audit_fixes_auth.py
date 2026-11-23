"""Regression tests for the auth and rate-limit audit findings.

1. Bad bearers from a shared address must not lock out valid tokens from it.
2. The /mcp limit follows the connection, not the raw bearer; IPv6 counts per /64.
3. Abandoned registrations and approvals do not stay in the store for good.
4. The consent page names the app by where the approval goes; loopback is opt-in.
"""

import json
from datetime import UTC, datetime, timedelta

import pytest

from scoped_drive_mcp import mcp_oauth as mcp_oauth_module
from scoped_drive_mcp import ratelimit
from scoped_drive_mcp.config import Settings
from scoped_drive_mcp.mcp_oauth import CLIENTS_KEY, GRANTS_KEY, OAuthClientRecord, OAuthGrant
from scoped_drive_mcp.server import build_app
from tests.conftest import OWNER_EMAIL, TOKENS, make_settings
from tests.dash import MCP_HEADERS, client, login
from tests.test_mcp_oauth import GROK, INIT, _approved, _refresh, exchange, register

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
    # ... but a valid token from the same address still works.
    assert _mcp(c, TOKENS["viewer"], office).status_code == 200
    # Bad tokens from there are still refused, and so is a request with no token.
    assert _mcp(c, "made-up-4", office).status_code == 429
    missing = c.post("/mcp", json=INIT, headers={**MCP_HEADERS, "X-Forwarded-For": office})
    assert missing.status_code == 429
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


# ---- 3. abandoned registrations and approvals are removed ----


def _ago(seconds: int) -> str:
    return (datetime.now(UTC) - timedelta(seconds=seconds)).isoformat(timespec="seconds")


def _backdate_client(server, client_id: str, seconds: int) -> None:
    store = server.store
    record = json.loads(store.hget(CLIENTS_KEY, client_id))
    record["created_at"] = _ago(seconds)
    store.hset(CLIENTS_KEY, client_id, json.dumps(record))


def _backdate_grant(server, grant_id: str, seconds: int) -> None:
    store = server.store
    grant = OAuthGrant.from_json(store.hget(GRANTS_KEY, grant_id))
    grant.created_at = _ago(seconds)
    store.hset(GRANTS_KEY, grant_id, grant.to_json())


def test_clients_never_approved_are_removed_after_a_day(world, memstore, oauth) -> None:
    app = _app(world, memstore, oauth)
    server = app.state.dashboard.mcp_oauth
    c = client(app)
    assert login(c).status_code == 303
    stale = register(c, GROK).json()["client_id"]
    fresh = register(c, GROK).json()["client_id"]
    used = register(c, GROK).json()["client_id"]
    code, verifier = _approved(c, used)
    assert exchange(c, used, code, verifier, GROK).status_code == 200
    # The approval is noted on the client itself.
    assert server.client(used).granted is True
    day = mcp_oauth_module.UNUSED_CLIENT_TTL
    for client_id in (stale, fresh, used):
        _backdate_client(server, client_id, day + 60 if client_id != fresh else 60)

    assert register(c, GROK).status_code == 201
    assert server.client(stale) is None
    assert server.client(fresh) is not None
    assert server.client(used) is not None


def test_unapproved_clients_are_capped(world, memstore, oauth, monkeypatch) -> None:
    monkeypatch.setattr(mcp_oauth_module, "MAX_UNUSED_CLIENTS", 3)
    app = _app(world, memstore, oauth)
    server = app.state.dashboard.mcp_oauth
    c = client(app)
    assert login(c).status_code == 303
    used = register(c, GROK).json()["client_id"]
    code, verifier = _approved(c, used)
    assert exchange(c, used, code, verifier, GROK).status_code == 200
    ids = []
    for age in (50, 40, 30, 20, 10):
        ids.append(register(c, GROK).json()["client_id"])
        _backdate_client(server, ids[-1], age)
    newest = register(c, GROK).json()["client_id"]
    stored = server.store.hgetall(CLIENTS_KEY)
    unused = [cid for cid, raw in stored.items() if not OAuthClientRecord.from_json(raw).granted]
    assert len(unused) == 3
    # The oldest made room. A client in use is never one of them.
    assert set(unused) == {ids[3], ids[4], newest}
    assert server.client(used) is not None


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

    # Still inside the code's lifetime: kept.
    _backdate_grant(server, abandoned, 60)
    assert register(c, GROK).status_code == 201
    assert abandoned in server.store.hgetall(GRANTS_KEY)

    old = mcp_oauth_module.CODE_TTL + 120
    _backdate_grant(server, abandoned, old)
    _backdate_grant(server, finished, old)
    assert register(c, GROK).status_code == 201
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

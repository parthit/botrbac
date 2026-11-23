"""Regression tests for dashboard security fixes: a refused Drive connection only touches
the person who made it, signing in again ends the old session, and only Picker pages get
the relaxed Content-Security-Policy."""

from dataclasses import replace

from scoped_drive_mcp.dashboard import SESSION_COOKIE
from scoped_drive_mcp.server import build_app
from tests.conftest import EVE, OWNER_EMAIL, make_settings
from tests.dash import client, connect_drive, login, sign_in
from tests.test_multi_user import _app

FULL_DRIVE = "https://www.googleapis.com/auth/drive"


# ---- a refused full-Drive connection clears only that person's token ----


def test_full_drive_connect_by_another_person_keeps_the_admins_token(
    world, memstore, oauth, monkeypatch
) -> None:
    app = _app(world, memstore, oauth)
    directory = app.state.dashboard.directory
    admin, eve = client(app), client(app)
    assert login(admin).status_code == 303
    assert login(eve, "eve-code").status_code == 303
    assert directory.vault_for(OWNER_EMAIL).owner() is not None
    assert directory.vault_for(EVE).owner() is not None

    # Eve edits Google's consent URL so the grant comes back with full Drive.
    real = oauth.exchange_code

    def wider(code):
        tokens = real(code)
        if code != "eve-code" or not tokens.refresh_token:
            return tokens
        return replace(tokens, scopes=tokens.scopes | {FULL_DRIVE})

    monkeypatch.setattr(oauth, "exchange_code", wider)
    r = connect_drive(eve, "eve-code")
    assert r.status_code == 400 and "more access than Bot RBAC asks for" in r.text

    admin_record = directory.vault_for(OWNER_EMAIL).owner()
    assert admin_record is not None and admin_record["t"] == f"rt-{OWNER_EMAIL}"
    assert directory.vault_for(EVE).owner() is None
    assert directory.vault_for(EVE).legacy_owner() is None
    # The admin's Drive still works.
    assert admin.get("/files").status_code == 200


# ---- signing in again ends the previous server-side session ----


def test_signing_in_again_ends_the_old_session(p2_app) -> None:
    c = client(p2_app)
    assert login(c).status_code == 303
    old_cookie = c.cookies.get(SESSION_COOKIE)
    assert old_cookie

    assert sign_in(c).status_code == 303
    assert c.cookies.get(SESSION_COOKIE) != old_cookie
    assert c.get("/settings").status_code == 200

    copy = client(p2_app)
    copy.cookies.set(SESSION_COOKIE, old_cookie)
    r = copy.get("/settings")
    assert r.status_code == 303 and r.headers["location"].startswith("/login")


def test_signing_in_as_another_account_ends_the_old_session(world, memstore, oauth) -> None:
    app = _app(world, memstore, oauth)
    c = client(app)
    assert login(c).status_code == 303
    admin_cookie = c.cookies.get(SESSION_COOKIE)

    assert login(c, "eve-code").status_code == 303
    copy = client(app)
    copy.cookies.set(SESSION_COOKIE, admin_cookie)
    r = copy.get("/settings")
    assert r.status_code == 303 and r.headers["location"].startswith("/login")


# ---- Content-Security-Policy: strict by default, relaxed only for the Picker ----

PICKER_NEEDS = (
    "https://apis.google.com",
    "https://www.gstatic.com",
    "'unsafe-eval'",
    "https://docs.google.com",
    "https://content.googleapis.com",
)


def _policy(response) -> str:
    policies = response.headers.get_list("content-security-policy")
    assert len(policies) == 1, policies
    return policies[0]


def _assert_strict(policy: str) -> None:
    assert "'unsafe-eval'" not in policy
    assert "apis.google.com" not in policy
    assert "gstatic.com" not in policy
    assert "script-src 'self';" in policy
    assert "frame-ancestors 'none'" in policy
    # Sign-in forms redirect to Google.
    assert "form-action 'self' https://accounts.google.com" in policy


def _picker_app(world, memstore, oauth):
    return build_app(
        make_settings(
            root_folder_id=None,
            allowlist_cache_ttl=0,
            google_picker_api_key="AIzaSyTestKeyValue",
            google_cloud_project_number="123456789012",
        ),
        world.as_user(OWNER_EMAIL),
        store=memstore,
        owner_drive_factory=lambda token: world.as_user(OWNER_EMAIL),
        oauth=oauth,
    )


def test_ordinary_pages_get_the_strict_policy(world, memstore, oauth) -> None:
    app = _picker_app(world, memstore, oauth)
    c = client(app)
    for path in ("/", "/login", "/privacy"):
        _assert_strict(_policy(c.get(path)))
    assert login(c).status_code == 303
    for path in ("/", "/settings", "/requests", "/health"):
        _assert_strict(_policy(c.get(path)))


def test_picker_page_keeps_what_the_picker_needs(world, memstore, oauth) -> None:
    app = _picker_app(world, memstore, oauth)
    c = client(app)
    assert login(c).status_code == 303
    page = c.get("/files")
    assert page.status_code == 200 and 'id="pick-drive"' in page.text
    policy = _policy(page)
    for needed in PICKER_NEEDS:
        assert needed in policy, needed
    assert "frame-ancestors 'none'" in policy


def test_picker_page_is_strict_when_the_picker_is_not_set_up(p2_app) -> None:
    c = client(p2_app)
    assert login(c).status_code == 303
    page = c.get("/files")
    assert page.status_code == 200 and 'id="pick-drive"' not in page.text
    _assert_strict(_policy(page))


# ---- an address that cannot name a person's records is refused at sign-in ----


def test_sign_in_with_an_unusable_address_is_refused_cleanly(world, memstore, oauth) -> None:
    app = _app(world, memstore, oauth)
    oauth.accounts["colon-code"] = ("a:b@example.com", True)
    c = client(app)
    r = sign_in(c, "colon-code")
    assert r.status_code == 403
    assert "not allowed to use this dashboard" in r.text
    assert "at:colon-code" in oauth.revoked
    assert c.get("/settings").status_code == 303


# ---- the sign-in rate limit counts an IPv6 /64 as one caller ----


def test_login_limit_counts_an_ipv6_64_once(world, memstore, oauth, monkeypatch) -> None:
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "1")
    app = build_app(
        make_settings(
            root_folder_id=None,
            allowlist_cache_ttl=0,
            login_rate_limit=2,
            login_rate_window_seconds=600,
        ),
        world.as_user(OWNER_EMAIL),
        store=memstore,
        owner_drive_factory=lambda token: world.as_user(OWNER_EMAIL),
        oauth=oauth,
    )
    c = client(app)
    for n in (1, 2):
        r = c.get("/auth/login", headers={"X-Forwarded-For": f"2001:db8:1:2::{n}"})
        assert r.status_code == 303
    blocked = c.get("/auth/login", headers={"X-Forwarded-For": "2001:db8:1:2::ffff"})
    assert blocked.status_code == 429
    other = c.get("/auth/login", headers={"X-Forwarded-For": "2001:db8:1:3::1"})
    assert other.status_code == 303

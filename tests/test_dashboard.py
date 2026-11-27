"""Owner dashboard: sign-in, sessions, CSRF, security headers, separation from /mcp,
browse/grant/revoke, Activity and the Overview."""

import re
from dataclasses import replace
from html import unescape

import pytest

from scoped_drive_mcp import oauth as google_oauth
from scoped_drive_mcp import ratelimit
from scoped_drive_mcp.config import Settings
from scoped_drive_mcp.dashboard import SESSION_COOKIE, describe_mime
from scoped_drive_mcp.drive_client import FOLDER_MIME, DriveNotFoundError
from scoped_drive_mcp.grants import GrantError, GrantService
from scoped_drive_mcp.mcp_oauth import McpOAuth, done_redirect
from scoped_drive_mcp.ratelimit import client_ip
from scoped_drive_mcp.server import build_app
from scoped_drive_mcp.store import (
    BOT_TOKEN_KEY,
    KEY_PREFIX,
    OWNER_TOKEN_KEY,
    MemoryStore,
    TenantDirectory,
)
from tests.conftest import BASE_URL, EVE, OWNER_EMAIL, TOKENS, make_settings
from tests.dash import (
    MCP_HEADERS,
    client,
    connect_drive,
    csrf,
    login,
    mcp_call,
    post,
    sign_in,
    start_oauth,
)
from tests.fake_drive import FakeDrive
from tests.test_multi_user import _app, _grok, _mcp

FULL_DRIVE = "https://www.googleapis.com/auth/drive"
OWNER_PAGES = [
    "/files",
    "/files?folder=proj",
    "/files?tab=allowed",
    "/sharing",
    "/settings",
    "/requests",
    "/activity",
    "/requests/" + "A" * 32,
]
OWNER_POSTS = [
    "/grant",
    "/revoke",
    "/logout",
    "/requests/" + "A" * 32 + "/approve",
    "/requests/" + "A" * 32 + "/deny",
    "/oauth/grants/revoke",
]


@pytest.fixture
def c(p2_app):
    return client(p2_app)


@pytest.fixture
def owner_c(c):
    r = login(c)
    assert r.status_code == 303 and r.headers["location"] == "/"
    return c


def _app_with(world, memstore, oauth, **settings):
    """A single-owner app like p2_app, with extra settings."""
    return build_app(
        make_settings(root_folder_id=None, allowlist_cache_ttl=0, **settings),
        world.as_user(OWNER_EMAIL),
        store=memstore,
        owner_drive_factory=lambda token: world.as_user(OWNER_EMAIL),
        oauth=oauth,
    )


def _widen_connect(oauth, monkeypatch, only_code: str | None = None) -> None:
    """Google answers the connect step with full Drive (e.g. an older grant folded in, or
    a consent URL the person edited)."""
    real = oauth.exchange_code

    def wider(code):
        tokens = real(code)
        if not tokens.refresh_token or (only_code and code != only_code):
            return tokens
        return replace(tokens, scopes=tokens.scopes | {FULL_DRIVE})

    monkeypatch.setattr(oauth, "exchange_code", wider)


# ---- logged out ----------------------------------------------------------------


@pytest.mark.parametrize("page", OWNER_PAGES)
def test_logged_out_pages_redirect_to_login(c, page: str) -> None:
    r = c.get(page)
    assert r.status_code == 303
    assert r.headers["location"].startswith("/login?next=")


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("/browse", "/files"),
        ("/browse?folder=proj&q=x", "/files?folder=proj&q=x"),
        ("/access", "/files?tab=allowed"),
        ("/shared", "/sharing?tab=with-me"),
        ("/bridge", "/sharing?tab=people"),
    ],
)
def test_old_addresses_redirect_to_the_new_pages(c, old: str, new: str) -> None:
    r = c.get(old)
    assert r.status_code == 308 and r.headers["location"] == new


@pytest.mark.parametrize("path", OWNER_POSTS)
def test_logged_out_posts_are_refused(c, world, path: str) -> None:
    r = c.post(path, data={"file_id": "proj", "csrf": "x"})
    assert r.status_code == 403
    assert world.files["proj"].permissions == []


def test_login_page_is_public(c) -> None:
    r = c.get("/login")
    assert r.status_code == 200 and "Sign in with Google" in r.text
    assert r.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert "apis.google.com" not in r.headers["content-security-policy"]
    assert 'href="/terms"' in r.text and 'href="/privacy"' in r.text
    # Google requires the data disclosure immediately before the consent button.
    assert r.text.index("files, folders and pages you allow") < r.text.index("Sign in with Google")
    assert "Only the" not in r.text and "only the owner" not in r.text.lower()


@pytest.mark.parametrize(
    ("path", "needles"),
    [
        (
            "/",
            (
                "without handing over the whole Drive",
                "Google Drive",
                ">Privacy policy</a>",
                ">Terms of service</a>",
                'href="/privacy"',
                'href="/terms"',
                "Signing in shares only your email",
                '<meta name="description"',
            ),
        ),
        ("/terms", ("access-control gateway",)),
        ("/privacy", ("Google API Services User Data Policy", "14 days", "Postgres")),
    ],
)
def test_public_pages_set_no_cookie(c, path: str, needles: tuple[str, ...]) -> None:
    r = c.get(path)
    assert r.status_code == 200
    for needle in needles:
        assert needle in r.text, needle
    assert "set-cookie" not in {name.lower() for name in r.headers}
    assert r.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    # Anyone with a Google account can sign in; the pages must not say otherwise.
    assert "Only the" not in r.text and "only the owner" not in r.text.lower()


def test_dashboard_not_configured(world) -> None:
    app = build_app(
        make_settings(session_secret=None, owner_email=None),
        world.as_user(OWNER_EMAIL),
        store=MemoryStore(),
    )
    c = client(app)
    r = c.get("/")
    assert r.status_code == 503
    assert "SESSION_SECRET" in r.text and "OWNER_EMAIL" in r.text
    assert c.get("/terms").status_code == 200
    assert c.get("/privacy").status_code == 200
    health = c.get("/health").json()
    assert health == {"status": "ok"}
    assert "SESSION_SECRET" not in str(health)


# ---- the whole owner journey ----------------------------------------------------------


def test_owner_journey_sign_in_connect_allow_read_revoke(c, world) -> None:
    """What a new person does: sign in with Google, connect Drive, connect an assistant
    over MCP OAuth, allow a folder, let the assistant read inside it, then remove it."""
    r = sign_in(c)
    assert r.status_code == 303 and r.headers["location"].startswith("/connect")
    assert connect_drive(c).headers["location"] == "/"
    token = _grok(c, "Grok Bot")

    refused = _mcp(c, token, "read_file", file_id="proj-notes")
    assert refused["structuredContent"]["error"] == "access_required"

    r = post(c, "/grant", file_id="proj", next="/browse")
    assert r.status_code == 303 and r.headers["location"] == "/browse"
    assert world.files["proj"].permissions == []  # nothing is shared in Drive
    page = c.get("/files").text
    assert "Remove" in page and 'data-confirm="Remove “' in page
    page = c.get("/files?folder=proj").text
    assert "via folder" in page and "Everything in this folder is available" in page
    assert "Projects" in c.get("/files?tab=allowed").text

    read = _mcp(c, token, "read_file", file_id="proj-notes")
    assert read["isError"] is False
    assert read["structuredContent"]["content"] == "project notes alpha"
    # A file outside the allowed folder is still refused.
    assert _mcp(c, token, "read_file", file_id="priv-secret")["isError"] is True

    r = post(c, "/revoke", file_id="proj", next="/access")
    assert r.status_code == 303
    assert world.files["proj"].permissions == []
    after = _mcp(c, token, "read_file", file_id="proj-notes")
    assert after["isError"] is True
    assert after["structuredContent"]["error"] == "access_required"
    assert "project notes alpha" not in str(after)


# ---- owner sign-in ---------------------------------------------------------------


def test_owner_login(c, oauth, memstore, p2_app) -> None:
    r = login(c)
    assert r.status_code == 303
    cookie = r.headers["set-cookie"].lower()
    assert SESSION_COOKIE in cookie
    assert "httponly" in cookie and "secure" in cookie and "samesite=lax" in cookie
    # Step 1 had no hint; step 2 is pinned to the signed-in address.
    assert oauth.hints[-2:] == [None, OWNER_EMAIL]
    assert c.get("/").status_code == 200
    # the refresh token is stored encrypted
    raw = memstore.get(KEY_PREFIX + OWNER_TOKEN_KEY)
    assert raw and "rt-owner" not in raw
    vault = p2_app.state.dashboard.vault
    assert vault.owner()["t"] == f"rt-{OWNER_EMAIL}"
    # and used for the owner's Drive
    assert c.get("/files").status_code == 200
    assert p2_app.state.owner_tokens[-1] == f"rt-{OWNER_EMAIL}"


def test_login_redirects_back_to_next(c) -> None:
    r = c.get("/requests")
    assert r.headers["location"] == "/login?next=%2Frequests"
    state = start_oauth(c, "/auth/login?next=/requests")
    r = c.get("/auth/callback", params={"code": "owner-code", "state": state})
    # First sign-in goes to the separate connect step, which keeps the destination.
    assert r.headers["location"] == "/connect?next=%2Frequests"
    r = connect_drive(c, next_url="/requests")
    assert r.headers["location"] == "/requests"
    # A returning person who is already connected goes straight back.
    post(c, "/logout")
    state = start_oauth(c, "/auth/login?next=/requests")
    r = c.get("/auth/callback", params={"code": "owner-code", "state": state})
    assert r.headers["location"] == "/requests"


def test_login_next_cannot_redirect_offsite(c) -> None:
    state = start_oauth(c, "/auth/login?next=//evil.example.com/x")
    r = c.get("/auth/callback", params={"code": "owner-code", "state": state})
    # Not connected yet, so step 2 comes next; the offsite next became "/".
    assert r.headers["location"] == "/connect?next=%2F"
    assert "evil" not in r.headers["location"]


def test_unverified_account_cannot_sign_in(c, oauth, memstore) -> None:
    r = login(c, "unverified-owner-code")
    assert r.status_code == 403
    assert "not allowed" in r.text
    assert c.get("/files").status_code == 303  # still logged out
    assert memstore.get(KEY_PREFIX + OWNER_TOKEN_KEY) is None
    assert oauth.revoked  # the unwanted token was revoked


def test_sign_in_with_an_unusable_address_is_refused_cleanly(world, memstore, oauth) -> None:
    """An address that cannot name a person's records (a colon splits store keys)."""
    app = _app(world, memstore, oauth)
    oauth.accounts["colon-code"] = ("a:b@example.com", True)
    c = client(app)
    r = sign_in(c, "colon-code")
    assert r.status_code == 403
    assert "not allowed to use this dashboard" in r.text
    assert "at:colon-code" in oauth.revoked
    assert c.get("/settings").status_code == 303


def test_second_verified_account_can_sign_in(c, memstore, p2_app) -> None:
    r = login(c, "eve-code")
    assert r.status_code == 303
    assert c.get("/files").status_code == 200
    # The admin's legacy key stays empty; eve's token is under her prefix.
    assert memstore.get(KEY_PREFIX + OWNER_TOKEN_KEY) is None
    raw = memstore.get(KEY_PREFIX + f"u:{EVE}:" + OWNER_TOKEN_KEY)
    assert raw and "rt-eve" not in raw
    assert p2_app.state.dashboard.directory.has_owner_refresh(EVE)
    assert c.get("/admin").status_code == 404
    assert 'href="/admin"' not in c.get("/").text


def test_allowed_emails_rejects_other_accounts(world, memstore, oauth) -> None:
    c = client(_app_with(world, memstore, oauth, allowed_emails=OWNER_EMAIL))
    refused = login(c, "eve-code")
    assert refused.status_code == 403
    assert "not allowed" in refused.text
    assert oauth.revoked
    assert c.get("/files").status_code == 303
    assert login(c).status_code == 303
    assert c.get("/files").status_code == 200


def test_state_is_checked(c) -> None:
    assert c.get("/auth/callback", params={"error": "access_denied"}).status_code == 400
    state = start_oauth(c)
    r = c.get("/auth/callback", params={"code": "owner-code", "state": state + "x"})
    assert r.status_code == 400
    # a valid state from another browser (no matching nonce in this session) is refused
    other = client(c.app)
    other_state = start_oauth(other)
    r = c.get("/auth/callback", params={"code": "owner-code", "state": other_state})
    assert r.status_code == 400
    # a state is single-use
    r = other.get("/auth/callback", params={"code": "owner-code", "state": other_state})
    assert r.status_code == 303
    r = other.get("/auth/callback", params={"code": "owner-code", "state": other_state})
    assert r.status_code == 400


def test_drive_scope_required(c, oauth) -> None:
    oauth.scopes = frozenset({"openid", "email"})
    r = login(c)
    assert r.status_code == 400 and "Drive access was not granted" in r.text


def test_full_drive_scope_is_refused_and_revoked(c, oauth, p2_app, monkeypatch) -> None:
    _widen_connect(oauth, monkeypatch)
    r = login(c)
    assert r.status_code == 400 and "more access than Bot RBAC asks for" in r.text
    assert oauth.revoked
    assert p2_app.state.dashboard.vault.owner() is None
    assert p2_app.state.dashboard.vault.legacy_owner() is None


def test_full_drive_connect_by_another_person_keeps_the_admins_token(
    world, memstore, oauth, monkeypatch
) -> None:
    """A refused connection clears only the token of the person who made it."""
    app = _app(world, memstore, oauth)
    directory = app.state.dashboard.directory
    admin, eve = client(app), client(app)
    assert login(admin).status_code == 303
    assert login(eve, "eve-code").status_code == 303
    assert directory.vault_for(OWNER_EMAIL).owner() is not None
    assert directory.vault_for(EVE).owner() is not None

    _widen_connect(oauth, monkeypatch, only_code="eve-code")
    r = connect_drive(eve, "eve-code")
    assert r.status_code == 400 and "more access than Bot RBAC asks for" in r.text

    admin_record = directory.vault_for(OWNER_EMAIL).owner()
    assert admin_record is not None and admin_record["t"] == f"rt-{OWNER_EMAIL}"
    assert directory.vault_for(EVE).owner() is None
    assert directory.vault_for(EVE).legacy_owner() is None
    assert admin.get("/files").status_code == 200


def test_login_hint_is_only_the_visitors(c, oauth) -> None:
    start_oauth(c, "/auth/login")
    assert oauth.hints[-1] is None
    start_oauth(c, "/auth/login?login_hint=visitor@example.com")
    assert oauth.hints[-1] == "visitor@example.com"
    start_oauth(c, "/auth/login?login_hint=not-an-email")
    assert oauth.hints[-1] is None
    start_oauth(c, f"/auth/login?login_hint={OWNER_EMAIL}")
    assert oauth.hints[-1] == OWNER_EMAIL


class _GoogleAnswer:
    def __init__(self, status: int, body: dict) -> None:
        self.status_code = status
        self._body = body

    def json(self) -> dict:
        return self._body


@pytest.mark.parametrize(
    ("status", "scope", "issued"),
    [
        (200, "https://www.googleapis.com/auth/drive.file", True),
        # Google ignored the request to narrow, or did not say what it gave.
        (200, FULL_DRIVE, False),
        (200, f"https://www.googleapis.com/auth/drive.file {FULL_DRIVE}", False),
        (200, "", False),
        # Google refused to narrow this sign-in.
        (400, "", False),
    ],
)
def test_the_picker_token_is_limited_to_picked_files(monkeypatch, status, scope, issued) -> None:
    sent: dict = {}

    def fake_post(url, data, timeout):
        sent.update(data)
        return _GoogleAnswer(status, {"access_token": "ya29-token", "scope": scope})

    monkeypatch.setattr(google_oauth.httpx, "post", fake_post)
    if issued:
        assert google_oauth.refresh_access_token("id", "secret", "rt") == "ya29-token"
    else:
        with pytest.raises(google_oauth.OAuthError):
            google_oauth.refresh_access_token("id", "secret", "rt")
    assert sent["scope"] == "https://www.googleapis.com/auth/drive.file"


def test_sign_in_is_the_only_drive_token(world, memstore, oauth) -> None:
    """With no GOOGLE_OAUTH_REFRESH_TOKEN, the assistant uses the owner's own sign-in."""
    built: list[str] = []

    def bot_factory(token: str):
        built.append(token)
        return world.as_user(OWNER_EMAIL)

    app = build_app(
        make_settings(root_folder_id=None, google_oauth_refresh_token=None, allowlist_cache_ttl=0),
        store=memstore,
        owner_drive_factory=lambda t: world.as_user(OWNER_EMAIL),
        oauth=oauth,
        bot_drive_factory=bot_factory,
    )
    c = client(app)
    result = mcp_call(c, "read_file", file_id="loose-doc")
    text = result["content"][0]["text"]
    assert result["isError"] and "Google Drive is not connected" in text
    assert f"{BASE_URL}/connect" in text and "sign in with Google" not in text
    assert "Connect bot" not in text

    login(c)
    assert c.get("/health").json() == {"status": "ok"}
    post(c, "/grant", file_id="loose-doc")
    assert world.files["loose-doc"].permissions == []
    result = mcp_call(c, "read_file", file_id="loose-doc")
    assert result["isError"] is False
    assert result["structuredContent"]["content"] == "memo beta"
    assert built == [f"rt-{OWNER_EMAIL}"]
    assert memstore.get(KEY_PREFIX + BOT_TOKEN_KEY) is None


# ---- sessions --------------------------------------------------------------------------

# HTML form POST is a non-cors navigation. These policies leave Origin as the
# document origin; `no-referrer` replaces it with the literal "null", which
# check_csrf rejects even when the session token is present.
_FORM_POST_KEEPS_ORIGIN = frozenset(
    {
        "same-origin",
        "origin",
        "origin-when-cross-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "no-referrer-when-downgrade",
    }
)
_LOGOUT_FORM = re.compile(
    r'<form class="inline" method="post" action="/logout">\s*'
    r'<input type="hidden" name="csrf" value="([^"]+)">'
)


def _browser_form_origin(policy: str) -> str:
    """Origin header a browser attaches to a same-origin HTML form POST under `policy`."""
    if policy in _FORM_POST_KEEPS_ORIGIN:
        return BASE_URL
    return "null"


def test_logout_form_post_as_the_browser(owner_c) -> None:
    """Sign out via the dashboard form, with the Origin a browser would send."""
    page = owner_c.get("/")
    assert page.status_code == 200
    match = _LOGOUT_FORM.search(page.text)
    assert match, "signed-in page has no logout form"
    origin = _browser_form_origin(page.headers["referrer-policy"])

    logged_out = owner_c.post("/logout", data={"csrf": match.group(1)}, headers={"Origin": origin})
    assert logged_out.status_code == 303, logged_out.text
    assert logged_out.headers["location"] == "/login?signed_out=1"
    landing = owner_c.get(logged_out.headers["location"])
    assert landing.status_code == 200 and "You’ve signed out." in landing.text
    home = owner_c.get("/")
    assert home.status_code == 200 and "Privacy policy" in home.text
    assert "Sign out" not in home.text
    assert owner_c.get("/files").headers["location"].startswith("/login")

    login(owner_c)
    denied = owner_c.post("/logout", headers={"Origin": origin})
    assert denied.status_code == 403
    assert "reload the page and try again" in denied.text
    assert "Back to home" in denied.text
    assert owner_c.get("/").status_code == 200


def test_a_copied_session_cookie_stops_working_when_its_session_ends(
    world, memstore, oauth
) -> None:
    """A stolen cookie is only good while its server-side session lives: signing in again
    (as the same or another account) and signing out each end the old one."""
    app = _app(world, memstore, oauth)
    c = client(app)

    def replayed(cookie: str):
        copy = client(app)
        copy.cookies.set(SESSION_COOKIE, cookie)
        return copy.get("/settings")

    assert login(c).status_code == 303
    first = c.cookies.get(SESSION_COOKIE)
    assert first and replayed(first).status_code == 200

    assert sign_in(c).status_code == 303
    second = c.cookies.get(SESSION_COOKIE)
    assert second != first
    assert c.get("/settings").status_code == 200
    r = replayed(first)
    assert r.status_code == 303 and r.headers["location"].startswith("/login")

    assert login(c, "eve-code").status_code == 303
    r = replayed(second)
    assert r.status_code == 303 and r.headers["location"].startswith("/login")

    third = c.cookies.get(SESSION_COOKIE)
    assert c.post("/logout", data={"csrf": csrf(c)}).status_code == 303
    assert replayed(third).status_code == 303


def test_a_session_ends_when_its_time_is_up_however_fresh_the_cookie() -> None:
    now = [1000.0]
    directory = TenantDirectory(MemoryStore(clock=lambda: now[0]), OWNER_EMAIL, None)
    sid = directory.open_session(EVE, 100)
    assert directory.session_alive(sid, EVE)
    assert not directory.session_alive(sid, OWNER_EMAIL)
    assert not directory.session_alive("made-up", EVE)
    now[0] += 101
    assert not directory.session_alive(sid, EVE)


def test_session_for_other_owner_is_ignored(p2_app, world, memstore, oauth) -> None:
    c = client(p2_app)
    login(c)
    cookie = c.cookies.get(SESSION_COOKIE)
    other = client(_app_with(world, memstore, oauth, owner_email="someone-else@example.com"))
    other.cookies.set(SESSION_COOKIE, cookie)
    assert other.get("/files").status_code == 303


# ---- CSRF -------------------------------------------------------------------------------


def test_csrf_required_on_every_post(owner_c, world) -> None:
    for path in (
        "/grant",
        "/revoke",
        "/logout",
        "/oauth/authorize",
        "/oauth/grants/revoke",
    ):
        assert owner_c.post(path, data={"file_id": "proj"}).status_code == 403
        assert owner_c.post(path, data={"file_id": "proj", "csrf": "wrong"}).status_code == 403
    assert world.files["proj"].permissions == []
    assert owner_c.get("/").status_code == 200  # logout without csrf did nothing


def test_cross_origin_post_refused(owner_c, world) -> None:
    token = csrf(owner_c)
    r = owner_c.post(
        "/grant",
        data={"csrf": token, "file_id": "proj"},
        headers={"Origin": "https://evil.example.com"},
    )
    assert r.status_code == 403
    assert world.files["proj"].permissions == []
    r = owner_c.post(
        "/grant", data={"csrf": token, "file_id": "proj"}, headers={"Origin": BASE_URL}
    )
    assert r.status_code == 303
    assert world.files["proj"].permissions == []


def test_csrf_token_rotates_on_login(c) -> None:
    login(c)
    first = csrf(c)
    post(c, "/logout")
    login(c)
    assert csrf(c) != first


# ---- separation of dashboard and /mcp --------------------------------------------------


@pytest.mark.parametrize("role", ["viewer", "admin"])
def test_bearer_tokens_do_not_open_the_dashboard(c, world, role: str) -> None:
    headers = {"Authorization": f"Bearer {TOKENS[role]}"}
    for page in OWNER_PAGES:
        r = c.get(page, headers=headers)
        assert r.status_code == 303 and r.headers["location"].startswith("/login")
    r = c.post("/grant", data={"file_id": "proj"}, headers=headers)
    assert r.status_code == 403
    assert world.files["proj"].permissions == []


def test_dashboard_cookie_does_not_open_mcp(owner_c) -> None:
    assert owner_c.cookies.get(SESSION_COOKIE)
    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "0"},
        },
    }
    r = owner_c.post("/mcp", json=init, headers=MCP_HEADERS)
    assert r.status_code == 401
    r = owner_c.get("/mcp")
    assert r.status_code == 401


# ---- security headers: strict by default, relaxed only for the Picker -------------------

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
    return _app_with(
        world,
        memstore,
        oauth,
        google_picker_api_key="AIzaSyTestKeyValue",
        google_cloud_project_number="123456789012",
    )


def test_routes_outside_the_dashboard_get_the_security_headers(p2_app) -> None:
    for path in ("/health", "/oauth/done"):
        headers = client(p2_app).get(path).headers
        assert headers["x-frame-options"] == "DENY", path
        assert "frame-ancestors 'none'" in headers["content-security-policy"], path
        assert len(headers.get_list("content-security-policy")) == 1, path
    page = client(p2_app).get("/")
    assert len(page.headers.get_list("x-frame-options")) == 1


def test_ordinary_pages_get_the_strict_policy(world, memstore, oauth) -> None:
    c = client(_picker_app(world, memstore, oauth))
    for path in ("/", "/login", "/privacy"):
        _assert_strict(_policy(c.get(path)))
    assert login(c).status_code == 303
    for path in ("/", "/settings", "/requests", "/health"):
        _assert_strict(_policy(c.get(path)))


def test_picker_page_keeps_what_the_picker_needs(world, memstore, oauth) -> None:
    c = client(_picker_app(world, memstore, oauth))
    assert login(c).status_code == 303
    page = c.get("/files")
    assert page.status_code == 200 and 'id="pick-drive"' in page.text
    policy = _policy(page)
    for needed in PICKER_NEEDS:
        assert needed in policy, needed
    assert "frame-ancestors 'none'" in policy


def test_picker_page_is_strict_when_the_picker_is_not_set_up(owner_c) -> None:
    page = owner_c.get("/files")
    assert page.status_code == 200 and 'id="pick-drive"' not in page.text
    _assert_strict(_policy(page))


def test_referrer_policy_sends_only_the_origin_to_other_sites(owner_c) -> None:
    """Google checks a website-restricted Picker key against the Referer, so other sites
    must get this site's origin. They must never get a path (request ids live in URLs)."""
    policy = owner_c.get("/files").headers["referrer-policy"]
    assert policy == "strict-origin-when-cross-origin"
    assert policy in _FORM_POST_KEEPS_ORIGIN


def test_own_code_page_exists_only_with_the_test_setting_and_never_shows_the_code(
    p2_app,
) -> None:
    """An attacker's app must not get a code shown to the person who clicked Allow."""
    assert Settings.model_fields["oauth_test_callback"].default is False
    done = done_redirect(BASE_URL)
    assert not McpOAuth(MemoryStore(), BASE_URL, OWNER_EMAIL).redirect_allowed(done)
    paths = {r.path for r in McpOAuth(MemoryStore(), BASE_URL, OWNER_EMAIL).routes()}
    assert "/oauth/done" not in paths
    assert McpOAuth(MemoryStore(), BASE_URL, OWNER_EMAIL, test_callback=True).redirect_allowed(done)
    # With the setting on (as in these tests), the page still never shows the code.
    page = client(p2_app).get("/oauth/done?code=SECRETCODE123").text
    assert "SECRETCODE123" not in page


# ---- rate limits: who the caller is ----------------------------------------------------


def test_a_typed_in_forwarded_address_is_ignored(monkeypatch) -> None:
    headers = [(b"x-forwarded-for", b"6.6.6.6, 9.9.9.9")]
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.delenv("TRUSTED_PROXY_HOPS", raising=False)
    assert client_ip(headers, "10.0.0.1") == "10.0.0.1"
    # One trusted proxy: its entry is the last one. Anything before it is the caller's.
    monkeypatch.setenv("VERCEL", "1")
    assert client_ip(headers, "10.0.0.1") == "9.9.9.9"
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "2")
    assert client_ip(headers, "10.0.0.1") == "6.6.6.6"
    assert client_ip([(b"x-forwarded-for", b"9.9.9.9")], "10.0.0.1") == "10.0.0.1"


def test_an_ignored_forwarded_address_is_said_once(monkeypatch, caplog) -> None:
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.delenv("TRUSTED_PROXY_HOPS", raising=False)
    monkeypatch.setattr(ratelimit, "_warned", set())
    with caplog.at_level("WARNING", logger="scoped_drive_mcp.ratelimit"):
        for _ in range(3):
            client_ip([(b"x-forwarded-for", b"6.6.6.6")], "10.0.0.1")
        monkeypatch.setenv("TRUSTED_PROXY_HOPS", "two")
        assert client_ip([(b"x-forwarded-for", b"6.6.6.6")], "10.0.0.1") == "10.0.0.1"
    messages = [r.getMessage() for r in caplog.records]
    assert sum("TRUSTED_PROXY_HOPS to the number" in m for m in messages) == 1
    assert sum("not a number" in m for m in messages) == 1


def test_login_limit_counts_an_ipv6_64_once(world, memstore, oauth, monkeypatch) -> None:
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "1")
    app = _app_with(world, memstore, oauth, login_rate_limit=2, login_rate_window_seconds=600)
    c = client(app)
    for n in (1, 2):
        r = c.get("/auth/login", headers={"X-Forwarded-For": f"2001:db8:1:2::{n}"})
        assert r.status_code == 303
    blocked = c.get("/auth/login", headers={"X-Forwarded-For": "2001:db8:1:2::ffff"})
    assert blocked.status_code == 429
    other = c.get("/auth/login", headers={"X-Forwarded-For": "2001:db8:1:3::1"})
    assert other.status_code == 303


# ---- browse, grant, revoke ---------------------------------------------------------


def test_browse_my_drive(owner_c) -> None:
    r = owner_c.get("/files")
    assert r.status_code == 200
    for name in ("Projects", "Private", "Loose memo"):
        assert name in r.text
    assert "secret from eve" not in r.text  # not in the owner's Drive
    r = owner_c.get("/files?folder=proj-sub")
    assert "Deep roadmap" in r.text
    assert 'href="/files?folder=proj"' in r.text  # breadcrumb
    r = owner_c.get("/files?q=memo")
    assert "Loose memo" in r.text and "Second memo" in r.text and "Projects" not in r.text
    assert owner_c.get("/files?folder=bad id").status_code == 400
    assert owner_c.get("/files?folder=proj-notes").status_code == 400


def test_browse_when_my_drive_root_is_hidden(owner_c, monkeypatch) -> None:
    """drive.file often 404s files.get('root'). Browse still has to render."""
    real = FakeDrive.get_file

    def get_file(self, file_id, fields):
        if file_id == "root":
            raise DriveNotFoundError(file_id)
        return real(self, file_id, fields)

    monkeypatch.setattr(FakeDrive, "get_file", get_file)
    page = owner_c.get("/files")
    assert page.status_code == 200
    assert "Something went wrong" not in page.text
    assert "My Drive" in page.text


def test_browse_does_not_invent_a_my_drive_parent(owner_c, world) -> None:
    """A folder whose parent this app cannot see is not shown under My Drive."""
    world.add("specs", "Specs", FOLDER_MIME, ["shared-drive-root"], owner=OWNER_EMAIL)
    page = owner_c.get("/files?folder=specs")
    assert page.status_code == 200
    assert "Specs" in page.text
    assert 'href="/files?folder=root"' not in page.text


def test_browse_stays_up_when_drive_list_fails(owner_c, monkeypatch) -> None:
    def boom(self, q, fields, page_size, page_token=None):
        raise RuntimeError("drive list refused")

    monkeypatch.setattr(FakeDrive, "list_files", boom)
    page = owner_c.get("/files")
    assert page.status_code == 200
    assert "Google Drive did not return files" in page.text
    assert "Something went wrong" not in page.text
    assert "Reload the page to try again" in page.text
    assert "picker is not set up" not in page.text and "Google Picker" not in page.text


def test_files_tab_says_where_files_come_from(owner_c) -> None:
    """The first Files tab lists what was chosen from Google Drive, not the whole Drive,
    and choosing a file is not the same as allowing it."""
    page = unescape(owner_c.get("/files").text)
    tabs = page[page.index('<nav class="tabs" aria-label="Files">') :].split("</nav>", 1)[0]
    assert ">From Google Drive</a>" in tabs and "All files" not in tabs
    assert "is allowed for your assistants straight away" in page


def test_grant_errors_are_shown(owner_c) -> None:
    post(owner_c, "/grant", file_id="does-not-exist", next="/browse")
    assert "not found" in owner_c.get("/files").text
    r = post(owner_c, "/grant", file_id="bad id")
    assert r.status_code == 400


def test_grant_shortcut_from_browse(owner_c, world) -> None:
    post(owner_c, "/grant", file_id="proj-shortcut")
    assert world.files["priv-secret"].permissions == []
    assert world.files["proj-shortcut"].permissions == []


def test_requests_nav_counts_pending(owner_c) -> None:
    mcp_call(owner_c, "read_file", file_id="priv-secret")
    page = owner_c.get("/files").text
    start = page.index("Requests")
    assert "1 waiting" in page[start : start + 220]


def test_describe_mime_gives_short_human_labels() -> None:
    word = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    assert describe_mime(word) == "Word"
    assert describe_mime("text/csv") == "CSV"
    assert describe_mime("application/vnd.some-vendor.thing-nobody-knows") == "File"
    assert describe_mime("application/x-whatever") == "File"
    assert describe_mime("video/mp4") == "Video"


# ---- rows update in place (ui.js) ----------------------------------------------------


def _post_json(c, path: str, **data):
    token = csrf(c)
    return c.post(path, data={"csrf": token, **data}, headers={"Accept": "application/json"})


def test_row_actions_answer_json_so_only_the_row_updates(owner_c) -> None:
    """ui.js posts Allow/Remove in the background; it must get JSON, not a page redirect."""
    r = _post_json(owner_c, "/grant", file_id="proj", next="/browse")
    assert r.status_code == 200
    assert r.json() == {
        "ok": True,
        "kind": "ok",
        "message": "Allowed “Projects” for the assistant.",
        "changed": True,
        # The Allowed tab's number, so the page can update it without a reload.
        "allow_count": 1,
    }
    # No flash left behind for the next full page load.
    assert "for the assistant." not in owner_c.get("/files?tab=allowed").text.split("<h1>")[0]
    assert "Projects" in owner_c.get("/files?tab=allowed").text

    r = _post_json(owner_c, "/revoke", file_id="proj", next="/browse")
    assert r.status_code == 200 and r.json()["ok"] is True
    assert r.json()["allow_count"] == 0
    assert "Projects" not in owner_c.get("/files?tab=allowed").text

    r = _post_json(owner_c, "/grant", file_id="does-not-exist", next="/browse")
    assert r.status_code == 400
    body = r.json()
    assert body["ok"] is False and "not found" in body["message"]
    assert "allow_count" not in body
    # A failure that changed nothing must not tell ui.js to update the row.
    assert body["changed"] is False


def test_revoke_json_reports_change_when_drive_cleanup_fails(owner_c, monkeypatch) -> None:
    """The allowlist entry is gone even though Drive errored, so the row must still update."""
    post(owner_c, "/grant", file_id="proj")
    real_revoke = GrantService.revoke

    def half_revoke(self, file_id):
        real_revoke(self, file_id)
        raise GrantError("Removed from the allowlist, but Google did not remove the bot's sharing.")

    monkeypatch.setattr(GrantService, "revoke", half_revoke)
    r = _post_json(owner_c, "/revoke", file_id="proj", next="/browse")
    assert r.status_code == 400
    body = r.json()
    assert body["ok"] is False and body["changed"] is True


def test_pages_carry_the_markup_for_in_place_updates(owner_c) -> None:
    page = owner_c.get("/files").text
    assert 'data-async data-flip="access" data-access-when="off"' in page
    assert 'data-async data-flip="access" data-access-when="on"' in page
    assert "data-row data-access=" in page

    post(owner_c, "/grant", file_id="proj")
    page = owner_c.get("/files?tab=allowed").text
    assert 'data-async data-on-success="remove-row"' in page
    # The empty-state block is on the page (hidden) so ui.js can show it after the last row.
    assert "Nothing is allowed" in page

    # confirm.js asks before data-confirm forms and leaves async forms to ui.js.
    r = owner_c.get("/confirm.js")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/javascript")
    assert "data-confirm" in r.text and "data-async" in r.text


def test_shortcut_rows_update_in_place_and_remove_acts_on_the_target(owner_c) -> None:
    """A shortcut row renders its target's state, so ui.js can flip it like any row.
    Remove posts the target's id, since that is what Allow stored."""
    page = owner_c.get("/files?folder=proj").text
    assert "Allow the target" in page
    allow_target = r"<form[^>]*>\s*(?:<input[^>]*>\s*)*<button[^>]*>Allow the target"
    forms = re.findall(allow_target, page)
    assert forms
    for form in forms:
        assert "data-async" in form and 'value="proj-shortcut"' in form
    remove = re.findall(
        r'<form[^>]*action="/revoke"[^>]*>\s*(?:<input[^>]*>\s*)*<button[^>]*>Remove the target',
        page,
    )
    assert remove and all('value="priv-secret"' in form for form in remove)


# ---- Activity ---------------------------------------------------------------------------


def test_activity_page(owner_c) -> None:
    post(owner_c, "/grant", file_id="loose-doc")
    mcp_call(owner_c, "read_file", file_id="loose-doc")
    mcp_call(owner_c, "read_file", file_id="priv-secret")
    page = owner_c.get("/activity").text
    assert "You allowed “Loose memo” for your assistant." in page
    assert "Your assistant (viewer token) read “Loose memo”." in page
    # A denied read names the file from the access request it filed.
    assert (
        "Your assistant (viewer token) tried to read “payroll.txt”. "
        "Blocked: it isn’t on your list." in page
    )
    assert "TOP SECRET" not in page
    # Raw tool names, reasons and UTC milliseconds are not shown as text.
    assert ">read_file<" not in page and "out_of_scope<" not in page
    assert re.search(r'<time datetime="[0-9T:-]+Z" data-time', page)
    assert ".000+00:00" not in page.replace('title="', "")


def test_activity_badges_filters_and_polling(owner_c) -> None:
    payload = mcp_call(owner_c, "read_file", file_id="priv-other")["structuredContent"]
    rid = payload["request_id"]
    for _ in range(3):
        mcp_call(owner_c, "check_access_request", request_id=rid)
    post(owner_c, f"/requests/{rid}/deny")
    page = owner_c.get("/activity").text
    assert "You denied a request for “other.txt”." in page
    row = page[page.index("You denied a request") :].split("</li>", 1)[0]
    assert "Denied" in row and "Allowed" not in row and "pill bad" in row
    # The assistant asking "answered yet?" is hidden, with a way to show it.
    assert "checked on an access request" not in page
    assert "3 routine checks by your assistants are hidden" in page
    shown = owner_c.get("/activity?checks=1").text
    assert shown.count("checked on an access request") == 3
    attention = owner_c.get("/activity?view=attention").text
    assert "tried to read “other.txt”" in attention
    assert "You denied a request" not in attention
    mine = owner_c.get("/activity?view=you").text
    assert "You denied a request" in mine and "tried to read" not in mine
    assert 'aria-current="page"' in mine


def test_activity_shows_more_on_request(owner_c, p2_app) -> None:
    log = p2_app.state.dashboard.activity
    for _ in range(120):
        log({"ts": "2026-11-19T23:58:10.123+00:00", "event": "owner", "action": "login"})
    page = owner_c.get("/activity").text
    assert page.count('class="activity-row"') == 50
    more = re.search(r'href="([^"]+)" id="show-more"', page)
    assert more
    bigger = owner_c.get(unescape(more.group(1))).text
    assert bigger.count('class="activity-row"') == 100
    assert "Nov 19, 2026, 23:58 UTC" in bigger


def test_activity_is_capped(p2_app) -> None:
    log = p2_app.state.dashboard.activity
    for i in range(520):
        log({"ts": str(i), "event": "x"})
    recent = log.recent()
    assert len(recent) == 500 and recent[0]["ts"] == "519"


# ---- Overview ---------------------------------------------------------------------------


def test_overview_and_health_report_status(owner_c) -> None:
    page = owner_c.get("/").text
    assert f"{BASE_URL}/mcp" in page
    assert "never sign in to Google as you" in page
    assert "files and folders you allow" in page
    assert "Assistant acts as" not in page
    # Operator notes moved from Overview to Settings, admin only.
    assert "make_token.py" not in page
    settings_page = owner_c.get("/settings").text
    assert "UPSTASH_REDIS_REST_URL" in settings_page
    assert "make_token.py" in settings_page


def test_non_admin_overview_hides_operator_notes(c) -> None:
    login(c, "eve-code")
    page = c.get("/").text
    assert "never sign in to Google as you" in page
    assert "files and folders you allow" in page
    # One MCP address for every client.
    assert page.count(f'data-copy="{BASE_URL}/mcp"') == 1
    for name in ("Claude", "ChatGPT", "Dots", "Grok", "Muse", "Cursor"):
        assert f"<b>{name}</b>" in page
    for operator_note in ("make_token.py", "UPSTASH_REDIS_REST_URL", "Vercel", "BOT_EMAIL"):
        assert operator_note not in page
    settings_page = c.get("/settings").text
    assert "make_token.py" not in settings_page and 'id="server"' not in settings_page


def test_mailbox_empty_state_is_plain_language(owner_c) -> None:
    page = owner_c.get("/sharing?tab=people").text
    assert "request_link" not in page
    assert "Ask your assistant to start a pairing" in page


def test_login_page_forgets_an_account_whose_session_has_ended(owner_c, p2_app) -> None:
    """The cookie still names the account after the server session is gone. The sign-in
    page must not show that address to whoever is at the browser now."""
    from tests.conftest import OWNER_EMAIL

    assert OWNER_EMAIL in owner_c.get("/").text
    directory = p2_app.state.dashboard.directory
    directory.session_alive = lambda sid, owner: False
    page = owner_c.get("/login")
    assert page.status_code == 200 and OWNER_EMAIL not in page.text

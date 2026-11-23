"""Sign-in (step 1, identity only) is separate from connecting Google Drive (step 2)."""

import pytest

from scoped_drive_mcp.drive_client import DRIVE_SCOPE
from scoped_drive_mcp.store import KEY_PREFIX, OWNER_TOKEN_KEY
from tests.conftest import OWNER_EMAIL
from tests.dash import client, connect_drive, csrf, sign_in, start_oauth
from tests.test_mcp_oauth import DONE, auth_params, register

DRIVE_PAGES = ["/files", "/files?folder=proj"]


@pytest.fixture
def c(p2_app):
    return client(p2_app)


@pytest.fixture
def signed_in(c):
    r = sign_in(c)
    assert r.status_code == 303
    return c


def test_sign_in_asks_only_for_identity_and_stores_no_token(c, oauth, memstore, p2_app) -> None:
    r = sign_in(c)
    assert r.status_code == 303
    assert r.headers["location"] == "/connect?next=%2F"
    assert oauth.requested == [(("openid", "email"), False)]
    assert memstore.get(KEY_PREFIX + OWNER_TOKEN_KEY) is None
    assert p2_app.state.dashboard.directory.is_known_user(OWNER_EMAIL)
    assert not p2_app.state.dashboard.directory.has_owner_refresh(OWNER_EMAIL)


def test_signed_in_without_drive_sees_the_connect_step(signed_in) -> None:
    page = signed_in.get("/connect")
    assert page.status_code == 200
    assert "One more step" in page.text and "Step 1 of 2" not in page.text
    assert "Allow Bot RBAC to access Google Drive" in page.text
    # The disclosure comes right before the button.
    assert page.text.index("see, edit, create, and delete") < page.text.index(
        "Allow Bot RBAC to access Google Drive"
    )
    overview = signed_in.get("/")
    assert overview.status_code == 200
    # The admin's deployment bot token is set in these settings, but Browse and Allow
    # need this person's own Drive, so the banner still shows until step 2 is done.
    assert 'id="connect-drive"' in overview.text
    assert connect_drive(signed_in).status_code == 303
    assert 'id="connect-drive"' not in signed_in.get("/").text


@pytest.mark.parametrize("page", DRIVE_PAGES)
def test_drive_pages_send_you_to_connect_not_to_login(signed_in, page: str) -> None:
    r = signed_in.get(page)
    assert r.status_code == 303
    assert r.headers["location"].startswith("/connect?next=")
    # still signed in
    assert signed_in.get("/connect").status_code == 200


def test_connect_asks_for_drive_offline_for_the_signed_in_account(
    signed_in, oauth, memstore, p2_app
) -> None:
    r = connect_drive(signed_in)
    assert r.status_code == 303 and r.headers["location"] == "/"
    scopes, offline = oauth.requested[-1]
    assert DRIVE_SCOPE in scopes and offline is True
    assert oauth.hints[-1] == OWNER_EMAIL
    raw = memstore.get(KEY_PREFIX + OWNER_TOKEN_KEY)
    assert raw and "rt-owner" not in raw
    assert p2_app.state.dashboard.vault.owner()["t"] == f"rt-{OWNER_EMAIL}"
    assert signed_in.get("/files").status_code == 200
    page = signed_in.get("/settings").text
    assert "Allow Bot RBAC to access Google Drive" not in page
    assert "Disconnect" in page


def test_connect_with_a_different_google_account_is_refused(signed_in, oauth, memstore) -> None:
    r = connect_drive(signed_in, code="eve-code")
    assert r.status_code == 403
    assert "different account" in r.text
    assert memstore.get(KEY_PREFIX + OWNER_TOKEN_KEY) is None
    assert oauth.revoked
    assert signed_in.get("/files").headers["location"].startswith("/connect")


def test_connect_without_drive_scope_is_refused(signed_in, oauth, memstore) -> None:
    oauth.scopes = frozenset({"openid", "email"})
    r = connect_drive(signed_in)
    assert r.status_code == 400 and "Google Drive access was not granted" in r.text
    assert memstore.get(KEY_PREFIX + OWNER_TOKEN_KEY) is None


def test_connect_needs_csrf_and_a_session(c, signed_in) -> None:
    assert signed_in.post("/connect/google_drive", data={"csrf": "nope"}).status_code == 403
    logged_out = client(c.app)
    assert logged_out.post("/connect/google_drive", data={"csrf": "x"}).status_code == 403
    assert logged_out.get("/connect").headers["location"].startswith("/login?next=")


def test_unknown_connection_is_404(signed_in) -> None:
    token = csrf(signed_in, "/settings")
    assert signed_in.post("/connect/dropbox", data={"csrf": token}).status_code == 404


def test_connect_state_cannot_be_replayed_as_sign_in(c) -> None:
    """A connect callback without a signed-in session stores nothing."""
    from itsdangerous import URLSafeTimedSerializer

    from scoped_drive_mcp.dashboard import STATE_SALT
    from tests.conftest import SESSION_SECRET

    serializer = URLSafeTimedSerializer(SESSION_SECRET, STATE_SALT)
    nonce = serializer.loads(start_oauth(c))["nonce"]
    forged = serializer.dumps({"flow": "connect", "connection": "google_drive", "nonce": nonce})
    r = c.get("/auth/callback", params={"code": "owner-code", "state": forged})
    assert r.status_code == 400
    assert c.get("/files").headers["location"].startswith("/login")


def test_disconnect_drops_the_token_and_keeps_the_session(signed_in, oauth, p2_app) -> None:
    connect_drive(signed_in)
    token = csrf(signed_in, "/settings")
    r = signed_in.post("/connect/google_drive/disconnect", data={"csrf": token})
    assert r.status_code == 303 and r.headers["location"] == "/connect"
    assert p2_app.state.dashboard.vault.owner() is None
    assert f"rt-{OWNER_EMAIL}" in oauth.revoked
    assert signed_in.get("/connect").status_code == 200
    assert signed_in.get("/files").headers["location"].startswith("/connect")


FULL = "openid email https://www.googleapis.com/auth/drive"


def _plant_old_full_drive_token(p2_app) -> str:
    vault = p2_app.state.dashboard.vault
    vault.set_owner("rt-old-full", OWNER_EMAIL, FULL)
    p2_app.state.dashboard.forget_drive(OWNER_EMAIL)
    return "rt-old-full"


def test_old_full_drive_token_is_revoked_before_reconnecting(signed_in, oauth, p2_app) -> None:
    old = _plant_old_full_drive_token(p2_app)
    vault = p2_app.state.dashboard.vault
    page = signed_in.get("/settings").text
    assert "Reconnect Google Drive" in page
    assert 'action="/connect/google_drive"' in page
    oauth.revoked.clear()
    r = connect_drive(signed_in)
    assert r.status_code == 303
    # Revoked first (before Google's screen), so the new grant is not revoked with it.
    assert oauth.revoked == [old]
    assert vault.legacy_owner() is None
    assert vault.owner()["scopes"].split() == sorted(["openid", "email", DRIVE_SCOPE])
    assert "https://www.googleapis.com/auth/drive" not in vault.owner()["scopes"].split()
    page = signed_in.get("/settings").text
    assert "Reconnect Google Drive" not in page


def test_declined_reconnect_leaves_no_old_token(signed_in, oauth, p2_app) -> None:
    old = _plant_old_full_drive_token(p2_app)
    vault = p2_app.state.dashboard.vault
    oauth.revoked.clear()
    oauth.scopes = frozenset({"openid", "email"})
    r = connect_drive(signed_in)
    assert r.status_code == 400
    assert old in oauth.revoked
    assert vault.owner() is None and vault.legacy_owner() is None


def test_disconnect_revokes_an_old_full_drive_token(signed_in, oauth, p2_app) -> None:
    old = _plant_old_full_drive_token(p2_app)
    token = csrf(signed_in, "/settings")
    oauth.revoked.clear()
    r = signed_in.post("/connect/google_drive/disconnect", data={"csrf": token})
    assert r.status_code == 303
    assert oauth.revoked == [old]
    assert p2_app.state.dashboard.vault.legacy_owner() is None


def test_wrong_account_connect_keeps_that_accounts_own_grant(c, oauth, p2_app) -> None:
    eve = client(c.app)
    sign_in(eve, "eve-code")
    connect_drive(eve, "eve-code")
    assert p2_app.state.dashboard.directory.has_owner_refresh("eve@example.com")
    sign_in(c)
    oauth.revoked.clear()
    r = connect_drive(c, code="eve-code")
    assert r.status_code == 403
    assert oauth.revoked == []
    assert p2_app.state.dashboard.directory.has_owner_refresh("eve@example.com")


def test_assistant_consent_waits_for_a_drive_connection(signed_in) -> None:
    created = register(signed_in, DONE)
    _verifier, params = auth_params(created.json()["client_id"], DONE)
    r = signed_in.get("/oauth/authorize", params=params)
    assert r.status_code == 303
    assert r.headers["location"].startswith("/connect?next=%2Foauth%2Fauthorize")
    connect_drive(signed_in)
    page = signed_in.get("/oauth/authorize", params=params)
    assert page.status_code == 200 and "Allow" in page.text


def test_old_connection_shows_reconnect_with_explanation(signed_in, oauth, p2_app) -> None:
    connect_drive(signed_in)
    _plant_old_full_drive_token(p2_app)
    page = signed_in.get("/settings").text
    card = page[page.index('id="connection-google_drive"') :].split("</article>", 1)[0]
    assert "Not connected" in card and 'id="old-connection"' in card
    assert ">Reconnect Google Drive</button>" in card
    assert "only the specific Google Drive files you use with this app" in card

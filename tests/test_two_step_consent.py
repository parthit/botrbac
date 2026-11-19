"""Sign-in (step 1, identity only) is separate from connecting Google Drive (step 2)."""

import pytest

from scoped_drive_mcp.drive_client import DRIVE_SCOPE
from scoped_drive_mcp.store import KEY_PREFIX, OWNER_TOKEN_KEY
from tests.conftest import OWNER_EMAIL
from tests.dash import client, connect_drive, csrf, sign_in, start_oauth
from tests.test_mcp_oauth import DONE, auth_params, register

DRIVE_PAGES = ["/browse", "/browse?folder=proj"]


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
    assert "Step 2 of 2" in page.text
    assert "Allow Bot RBAC to access Google Drive" in page.text
    # The disclosure comes right before the button.
    assert page.text.index("see, edit, create, and delete") < page.text.index(
        "Allow Bot RBAC to access Google Drive"
    )
    overview = signed_in.get("/")
    assert overview.status_code == 200
    assert 'id="connect-drive"' in overview.text


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
    assert signed_in.get("/browse").status_code == 200
    page = signed_in.get("/connect").text
    assert "Allow Bot RBAC to access Google Drive" not in page
    assert "Disconnect" in page


def test_connect_with_a_different_google_account_is_refused(signed_in, oauth, memstore) -> None:
    r = connect_drive(signed_in, code="eve-code")
    assert r.status_code == 403
    assert "different account" in r.text
    assert memstore.get(KEY_PREFIX + OWNER_TOKEN_KEY) is None
    assert oauth.revoked
    assert signed_in.get("/browse").headers["location"].startswith("/connect")


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
    token = csrf(signed_in, "/connect")
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
    assert c.get("/browse").headers["location"].startswith("/login")


def test_disconnect_drops_the_token_and_keeps_the_session(signed_in, oauth, p2_app) -> None:
    connect_drive(signed_in)
    token = csrf(signed_in, "/connect")
    r = signed_in.post("/connect/google_drive/disconnect", data={"csrf": token})
    assert r.status_code == 303 and r.headers["location"] == "/connect"
    assert p2_app.state.dashboard.vault.owner() is None
    assert f"rt-{OWNER_EMAIL}" in oauth.revoked
    assert signed_in.get("/connect").status_code == 200
    assert signed_in.get("/browse").headers["location"].startswith("/connect")


def test_narrow_token_can_be_upgraded_from_connect(signed_in, oauth, p2_app) -> None:
    connect_drive(signed_in)
    vault = p2_app.state.dashboard.vault
    record = vault.owner()
    narrow = "openid email https://www.googleapis.com/auth/drive.file"
    vault.set_owner(record["t"], record["email"], narrow)
    page = signed_in.get("/connect").text
    assert "Reconnect Google Drive" in page
    assert 'action="/connect/google_drive"' in page
    assert "Disconnect" in page
    # The existing token stays until the upgrade succeeds.
    r = connect_drive(signed_in)
    assert r.status_code == 303
    assert DRIVE_SCOPE in vault.owner()["scopes"].split()
    page = signed_in.get("/connect").text
    assert "Reconnect Google Drive" not in page
    assert 'action="/connect/google_drive"' not in page


def test_declined_upgrade_does_not_revoke_the_stored_grant(signed_in, oauth, p2_app) -> None:
    connect_drive(signed_in)
    vault = p2_app.state.dashboard.vault
    record = vault.owner()
    narrow = "openid email https://www.googleapis.com/auth/drive.file"
    vault.set_owner(record["t"], record["email"], narrow)
    oauth.revoked.clear()
    oauth.scopes = frozenset({"openid", "email", "https://www.googleapis.com/auth/drive.file"})
    r = connect_drive(signed_in)
    assert r.status_code == 400
    assert oauth.revoked == []
    assert vault.owner()["t"] == record["t"]
    assert vault.owner()["scopes"] == narrow


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

"""Google's file picker as a full page (POST /picker/redirect, back through /auth/callback).

The in-page picker cannot load where the browser blocks Google's cookies inside a frame:
every iPhone and iPad browser, and Safari by default. The full page needs none.
"""

from urllib.parse import parse_qs, urlparse

import pytest

from scoped_drive_mcp.oauth import GoogleOAuthClient
from tests.conftest import OWNER_EMAIL
from tests.dash import client, csrf, login, mcp_call, start_oauth

DRIVE_FILE = "https://www.googleapis.com/auth/drive.file"


@pytest.fixture
def c(p2_app):
    return client(p2_app)


@pytest.fixture
def owner_c(c):
    assert login(c).status_code == 303
    return c


def start_pick(c, **form) -> str:
    return start_oauth(c, "/picker/redirect", csrf=csrf(c, "/settings"), **form)


def allowed(c) -> str:
    return c.get("/files?tab=allowed").text


def test_picker_url_is_googles_redirect_picker() -> None:
    oauth = GoogleOAuthClient("id", "secret", "https://app.example/auth/callback")
    query = parse_qs(urlparse(oauth.picker_url("state-token", "me@example.com")).query)
    # Google allows only drive.file here, on its own.
    assert query["scope"] == [DRIVE_FILE]
    assert query["trigger_onepick"] == ["true"]
    assert query["prompt"] == ["consent"]
    assert query["allow_multiple"] == ["true"]
    assert query["allow_folder_selection"] == ["true"]
    assert query["redirect_uri"] == ["https://app.example/auth/callback"]
    assert query["login_hint"] == ["me@example.com"]
    # No new refresh token: the server keeps the one from Connect.
    assert query["access_type"] == ["online"]
    assert query["include_granted_scopes"] == ["false"]


def test_picked_items_are_allowed_and_no_token_is_revoked(owner_c, oauth) -> None:
    state = start_pick(owner_c, next="/files?tab=allowed")
    assert oauth.hints[-1] == OWNER_EMAIL
    assert oauth.requested[-1] == ((DRIVE_FILE,), False)
    back = owner_c.get(
        "/auth/callback",
        params={"code": "owner-code", "state": state, "picked_file_ids": "proj,proj-notes"},
    )
    assert back.status_code == 303
    assert back.headers["location"] == "/files?tab=allowed"
    page = allowed(owner_c)
    assert "Allowed 2 items for the assistant." in page
    assert mcp_call(owner_c, "get_metadata", file_id="proj-notes").get("isError") is not True
    assert oauth.revoked == []


def test_one_picked_item_is_named(owner_c) -> None:
    state = start_pick(owner_c)
    back = owner_c.get(
        "/auth/callback", params={"code": "owner-code", "state": state, "picked_file_ids": "proj"}
    )
    assert back.headers["location"] == "/files"
    assert "Allowed “" in owner_c.get("/files").text


def test_a_pick_with_another_google_account_adds_nothing(owner_c, oauth) -> None:
    state = start_pick(owner_c)
    back = owner_c.get(
        "/auth/callback", params={"code": "eve-code", "state": state, "picked_file_ids": "proj"}
    )
    assert back.status_code == 303
    page = owner_c.get("/files").text
    assert "different Google account" in page
    assert mcp_call(owner_c, "get_metadata", file_id="proj").get("isError") is True
    # Revoking would end that other account's whole grant, so it is left alone.
    assert oauth.revoked == []


def test_an_item_the_connection_cannot_open_is_refused(owner_c, oauth) -> None:
    # Google did not say whose token it was: the grant check itself still decides.
    oauth.drive_account_unknown = True
    state = start_pick(owner_c)
    owner_c.get(
        "/auth/callback",
        params={"code": "eve-code", "state": state, "picked_file_ids": "no-such-item"},
    )
    assert "not found in your Drive" in owner_c.get("/files").text


def test_coming_back_with_nothing_picked_changes_nothing(owner_c) -> None:
    state = start_pick(owner_c)
    back = owner_c.get("/auth/callback", params={"code": "owner-code", "state": state})
    assert back.status_code == 303
    assert "Nothing came back from Google’s file picker" in owner_c.get("/files").text


def test_cancelling_the_picker_returns_to_the_page(owner_c) -> None:
    state = start_pick(owner_c, next="/files?tab=allowed")
    back = owner_c.get("/auth/callback", params={"error": "access_denied", "state": state})
    assert back.status_code == 303
    assert back.headers["location"] == "/files?tab=allowed"
    assert "nothing changed" in allowed(owner_c)


def test_ids_that_are_not_drive_items_are_refused(owner_c) -> None:
    state = start_pick(owner_c)
    owner_c.get(
        "/auth/callback",
        params={"code": "owner-code", "state": state, "picked_file_ids": "proj,../x"},
    )
    assert "not a Drive item" in owner_c.get("/files").text
    assert mcp_call(owner_c, "get_metadata", file_id="proj").get("isError") is True


def test_a_callback_cannot_be_replayed_or_forged(owner_c) -> None:
    state = start_pick(owner_c)
    params = {"code": "owner-code", "state": state, "picked_file_ids": "proj"}
    assert owner_c.get("/auth/callback", params=params).status_code == 303
    again = owner_c.get("/auth/callback", params=params)
    assert again.status_code == 400
    forged = owner_c.get("/auth/callback", params={**params, "state": "forged"})
    assert forged.status_code == 400


def test_the_picker_needs_a_csrf_token(owner_c) -> None:
    assert owner_c.post("/picker/redirect", data={"next": "/files"}).status_code == 403


def test_next_cannot_leave_the_site(owner_c) -> None:
    state = start_pick(owner_c, next="https://evil.example/")
    back = owner_c.get(
        "/auth/callback", params={"code": "owner-code", "state": state, "picked_file_ids": "proj"}
    )
    assert back.headers["location"].startswith("/")
    assert "evil.example" not in back.headers["location"]


def test_picking_for_a_request_approves_it(owner_c) -> None:
    denied = mcp_call(owner_c, "get_metadata", file_id="proj-notes")
    request_id = denied["structuredContent"]["request_id"]
    state = start_pick(owner_c, next=f"/requests/{request_id}", request=request_id)
    back = owner_c.get(
        "/auth/callback",
        params={"code": "owner-code", "state": state, "picked_file_ids": "proj-notes"},
    )
    assert back.headers["location"] == f"/requests/{request_id}"
    assert "Approved" in owner_c.get(f"/requests/{request_id}").text
    assert mcp_call(owner_c, "get_metadata", file_id="proj-notes").get("isError") is not True


def test_signed_out_callback_adds_nothing(p2_app) -> None:
    c = client(p2_app)
    login(c)
    state = start_pick(c)
    c.post("/logout", data={"csrf": csrf(c, "/settings")})
    # The session is gone; the callback must not act for anyone.
    back = c.get(
        "/auth/callback", params={"code": "owner-code", "state": state, "picked_file_ids": "proj"}
    )
    assert back.status_code == 400

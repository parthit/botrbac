"""Login hint, OAuth scopes, public assets, picker session, pagination, and rate limits."""

import json
import re
from html import unescape
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from scoped_drive_mcp.connections import GOOGLE_DRIVE
from scoped_drive_mcp.dashboard import browse_href, normalize_page_token
from scoped_drive_mcp.oauth import GoogleOAuthClient
from tests.conftest import OWNER_EMAIL, make_settings
from tests.dash import client, csrf, login, mcp_call

PICKER_KEYS = {
    "google_picker_api_key": "AIzaSyTestKeyValue",
    "google_cloud_project_number": "123456789012",
}


def _settings(**overrides):
    return make_settings(root_folder_id=None, allowlist_cache_ttl=0, **overrides)


with_picker = pytest.mark.parametrize("p2_settings", [_settings(**PICKER_KEYS)], ids=["picker"])
UI_JS = Path(__file__).resolve().parents[1] / "src/scoped_drive_mcp/templates/ui.js"


@pytest.fixture
def c(p2_app):
    return client(p2_app)


@pytest.fixture
def owner_c(c):
    assert login(c).status_code == 303
    return c


def test_sign_in_url_asks_only_for_identity() -> None:
    oauth = GoogleOAuthClient("id", "secret", "https://app.example/auth/callback")
    query = parse_qs(urlparse(oauth.authorization_url("state-token")).query)
    assert query["scope"][0].split() == ["openid", "email"]
    assert query["access_type"] == ["online"]
    assert query["include_granted_scopes"] == ["false"]
    assert "login_hint" not in query


def test_connect_url_asks_only_for_picked_files() -> None:
    oauth = GoogleOAuthClient("id", "secret", "https://app.example/auth/callback")
    url = oauth.authorization_url(
        "state-token",
        "owner@example.com",
        scopes=GOOGLE_DRIVE.scopes,
        offline=True,
    )
    query = parse_qs(urlparse(url).query)
    assert query["scope"][0].split() == ["https://www.googleapis.com/auth/drive.file"]
    assert query["access_type"] == ["offline"]
    assert query["prompt"] == ["consent"]
    # Never fold in an older full-Drive grant.
    assert query["include_granted_scopes"] == ["false"]
    assert query["login_hint"] == ["owner@example.com"]
    hinted = parse_qs(urlparse(oauth.authorization_url("state-token", "visitor@example.com")).query)
    assert hinted["login_hint"] == ["visitor@example.com"]


def test_favicon_and_robots_do_not_redirect(c) -> None:
    icon = c.get("/favicon.ico")
    assert icon.status_code == 200
    assert icon.headers["content-type"].startswith("image/svg+xml")
    assert "scoped-mark" in icon.text
    assert "location" not in {name.lower() for name in icon.headers}
    robots = c.get("/robots.txt")
    assert robots.status_code == 200
    assert robots.headers["content-type"].startswith("text/plain")
    assert "User-agent: *" in robots.text
    assert "Disallow: /" in robots.text
    css = c.get("/app.css")
    assert css.status_code == 200 and ".skip" in css.text


def test_privacy_describes_per_file_access(c) -> None:
    page = c.get("/privacy")
    assert page.status_code == 200
    assert "https://www.googleapis.com/auth/drive.file</code>" in page.text
    assert "https://www.googleapis.com/auth/drive</code>" not in page.text


def test_opaque_drive_page_token_round_trips() -> None:
    token = "Cjx~!*|token"
    assert normalize_page_token(token) == token
    assert normalize_page_token("has space") is None
    assert normalize_page_token("line\nbreak") is None
    assert normalize_page_token("x" * 1025) is None
    href = browse_href("proj", q=None, request_id=None, page=token, prev=["prev~!*"])
    query = parse_qs(urlparse(href).query)
    assert query["page"] == [token]
    assert query["prev"] == ["prev~!*"]
    assert query["folder"] == ["proj"]


def test_browse_sends_opaque_page_token(owner_c, monkeypatch) -> None:
    from tests.fake_drive import FakeDrive

    seen: list[str | None] = []
    original = FakeDrive.list_files

    def wrapped(self, q, fields, page_size, page_token=None, order_by=None):
        seen.append(page_token)
        return original(self, q, fields, page_size, None)

    monkeypatch.setattr(FakeDrive, "list_files", wrapped)
    monkeypatch.setattr("scoped_drive_mcp.dashboard.BROWSE_PAGE_SIZE", 1)
    token = "Cjx~!*|token"
    page = owner_c.get("/files", params={"folder": "root", "page": token})
    assert page.status_code == 200
    assert token in seen
    nxt = re.search(r'href="([^"]+)">Next</a>', page.text)
    assert nxt, page.text
    query = parse_qs(urlparse(unescape(nxt.group(1))).query)
    assert query["prev"] == [token]


@with_picker
def test_picker_button_keeps_folder_and_request(owner_c) -> None:
    signed_in = owner_c
    denied = mcp_call(signed_in, "read_file", file_id="priv-secret")
    request_id = denied["structuredContent"]["request_id"]
    page = signed_in.get("/files", params={"folder": "proj", "request": request_id})
    assert page.status_code == 200
    button = re.search(r"<button[^>]*id=\"pick-drive\"[^>]*>", page.text)
    assert button, page.text
    tag = button.group(0)
    assert f'data-request="{request_id}"' in tag
    nxt = unescape(re.search(r'data-next="([^"]*)"', tag).group(1))
    query = parse_qs(urlparse(nxt).query)
    assert query["folder"] == ["proj"]
    assert query["request"] == [request_id]
    script = UI_JS.read_text()
    assert 'getAttribute("data-next")' in script
    assert 'getAttribute("data-request")' in script
    assert script.index('postForm("/grant"') < script.index('"/approve"')
    assert "response.status >= 400" in script


@with_picker
def test_request_page_picker_approves_an_unopened_file(owner_c) -> None:
    signed_in = owner_c
    # A file this app cannot see may still exist (drive.file), so the request is filed
    # and the picker can add it.
    denied = mcp_call(signed_in, "get_metadata", file_id="stray-shared")
    request_id = denied["structuredContent"]["request_id"]
    page = signed_in.get(f"/requests/{request_id}")
    assert page.status_code == 200
    assert "Choose the file to approve" in page.text
    assert "Google only lets Bot RBAC open files you pick" in page.text
    assert 'id="file-missing"' not in page.text
    button = re.search(r"<button[^>]*id=\"pick-drive\"[^>]*>", page.text)
    assert button, page.text
    assert f'data-request="{request_id}"' in button.group(0)
    assert f'data-next="/requests/{request_id}"' in button.group(0)


def test_browse_previous_and_next(owner_c, monkeypatch) -> None:
    monkeypatch.setattr("scoped_drive_mcp.dashboard.BROWSE_PAGE_SIZE", 1)
    first = owner_c.get("/files")
    assert first.status_code == 200
    assert 'aria-disabled="true">Previous' in first.text
    match = re.search(r'href="([^"]+)">Next</a>', first.text)
    assert match, first.text
    second = owner_c.get(unescape(match.group(1)))
    assert second.status_code == 200
    back = re.search(r'href="([^"]+)">Previous</a>', second.text)
    assert back, second.text
    returned = owner_c.get(unescape(back.group(1)))
    assert returned.status_code == 200
    assert 'aria-disabled="true">Previous' in returned.text


def test_old_full_drive_token_is_never_used(owner_c, p2_app) -> None:
    vault = p2_app.state.dashboard.vault
    record = vault.owner()
    assert 'id="reconsent"' not in owner_c.get("/").text
    for old in ("openid email https://www.googleapis.com/auth/drive", None):
        vault.set_owner(record["t"], record["email"], old)
        p2_app.state.dashboard.forget_drive(OWNER_EMAIL)
        assert vault.owner() is None and vault.legacy_owner()["t"] == record["t"]
        page = owner_c.get("/").text
        assert 'id="reconsent"' in page
        assert 'href="/settings#connection-google_drive"' in page
        # Not connected: Drive pages send the person to reconnect, and tools get nothing.
        assert owner_c.get("/files").headers["location"].startswith("/connect")
        listed = mcp_call(owner_c, "list_folder", folder_id="proj")
        assert listed["isError"] is True
        assert "project notes alpha" not in json.dumps(listed)
    # Both scopes together are just as unusable as full Drive alone.
    vault.set_owner(
        record["t"],
        record["email"],
        "https://www.googleapis.com/auth/drive.file https://www.googleapis.com/auth/drive",
    )
    assert vault.owner() is None


def test_picker_session_hidden_until_configured(owner_c) -> None:
    denied = owner_c.get("/picker/session")
    assert denied.status_code == 404
    assert "access_token" not in denied.text


@with_picker
def test_picker_session_returns_access_token_not_refresh(owner_c, monkeypatch) -> None:
    monkeypatch.setattr(
        "scoped_drive_mcp.dashboard.refresh_access_token",
        lambda *_args, **_kwargs: "ya29-test-token",
    )
    body = owner_c.get("/picker/session")
    assert body.status_code == 200, body.text
    payload = body.json()
    assert payload["access_token"] == "ya29-test-token"
    assert payload["api_key"] == "AIzaSyTestKeyValue"
    assert payload["app_id"] == "123456789012"
    assert "rt-" not in body.text


@pytest.mark.parametrize(
    "p2_settings", [_settings(login_rate_limit=2, login_rate_window_seconds=600)]
)
def test_login_is_rate_limited(c) -> None:
    assert c.get("/auth/login").status_code == 303
    assert c.get("/auth/login").status_code == 303
    blocked = c.get("/auth/login")
    assert blocked.status_code == 429
    assert "Too many sign-in attempts" in blocked.text
    assert blocked.headers["retry-after"] == "600"


@with_picker
def test_allowed_item_google_has_not_opened_offers_pick_again(owner_c, world) -> None:
    c = owner_c
    token = csrf(c, "/files")
    for item in ("proj", "loose-doc"):
        c.post("/grant", data={"csrf": token, "file_id": item, "next": "/files"})
    page = c.get("/files?tab=allowed").text
    assert 'id="needs-pick"' not in page
    # Google no longer opens one of them to this app (e.g. allowed under an older
    # full-Drive connection): it is kept, flagged, and can be picked again by name.
    hidden = world.files.pop("loose-doc")
    page = c.get("/files?tab=allowed").text
    assert 'id="needs-pick"' in page and "1 of these item" in page
    button = re.search(r"<button[^>]*data-pick[^>]*>", page)
    assert button and f'data-query="{hidden.name}"' in button.group(0)
    assert page.count("data-needs-pick") == 1


@pytest.mark.parametrize(
    "p2_settings", [_settings(**PICKER_KEYS), _settings()], ids=["picker", "no-picker"]
)
def test_safari_picker_note_only_with_the_picker(owner_c, p2_settings) -> None:
    # Safari blocks Google's cookies in the picker frame; the note says which setting to
    # change. It belongs next to a picker button, so it is only there when one is.
    picker = p2_settings.google_picker_api_key is not None
    denied = mcp_call(owner_c, "get_metadata", file_id="stray-shared")
    request_id = denied["structuredContent"]["request_id"]
    for path in ("/files", f"/requests/{request_id}"):
        page = owner_c.get(path)
        assert page.status_code == 200
        assert ("data-safari-note" in page.text) is picker, path
        if picker:
            note = re.search(r"<p[^>]*data-safari-note[^>]*>", page.text).group(0)
            assert "hidden" in note  # ui.js reveals it in Safari only


def test_safari_note_check_counts_every_ios_browser() -> None:
    script = UI_JS.read_text()
    # Edge on iOS (EdgiOS) runs on WebKit and hits the same cookie block as Safari.
    assert "Edg(?!iOS)" in script

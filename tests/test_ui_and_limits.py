"""Login hint, OAuth scopes, public assets, picker session, pagination, and rate limits."""

import re
from html import unescape
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from scoped_drive_mcp.dashboard import browse_href, normalize_page_token
from scoped_drive_mcp.oauth import GoogleOAuthClient
from scoped_drive_mcp.server import build_app
from tests.conftest import OWNER_EMAIL, make_settings
from tests.dash import MCP_HEADERS, client, login, mcp_call


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


def test_connect_url_adds_full_drive_scope_incrementally() -> None:
    oauth = GoogleOAuthClient("id", "secret", "https://app.example/auth/callback")
    url = oauth.authorization_url(
        "state-token",
        "owner@example.com",
        scopes=("openid", "email", "https://www.googleapis.com/auth/drive"),
        offline=True,
    )
    query = parse_qs(urlparse(url).query)
    assert query["scope"][0].split() == [
        "openid",
        "email",
        "https://www.googleapis.com/auth/drive",
    ]
    assert query["access_type"] == ["offline"]
    assert query["prompt"] == ["consent"]
    assert query["include_granted_scopes"] == ["true"]
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


def test_privacy_describes_full_drive(c) -> None:
    page = c.get("/privacy")
    assert page.status_code == 200
    assert "https://www.googleapis.com/auth/drive</code>" in page.text
    assert "drive.file" not in page.text


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

    def wrapped(self, q, fields, page_size, page_token=None):
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


def test_picker_button_keeps_folder_and_request(world, memstore, oauth) -> None:
    app = build_app(
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
    signed_in = client(app)
    assert login(signed_in).status_code == 303
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
    script_path = Path(__file__).resolve().parents[1] / "src/scoped_drive_mcp/templates/ui.js"
    script = script_path.read_text()
    assert 'getAttribute("data-next")' in script
    assert 'getAttribute("data-request")' in script
    assert script.index('postForm("/grant"') < script.index('"/approve"')
    assert "response.status >= 400" in script


def test_request_page_picker_approves_an_unopened_file(world, memstore, oauth) -> None:
    app = build_app(
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
    signed_in = client(app)
    assert login(signed_in).status_code == 303
    # An older sign-in that only covers files this app opened (drive.file): a file it
    # cannot see may still exist, so the request is filed and the picker can add it.
    vault = app.state.dashboard.vault
    record = vault.owner()
    vault.set_owner(
        record["t"], OWNER_EMAIL, "openid email https://www.googleapis.com/auth/drive.file"
    )
    denied = mcp_call(signed_in, "get_metadata", file_id="stray-shared")
    request_id = denied["structuredContent"]["request_id"]
    page = signed_in.get(f"/requests/{request_id}")
    assert page.status_code == 200
    assert "Choose the file to approve" in page.text
    assert "only covers some of your files" in page.text
    assert "doesn\u2019t exist" not in page.text
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


def test_narrow_token_shows_reconsent(owner_c, p2_app) -> None:
    vault = p2_app.state.dashboard.vault
    record = vault.owner()
    vault.set_owner(
        record["t"],
        record["email"],
        "openid email https://www.googleapis.com/auth/drive.file",
    )
    page = owner_c.get("/").text
    assert 'id="reconsent"' in page
    assert "Reconnect Google Drive" in page and 'href="/settings#connection-google_drive"' in page
    vault.set_owner(record["t"], record["email"])
    assert 'id="reconsent"' in owner_c.get("/").text
    vault.set_owner(
        record["t"],
        record["email"],
        "openid email https://www.googleapis.com/auth/drive",
    )
    assert 'id="reconsent"' not in owner_c.get("/").text


def test_picker_session_hidden_until_configured(owner_c) -> None:
    denied = owner_c.get("/picker/session")
    assert denied.status_code == 404
    assert "access_token" not in denied.text


def test_picker_session_returns_access_token_not_refresh(
    world, memstore, oauth, monkeypatch
) -> None:
    monkeypatch.setattr(
        "scoped_drive_mcp.dashboard.refresh_access_token",
        lambda *_args, **_kwargs: "ya29-test-token",
    )
    app = build_app(
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
    signed_in = client(app)
    assert login(signed_in).status_code == 303
    body = signed_in.get("/picker/session")
    assert body.status_code == 200, body.text
    payload = body.json()
    assert payload["access_token"] == "ya29-test-token"
    assert payload["api_key"] == "AIzaSyTestKeyValue"
    assert payload["app_id"] == "123456789012"
    assert "rt-" not in body.text


def test_login_is_rate_limited(world, memstore, oauth) -> None:
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
    assert c.get("/auth/login").status_code == 303
    assert c.get("/auth/login").status_code == 303
    blocked = c.get("/auth/login")
    assert blocked.status_code == 429
    assert "Too many sign-in attempts" in blocked.text
    assert blocked.headers["retry-after"] == "600"


def test_mcp_is_rate_limited_per_token(world, memstore, oauth) -> None:
    app = build_app(
        make_settings(
            root_folder_id=None, allowlist_cache_ttl=0, mcp_rate_limit=2, mcp_rate_window_seconds=60
        ),
        world.as_user(OWNER_EMAIL),
        store=memstore,
        owner_drive_factory=lambda token: world.as_user(OWNER_EMAIL),
        oauth=oauth,
    )
    c = client(app)
    payload = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}

    def post(token: str):
        headers = {**MCP_HEADERS, "Authorization": f"Bearer {token}"}
        return c.post("/mcp", json=payload, headers=headers)

    assert post("nope").status_code == 401
    assert post("nope").status_code == 401
    blocked = post("nope")
    assert blocked.status_code == 429
    assert blocked.json() == {"error": "rate_limited"}
    assert blocked.headers["retry-after"] == "60"
    # A different made-up token must not start a fresh allowance for the same address.
    assert post("someone-else").status_code == 429

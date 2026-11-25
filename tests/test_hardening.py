"""Dashboard hardening: redirects, refusals that are not dead ends, headers and caching."""

import pytest

from scoped_drive_mcp.dashboard import TEMPLATES_DIR, safe_next
from tests.dash import client, csrf, login


@pytest.fixture
def c(p2_app):
    return client(p2_app)


@pytest.fixture
def owner_c(c):
    assert login(c).status_code == 303
    return c


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        # Paths a browser would rewrite to another site are dropped.
        ("/\t/evil.example", "/"),
        ("/\n/evil.example", "/"),
        ("/\r/evil.example", "/"),
        ("/ /x", "/"),
        ("/a\x7fb", "/"),
        ("//evil.example", "/"),
        ("/browse?folder=abc&q=a%20b", "/browse?folder=abc&q=a%20b"),
    ],
)
def test_next_refuses_paths_a_browser_would_rewrite_offsite(value: str, expected: str) -> None:
    assert safe_next(value) == expected


def test_connect_page_does_not_link_offsite(owner_c) -> None:
    page = owner_c.get("/connect", params={"next": "/\t/evil.example"})
    # Already connected, and the unsafe next is dropped: straight to Settings.
    assert page.status_code == 303 and page.headers["location"] == "/settings#services"
    assert "evil.example" not in page.text


def test_signed_out_post_gets_a_way_back_as_a_page_or_a_message(c) -> None:
    refused = c.post("/revoke", data={"file_id": "proj", "csrf": "x"})
    assert refused.status_code == 403
    assert "signed out" in refused.text
    assert 'href="/login"' in refused.text
    assert refused.headers["x-frame-options"] == "DENY"
    # A row action (fetch, wants JSON) gets a message it can show.
    refused = c.post(
        "/revoke", data={"file_id": "proj", "csrf": "x"}, headers={"Accept": "application/json"}
    )
    assert refused.status_code == 403
    body = refused.json()
    assert body["ok"] is False and body["changed"] is False
    assert "signed out" in body["message"]


def test_expired_or_odd_form_token_is_refused_with_a_message(owner_c) -> None:
    refused = owner_c.post(
        "/revoke", data={"file_id": "proj", "csrf": "stale"}, headers={"Accept": "application/json"}
    )
    assert refused.status_code == 403
    assert "reload the page" in refused.json()["message"]
    # Non-ASCII is refused the same way, not a crash.
    assert owner_c.post("/revoke", data={"file_id": "proj", "csrf": "é"}).status_code == 403


def test_bad_id_on_a_row_action_reports_the_reason(owner_c) -> None:
    refused = owner_c.post(
        "/grant",
        data={"file_id": "not a drive id!", "csrf": csrf(owner_c)},
        headers={"Accept": "application/json"},
    )
    assert refused.status_code == 400
    assert refused.headers["content-type"].startswith("application/json")
    assert refused.json()["message"]


def test_pages_are_not_cached_and_send_hsts(owner_c) -> None:
    page = owner_c.get("/")
    assert page.headers["cache-control"] == "no-store"
    assert page.headers["strict-transport-security"].startswith("max-age=")


@pytest.mark.parametrize("path", ["/app.css", "/ui.js"])
def test_assets_revalidate_instead_of_downloading_again(c, path: str) -> None:
    first = c.get(path)
    assert first.status_code == 200
    assert first.headers["cache-control"] == "no-cache"
    assert first.headers["x-content-type-options"] == "nosniff"
    again = c.get(path, headers={"If-None-Match": first.headers["etag"]})
    assert again.status_code == 304
    assert again.content == b""


def test_fonts_are_cached(c) -> None:
    font = c.get("/fonts/geist-400.woff2")
    assert font.status_code == 200
    assert "max-age=2592000" in font.headers["cache-control"]
    assert c.get("/fonts/nope.woff2").status_code == 404


def test_a_stale_page_link_falls_back_to_the_first_page(owner_c) -> None:
    stale = owner_c.get("/files", params={"folder": "root", "page": "garbage"})
    assert stale.status_code == 303
    assert stale.headers["location"] == "/files?folder=root"
    assert owner_c.get(stale.headers["location"]).status_code == 200


def test_final_decisions_ask_first() -> None:
    bridge = (TEMPLATES_DIR / "bridge.html").read_text()
    wakeups = (TEMPLATES_DIR / "settings.html").read_text()
    request = (TEMPLATES_DIR / "request.html").read_text()
    for template, action in ((bridge, "/deny"), (wakeups, "/bridge/webhook"), (request, "/deny")):
        forms = [f for f in template.split("<form")[1:] if action in f.split(">")[0]]
        removing = [f for f in forms if "deny" in f.split(">")[0] or 'value="remove"' in f]
        assert removing and all("data-confirm=" in f.split(">")[0] for f in removing)

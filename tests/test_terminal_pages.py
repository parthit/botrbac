"""Terminal, phase 1: the page is there for everyone and existing pages are unchanged."""

from tests import dash
from tests.terminal_helpers import terminal_app


def test_page_and_nav(world, memstore, oauth) -> None:
    c = dash.client(terminal_app(world, memstore, oauth))
    dash.login(c)
    assert 'href="/terminal"' in c.get("/").text
    r = c.get("/terminal")
    assert r.status_code == 200
    assert "botrbac login" in r.text


def test_signed_out_is_sent_to_login(world, memstore, oauth) -> None:
    r = dash.client(terminal_app(world, memstore, oauth)).get("/terminal")
    assert r.status_code == 303
    assert r.headers["location"].startswith("/login")


def test_existing_pages_still_answer(world, memstore, oauth) -> None:
    c = dash.client(terminal_app(world, memstore, oauth))
    dash.login(c)
    for page in ["/", "/files", "/requests", "/sharing", "/activity", "/settings"]:
        assert c.get(page).status_code == 200, page

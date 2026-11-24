"""Terminal beta, phase 1: off by default, and existing pages are unchanged when on."""

import pytest

from scoped_drive_mcp.flags import EdgeConfigFlags, terminal_allowed
from scoped_drive_mcp.server import build_app
from scoped_drive_mcp.terminal import TerminalFeature
from tests import dash
from tests.conftest import OWNER_EMAIL, make_settings


def _app(world, memstore, oauth, **overrides):
    settings = make_settings(root_folder_id=None, allowlist_cache_ttl=0, **overrides)
    return build_app(
        settings,
        world.as_user(OWNER_EMAIL),
        store=memstore,
        owner_drive_factory=lambda token: world.as_user(OWNER_EMAIL),
        oauth=oauth,
    )


@pytest.mark.parametrize(
    ("value", "email", "expected"),
    [
        (None, "a@x.com", False),
        ({"enabled": False}, "a@x.com", False),
        ({"enabled": "yes"}, "a@x.com", False),
        ({"enabled": True}, "a@x.com", True),
        ({"enabled": True, "emails": ["A@x.com"]}, "a@x.com", True),
        ({"enabled": True, "emails": ["b@x.com"]}, "a@x.com", False),
        ({"enabled": True, "emails": "a@x.com"}, "a@x.com", False),
    ],
)
def test_terminal_item(value, email, expected) -> None:
    assert terminal_allowed(value, email) is expected


def test_off_without_edge_config() -> None:
    assert EdgeConfigFlags(None).terminal_enabled("a@x.com") is False


def test_edge_config_beta_list() -> None:
    flags = EdgeConfigFlags(
        "https://edge-config.example/ecfg_1?token=t",
        fetch=lambda key: {"enabled": True, "emails": ["a@x.com"]},
    )
    assert flags.terminal_enabled("a@x.com") is True
    assert flags.terminal_enabled("b@x.com") is False


def test_flag_errors_mean_off() -> None:
    def boom(_: str) -> bool:
        raise RuntimeError

    assert TerminalFeature(False, boom).enabled_for("a@x.com") is False
    assert TerminalFeature(True, boom).enabled_for(None) is False


def test_off_by_default_page_and_nav_hidden(world, memstore, oauth, monkeypatch) -> None:
    monkeypatch.delenv("TERMINAL_ENABLED", raising=False)
    app = _app(world, memstore, oauth)
    assert app.state.dashboard.terminal is None
    c = dash.client(app)
    dash.login(c)
    home = c.get("/")
    assert 'href="/terminal"' not in home.text
    r = c.get("/terminal")
    assert r.status_code == 404


def test_on_shows_page_and_nav(world, memstore, oauth) -> None:
    app = _app(world, memstore, oauth, terminal_enabled=True)
    c = dash.client(app)
    dash.login(c)
    assert 'href="/terminal"' in c.get("/").text
    r = c.get("/terminal")
    assert r.status_code == 200
    assert "botrbac login" in r.text
    assert 'id="no-terminals"' in r.text


def test_signed_out_is_sent_to_login(world, memstore, oauth) -> None:
    app = _app(world, memstore, oauth, terminal_enabled=True)
    r = dash.client(app).get("/terminal")
    assert r.status_code == 303
    assert r.headers["location"].startswith("/login")


def test_existing_pages_unchanged_when_on(world, memstore, oauth) -> None:
    """The same pages answer the same way with the beta on, apart from the nav link."""
    pages = ["/", "/files", "/requests", "/sharing", "/activity", "/settings"]
    results = []
    for enabled in (False, True):
        c = dash.client(_app(world, memstore, oauth, terminal_enabled=enabled))
        dash.login(c)
        results.append([c.get(p).status_code for p in pages])
    assert results[0] == results[1]

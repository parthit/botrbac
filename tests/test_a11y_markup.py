"""Accessibility markup the dashboard relies on: current page, live region, button context."""

import re
from pathlib import Path

import pytest

from tests.dash import client, login, mcp_call, post

TEMPLATES = Path(__file__).resolve().parents[1] / "src/scoped_drive_mcp/templates"


@pytest.fixture
def owner_c(p2_app):
    c = client(p2_app)
    assert login(c).status_code == 303
    return c


def test_active_nav_item_has_aria_current(owner_c) -> None:
    page = owner_c.get("/files?tab=allowed").text
    current = re.findall(r'<a href="([^"]+)" class="on" aria-current="page">', page)
    assert current == ["/files"]
    assert page.count('aria-current="page"') == 1


def test_one_persistent_live_region_and_no_role_on_flash(owner_c) -> None:
    post(owner_c, "/grant", file_id="proj")
    page = owner_c.get("/files?tab=allowed").text
    assert page.count('id="live"') == 1
    assert 'aria-live="polite"' in page
    assert re.search(r'<div class="flash ok">[^<]*Projects', page)
    assert '<div class="flash ok" role=' not in page


def test_repeated_row_buttons_name_their_row(owner_c) -> None:
    post(owner_c, "/grant", file_id="proj")
    browse = owner_c.get("/files").text
    assert re.search(r'Remove<span class="sr-only"> Projects</span></button>', browse)
    access = owner_c.get("/files?tab=allowed").text
    assert 'Remove<span class="sr-only"> Projects</span>' in access
    # The search label uses the real class, no inline clipping styles.
    assert '<label class="sr-only" for="q">' in browse


def test_requests_last_column_has_a_header(owner_c) -> None:
    mcp_call(owner_c, "request_access", description="the Q3 memo", reason="summary")
    page = owner_c.get("/requests").text
    assert "<th></th>" not in page
    assert "<th>Open</th>" in page
    assert 'Approve or deny<span class="sr-only"> the Q3 memo</span>' in page


def test_not_found_page_says_so(owner_c) -> None:
    page = owner_c.get("/no-such-page")
    assert page.status_code == 404
    assert "<title>Page not found · Bot RBAC</title>" in page.text
    assert "<h1>Page not found</h1>" in page.text
    assert "Something went wrong" not in page.text


def test_other_errors_stay_generic(owner_c) -> None:
    # A sign-in callback with a forged state is a plain error, not a missing page.
    page = owner_c.get("/auth/callback", params={"code": "owner-code", "state": "forged"})
    assert page.status_code == 400
    assert "<h1>Something went wrong</h1>" in page.text
    assert "Page not found" not in page.text


def test_admin_title_matches_heading(owner_c) -> None:
    page = owner_c.get("/admin").text
    assert "<title>People · Bot RBAC</title>" in page
    assert "<h1>People</h1>" in page


def test_css_defines_sr_only_and_dark_palette() -> None:
    css = (TEMPLATES / "app.css").read_text()
    assert ".sr-only {" in css
    assert "color-scheme: light dark" in css
    assert "@media (prefers-color-scheme: dark)" in css
    assert "overflow-wrap: anywhere" in css


def test_ui_js_keeps_focus_and_closes_phone_menu() -> None:
    script = (TEMPLATES / "ui.js").read_text()
    assert 'getElementById("live")' in script
    assert '"Escape"' in script and "focusout" in script
    # removeRow moves focus to a neighbouring row instead of leaving it on <body>.
    assert "rowTarget(next) || rowTarget(prev)" in script

"""Pages and tool answers that used to leave a person (or an assistant) with nowhere to go."""

import json
import re
import secrets
from html import unescape
from urllib.parse import parse_qs, urlparse

import pytest

from scoped_drive_mcp.access import AccessRequests
from scoped_drive_mcp.humanize import app_names, assistant_label, describe, when
from tests.conftest import EVE, OWNER_EMAIL
from tests.dash import (
    client,
    connect_drive,
    csrf,
    login,
    mcp_call,
    post,
    sign_in,
    start_oauth,
)
from tests.test_external_sharing import _error, _pair
from tests.test_mcp_oauth import GROK, auth_params, register
from tests.test_multi_user import _app, _grok, _mcp


@pytest.fixture
def owner_c(p2_app):
    c = client(p2_app)
    r = login(c)
    assert r.status_code == 303 and r.headers["location"] == "/"
    return c


# ---- A. "Drive is not connected" says so, and points at Connections --------------


def test_access_and_sharing_point_at_connections_without_drive(p2_app) -> None:
    c = client(p2_app)
    sign_in(c)  # step 1 only
    access = c.get("/access").text
    assert "Google Drive is not connected yet" in access
    assert 'href="/connect"' in access
    assert "Sign out and sign in again" not in access and "not stored yet" not in access
    sharing = c.get("/sharing").text
    assert "Connect Google Drive first" in sharing
    assert "Open Browse" not in sharing


# ---- B. Request pages that contradicted themselves ---------------------------------


def test_reading_a_paired_persons_file_points_at_read_shared_file(world, memstore, oauth) -> None:
    app = _app(world, memstore, oauth)
    owner, eve = client(app), client(app)
    login(owner)
    login(eve, "eve-code")
    token = _grok(eve, "Grok Eve")
    assert post(owner, "/sharing/add", file_id="loose-doc").status_code == 303
    _pair(app, OWNER_EMAIL, EVE)

    result = _mcp(eve, token, "read_file", file_id="loose-doc")
    payload = result["structuredContent"]
    assert result["isError"] is True
    assert payload["error"] == "shared_with_you" and payload["owner"] == OWNER_EMAIL
    assert "read_shared_file" in payload["message"] and "approval_url" not in payload
    assert "memo beta" not in json.dumps(result)
    # Nothing was filed that Eve could never approve.
    assert "Approve or deny" not in eve.get("/requests").text
    shared = _mcp(eve, token, "read_shared_file", owner=OWNER_EMAIL, file_id="loose-doc")
    assert shared["isError"] is False

    # An unshared file of the owner's is still just "not found" for Eve.
    other = _mcp(eve, token, "read_file", file_id="loose-two")["structuredContent"]
    assert other["error"] == "not_found" and "owner" not in other


def test_old_request_for_a_paired_persons_file_says_it_is_not_in_your_drive(
    world, memstore, oauth
) -> None:
    app = _app(world, memstore, oauth)
    owner, eve = client(app), client(app)
    login(owner)
    login(eve, "eve-code")
    assert post(owner, "/sharing/add", file_id="loose-doc").status_code == 303
    _pair(app, OWNER_EMAIL, EVE)
    store = app.state.dashboard.directory.store_for(EVE)
    req, _ = AccessRequests(store).create(
        tool="read_file", token_name="oauth:Grok_Eve", reason="r", file_id="loose-doc"
    )
    page = eve.get(f"/requests/{req.id}").text
    assert "This file isn\u2019t in your Drive" in page
    assert OWNER_EMAIL in page and "read_shared_file" in page
    assert "Sign in again" not in page and "picker" not in page.lower()
    assert "Deny" in page


def test_request_link_opened_by_the_wrong_account(world, memstore, oauth) -> None:
    app = _app(world, memstore, oauth)
    owner, eve = client(app), client(app)
    login(owner)
    login(eve, "eve-code")
    rid = mcp_call(owner, "read_file", file_id="priv-secret")["structuredContent"]["request_id"]

    page = eve.get(f"/requests/{rid}")
    assert page.status_code == 403
    assert f"This request isn\u2019t for {EVE}" in page.text
    assert "Sign in with the Google account that owns this assistant" in page.text
    assert OWNER_EMAIL not in page.text and "payroll" not in page.text
    assert "Switch account" in page.text and 'href="/requests"' in page.text
    # Approving from the wrong account changes nothing.
    assert post(eve, f"/requests/{rid}/approve", target_id="priv-secret").status_code == 403
    assert app.state.dashboard.allowlist.entries() == {}

    form_csrf = csrf(eve, "/")
    out = eve.post("/logout", data={"csrf": form_csrf, "next": f"/requests/{rid}"})
    assert out.status_code == 303
    target = out.headers["location"]
    assert target.startswith("/login?") and parse_qs(urlparse(target).query) == {
        "signed_out": ["1"],
        "next": [f"/requests/{rid}"],
    }
    login_page = eve.get(target).text
    assert "You\u2019ve signed out." in login_page
    assert "Sign in to review an access request." in login_page
    assert "Step 1 of 2" not in login_page


def test_unknown_request_id_links_to_all_requests(owner_c) -> None:
    page = owner_c.get(f"/requests/{secrets.token_urlsafe(24)}")
    assert page.status_code == 404
    assert "<h1>Request not found</h1>" in page.text
    assert "<title>Request not found" in page.text
    assert 'href="/requests"' in page.text and "Switch account" not in page.text


def test_login_explains_why_from_a_consent_link(p2_app) -> None:
    c = client(p2_app)
    page = c.get("/login", params={"next": "/oauth/authorize?client_id=x"}).text
    assert "Sign in to connect an assistant." in page
    plain = c.get("/login").text
    assert "Sign in to" not in plain.split("<h1>", 1)[1].split("</section>", 1)[0].split(".")[0]
    assert "Step 1 of 2" not in plain


def test_request_page_names_the_app_and_shows_its_reason(world, memstore, oauth) -> None:
    app = _app(world, memstore, oauth)
    owner = client(app)
    login(owner)
    token = _grok(owner, "Grok Ada")
    asked = _mcp(
        owner,
        token,
        "request_access",
        description="the Q3 budget",
        reason="To summarise spending for the board",
    )["structuredContent"]
    page = owner.get(f"/requests/{asked['request_id']}").text
    headline = re.search(r"<h2>(.*?)</h2>", page).group(1)
    assert headline == "Grok Ada is asking to use the Q3 budget."
    reason = page[page.index('id="request-reason"') :].split("</blockquote>", 1)[0]
    assert "To summarise spending for the board" in reason
    assert page.index('id="request-reason"') < page.index("Technical details")
    listing = owner.get("/requests").text
    assert "Grok Ada" in listing and "oauth:Grok_Ada" not in listing


def test_legacy_token_requests_have_a_friendly_name(owner_c) -> None:
    rid = mcp_call(owner_c, "read_file", file_id="priv-secret")["structuredContent"]["request_id"]
    page = owner_c.get(f"/requests/{rid}").text
    assert "<h2>Your assistant (viewer token) wants to read payroll.txt.</h2>" in page


def test_pick_mode_does_not_offer_already_allowed_items(owner_c) -> None:
    post(owner_c, "/grant", file_id="loose-doc")
    asked = mcp_call(owner_c, "request_access", description="a memo", reason="r")
    rid = asked["structuredContent"]["request_id"]
    page = owner_c.get(f"/browse?request={rid}").text
    page = page[page.index('<ul class="files">') :]
    loose = page[page.index("Loose memo") :].split("</li>", 1)[0]
    assert "Already allowed" in loose and "Share for this request" not in loose
    two = page[page.index("Second memo") :].split("</li>", 1)[0]
    assert "Share for this request" in two


def test_approved_request_names_the_item_for_the_assistant(owner_c) -> None:
    rid = mcp_call(owner_c, "read_file", file_id="priv-secret")["structuredContent"]["request_id"]
    post(owner_c, f"/requests/{rid}/approve", target_id="priv")
    status = mcp_call(owner_c, "check_access_request", request_id=rid)["structuredContent"]
    assert status["granted_name"] == "Private"
    assert "\u201cPrivate\u201d (id priv)" in status["message"]
    assert "list_folder" in status["message"]


# ---- C. Cancelling on Google's screen ------------------------------------------------


def test_cancelling_the_drive_connect_offers_try_again(p2_app) -> None:
    c = client(p2_app)
    sign_in(c)
    token = csrf(c, "/connect")
    state = start_oauth(c, "/connect/google_drive", csrf=token, next="/browse")
    page = c.get("/auth/callback", params={"error": "access_denied", "state": state})
    assert page.status_code == 400
    assert "You didn\u2019t connect Google Drive" in page.text
    assert "Something went wrong" not in page.text
    assert 'href="/connect?next=%2Fbrowse">Try again' in page.text


def test_cancelling_sign_in_offers_try_again(p2_app) -> None:
    c = client(p2_app)
    state = start_oauth(c, "/auth/login?next=/access")
    page = c.get("/auth/callback", params={"error": "access_denied", "state": state})
    assert page.status_code == 400
    assert "<h1>Sign-in cancelled</h1>" in page.text
    assert 'href="/login?next=%2Faccess">Try again' in page.text


def test_connecting_a_different_account_offers_try_again(p2_app) -> None:
    c = client(p2_app)
    sign_in(c)
    page = connect_drive(c, "eve-code")
    assert page.status_code == 403
    assert "Google returned a different account" in page.text
    assert ">Try again</a>" in page.text and 'href="/connect"' in page.text


# ---- D. An assistant waiting while Drive is connected --------------------------------


def test_connect_page_names_the_waiting_assistant(p2_app) -> None:
    c = client(p2_app)
    sign_in(c)
    client_id = register(c, GROK, name="Grok Bot").json()["client_id"]
    _, params = auth_params(client_id, GROK)
    detour = c.get("/oauth/authorize", params=params)
    assert detour.status_code == 303 and detour.headers["location"].startswith("/connect?next=")
    page = c.get(detour.headers["location"]).text
    assert "Grok Bot is waiting to connect." in page
    assert "then you\u2019ll be asked to Allow it" in page
    assert "Continue where you left off" not in page and "Continue to" not in page

    next_url = parse_qs(urlparse(detour.headers["location"]).query)["next"][0]
    done = connect_drive(c, next_url=next_url)
    assert done.status_code == 303 and done.headers["location"] == next_url
    again = c.get(detour.headers["location"]).text
    assert "is waiting to connect" not in again
    assert re.search(r'<a class="btn primary" href="[^"]+">Continue to Grok Bot</a>', again)


# ---- E. Headings and next steps ------------------------------------------------------


def test_connect_page_heading_after_drive_is_connected(owner_c) -> None:
    page = owner_c.get("/connect").text
    assert "Step 2 of 2" not in page and "One more step" not in page
    assert "<h1>Connections.</h1>" in page


def test_overview_says_what_to_do_next(owner_c) -> None:
    page = owner_c.get("/").text
    assert "Next: choose files your assistant can use" in page
    assert 'href="/browse">Choose files</a>' in page
    assert "setup cards above" not in page and "Copy the MCP URL above" in page
    post(owner_c, "/grant", file_id="loose-doc")
    assert "Next: choose files" not in owner_c.get("/").text


# ---- G. Timestamps ---------------------------------------------------------------------


def test_when_renders_a_time_element() -> None:
    html = str(when("2026-11-19T23:58:10.123+00:00"))
    assert html == (
        '<time datetime="2026-11-19T23:58:10Z" data-time title="Nov 19, 2026, 23:58 UTC">'
        "Nov 19, 2026, 23:58 UTC</time>"
    )
    assert str(when("2026-11-19T18:58:10-05:00")).startswith(
        '<time datetime="2026-11-19T23:58:10Z"'
    )
    assert str(when(None)) == "—" and str(when("", "Never")) == "Never"
    assert str(when("<script>")) == "&lt;script&gt;"


def test_dashboard_pages_render_times_not_iso_strings(owner_c) -> None:
    post(owner_c, "/grant", file_id="loose-doc")
    mcp_call(owner_c, "read_file", file_id="priv-secret")
    for path in ("/access", "/requests", "/activity"):
        page = owner_c.get(path).text
        assert "data-time" in page, path
        visible = re.sub(r"<[^>]+>", " ", page)
        assert not re.search(r"\d{4}-\d\d-\d\dT\d\d:\d\d", visible), path


def test_ui_script_localises_times() -> None:
    from pathlib import Path

    script = (Path(__file__).parents[1] / "src/scoped_drive_mcp/templates/ui.js").read_text()
    assert 'querySelectorAll("time[data-time]")' in script
    assert "RelativeTimeFormat" in script


# ---- F. Activity sentences ---------------------------------------------------------------


def test_assistant_labels() -> None:
    assert assistant_label("viewer-tok") == "Your assistant (viewer token)"
    assert assistant_label("oauth:Grok_owner") == "Grok owner"
    grants = [type("G", (), {"client_name": "Grok (owner)"})()]
    assert assistant_label("oauth:Grok_owner", app_names(grants)) == "Grok (owner)"
    assert assistant_label(f"guest:{EVE}") == f"{EVE}\u2019s assistant"
    assert assistant_label(f"guest:{EVE} (dashboard)") == EVE
    assert assistant_label(None) == "An assistant"


def test_describe_owner_and_tool_records() -> None:
    names = {"f1": "other.txt"}
    denied = describe(
        {"event": "owner", "action": "deny_request", "file_id": "f1", "decision": "allow"},
        names,
    )
    assert denied.text == "You denied a request for \u201cother.txt\u201d."
    assert (denied.badge.tone, denied.badge.label) == ("bad", "Denied")
    shared = describe({"event": "owner", "action": "share_external", "file_id": "zz"})
    assert shared.text == "You shared a file with people you are paired with."
    read = describe(
        {
            "event": "tool_call",
            "token_name": "viewer-tok",
            "tool": "read_file",
            "file_id": "f1",
            "decision": "allow",
            "reason": "ok",
        },
        names,
    )
    assert read.text == "Your assistant (viewer token) read \u201cother.txt\u201d."
    poll = describe(
        {"event": "tool_call", "tool": "check_messages", "decision": "allow", "reason": "ok"}
    )
    assert poll.polling and not poll.attention
    failed = describe(
        {
            "event": "tool_call",
            "token_name": "viewer-tok",
            "tool": "read_file",
            "file_id": "f1",
            "decision": "error",
            "reason": "bot_not_connected",
        },
        names,
    )
    assert "Google Drive isn\u2019t connected" in failed.text and failed.attention


# ---- H. Wording --------------------------------------------------------------------------


def test_own_file_on_shared_pages_speaks_to_a_person(owner_c) -> None:
    page = owner_c.get("/shared/open", params={"owner": OWNER_EMAIL, "id": "loose-doc"}).text
    assert "This is in your own Drive. Open it from Browse." in page
    assert "list_folder" not in page and "read_file" not in page


def test_not_linked_message_names_the_mailbox_page(world, memstore, oauth) -> None:
    app = _app(world, memstore, oauth)
    eve = client(app)
    login(eve, "eve-code")
    token = _grok(eve, "Grok Eve")
    refused = _error(_mcp(eve, token, "read_shared_file", owner=OWNER_EMAIL, file_id="x"))
    assert "Mailbox page" in refused["message"] and "/bridge" not in refused["message"]


def test_list_folder_note_and_consent_deny_wording(owner_c) -> None:
    listed = mcp_call(owner_c, "list_folder")["structuredContent"]
    assert listed["note"].startswith("These are the items the user allowed you to use.")
    client_id = register(owner_c, GROK).json()["client_id"]
    _, params = auth_params(client_id, GROK)
    assert owner_c.get("/oauth/authorize", params=params).status_code == 200
    denied = post(owner_c, "/oauth/authorize", decision="deny")
    landing = owner_c.get(denied.headers["location"])
    target = unescape(re.search(r'url=([^"]+)"', landing.text).group(1))
    assert parse_qs(urlparse(target).query)["error_description"] == ["The user denied access."]


def test_browse_and_mode_note_wording(owner_c) -> None:
    browse = owner_c.get("/browse").text
    assert "<h1>Your Google Drive</h1>" in browse
    assert "Files this app can see" not in browse and "Google Picker" not in browse
    assert "may still hide files" not in owner_c.get("/browse?folder=proj").text
    overview = owner_c.get("/").text
    assert '<div class="card" id="mode-note">' in overview


def test_activity_names_missing_files_and_requests(owner_c) -> None:
    mcp_call(owner_c, "read_file", file_id="no-such-file-123")
    mcp_call(owner_c, "request_access", description="the Q3 budget", reason="r")
    page = owner_c.get("/activity").text
    missing = "Your assistant (viewer token) tried to read a file that isn’t in your Drive."
    assert missing in page
    # The request's own description names the row, not "something in your Drive".
    assert "asked for access to something in your Drive" not in page
    row = page[page.index("asked for access to “the Q3 budget”") :].split("</li>", 1)[0]
    assert "Asked" in row and "Allowed" not in row


def test_decided_request_headline_is_past_tense() -> None:
    from types import SimpleNamespace

    from scoped_drive_mcp.dashboard import request_headline

    req = SimpleNamespace(
        token_name="viewer-tok", file_name="old notes", description=None, tool="request_access"
    )
    req.status = "pending"
    assert request_headline(req).endswith("is asking to use old notes.")
    req.status = "denied"
    assert request_headline(req).endswith("asked to use old notes.")
    req.tool, req.status = "read_file", "approved"
    assert request_headline(req).endswith("asked to read old notes.")


def test_old_request_for_a_file_inside_a_shared_folder_names_the_sharer(
    world, memstore, oauth
) -> None:
    """The request page uses the same guest guard as read_file: a file inside a folder on
    the sharer's list counts as shared, not only the exact id that was shared."""
    app = _app(world, memstore, oauth)
    owner, eve = client(app), client(app)
    login(owner)
    login(eve, "eve-code")
    assert post(owner, "/sharing/add", file_id="proj").status_code == 303
    _pair(app, OWNER_EMAIL, EVE)
    store = app.state.dashboard.directory.store_for(EVE)
    req, _ = AccessRequests(store).create(
        tool="read_file", token_name="oauth:Grok_Eve", reason="r", file_id="proj-notes"
    )
    page = eve.get(f"/requests/{req.id}").text
    assert "This file isn’t in your Drive" in page
    assert OWNER_EMAIL in page and "read_shared_file" in page


def test_mailbox_refusals_are_not_blamed_on_drive() -> None:
    record = {
        "ts": "2026-11-20T00:00:00+00:00",
        "event": "tool_call",
        "token_name": "viewer-tok",
        "tool": "send_message",
        "decision": "error",
        "reason": "link_revoked",
    }
    text = describe(record, {}, {}, {}).text
    assert "pairing is off" in text and "Google Drive" not in text
    record["reason"] = "some_new_code"
    assert "Google Drive" not in describe(record, {}, {}, {}).text

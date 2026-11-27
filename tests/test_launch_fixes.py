"""Pre-launch UX fixes: per-app switches for the Mailbox and Shared with me, the owner's
Mailbox page, the public 404, Overview's next steps, and the home page's share tags."""

import pytest

from scoped_drive_mcp.policy import FEATURE_TOOLS, VIEWER_TOOLS
from tests.dash import client, csrf, login, post
from tests.mail import READER, SENDER, self_pair
from tests.test_mcp_oauth import GROK, call_tool, connect, tool_names

MAILBOX = FEATURE_TOOLS["mailbox"]
# Read only is the default level, so only its share of each part is listed.
SHARED = FEATURE_TOOLS["shared"] & VIEWER_TOOLS


@pytest.fixture
def owner_c(p2_app):
    c = client(p2_app)
    assert login(c).status_code == 303
    return c


def _grant_id(app) -> str:
    grants = app.state.dashboard.mcp_oauth.list_grants("owner@example.com")
    assert len(grants) == 1
    return grants[0].id


# ---- switches on the consent page ---------------------------------------------------


def test_first_assistant_gets_mailbox_and_shared_unticked(owner_c) -> None:
    from tests.test_mcp_oauth import auth_params, register

    client_id = register(owner_c, GROK).json()["client_id"]
    _verifier, params = auth_params(client_id, GROK)
    page = owner_c.get("/oauth/authorize", params=params).text
    assert 'id="consent-features"' in page
    assert 'name="features_shown" value="mailbox,shared"' in page
    # Nothing to talk to and no one sharing yet: both boxes start empty.
    assert 'name="feature_mailbox" value="on" checked' not in page
    assert 'name="feature_shared" value="on" checked' not in page


def test_unticked_parts_are_neither_listed_nor_callable(owner_c, p2_app) -> None:
    _client, token = connect(owner_c, features_shown="mailbox,shared")
    names = tool_names(owner_c, token["access_token"])
    assert not names & MAILBOX
    assert not names & SHARED
    assert "list_folder" in names
    result = call_tool(owner_c, token["access_token"], "check_messages")
    assert result.get("isError") is True

    # Ticked on in Settings, the next call may use them.
    gid = _grant_id(p2_app)
    r = post(
        owner_c,
        "/oauth/grants/features",
        grant_id=gid,
        feature_mailbox="on",
        feature_shared="on",
    )
    assert r.status_code == 303
    names = tool_names(owner_c, token["access_token"])
    assert MAILBOX <= names
    assert call_tool(owner_c, token["access_token"], "check_messages").get("isError") is not True


def test_ticked_parts_stay_on(owner_c) -> None:
    _client, token = connect(
        owner_c, features_shown="mailbox,shared", feature_mailbox="on", feature_shared="on"
    )
    names = tool_names(owner_c, token["access_token"])
    assert MAILBOX <= names and SHARED <= names


def test_a_consent_page_from_before_the_switches_leaves_everything_on(owner_c) -> None:
    # No features_shown: the page did not offer the boxes, so nothing is switched off.
    _client, token = connect(owner_c)
    names = tool_names(owner_c, token["access_token"])
    assert MAILBOX <= names and SHARED <= names


def test_a_damaged_switch_record_turns_the_parts_off(owner_c, p2_app, memstore) -> None:
    _client, token = connect(owner_c)
    gid = _grant_id(p2_app)
    p2_app.state.dashboard.mcp_oauth.store.set(f"oauth:features:{gid}", "not json")
    names = tool_names(owner_c, token["access_token"])
    assert not names & MAILBOX


def test_switches_belong_to_their_owner(owner_c, p2_app) -> None:
    connect(owner_c)
    gid = _grant_id(p2_app)
    assert p2_app.state.dashboard.mcp_oauth.set_features(gid, "eve@example.com", {}) is False
    assert p2_app.state.dashboard.mcp_oauth.features_of(gid) == {"mailbox": True, "shared": True}


def test_settings_says_what_each_assistant_can_open(owner_c, p2_app) -> None:
    connect(owner_c)
    post(owner_c, "/grant", file_id="proj")
    page = owner_c.get("/settings").text
    assert "Can open <b>1 allowed item</b>" in page
    assert "the same for every assistant" in page
    assert 'action="/oauth/grants/features"' in page


# ---- the owner's Mailbox ------------------------------------------------------------


def test_mailbox_page_shows_messages_escaped_and_marks_nothing_read(owner_c, p2_app) -> None:
    from scoped_drive_mcp.bridge import as_assistant

    box = p2_app.state.mailbox
    link = self_pair(box)
    with as_assistant(SENDER):
        box.send_message("owner@example.com", link, "<b>Q3 notes</b> are in Projects")
    page = owner_c.get("/sharing?tab=mailbox").text
    assert "&lt;b&gt;Q3 notes&lt;/b&gt; are in Projects" in page
    assert "<b>Q3 notes</b>" not in page
    assert "Grok" in page and "Claude" in page
    assert "Unread by Claude" in page
    with as_assistant(READER):
        assert box.check_messages("owner@example.com")["unread_count"] == 1


def test_mailbox_page_empty_state(owner_c) -> None:
    page = owner_c.get("/sharing?tab=mailbox").text
    assert 'id="mail-empty"' in page and "No messages" in page


def test_sent_mail_is_not_labelled_allowed_in_activity(owner_c, p2_app) -> None:
    from scoped_drive_mcp.humanize import _MAIL_BADGES

    assert _MAIL_BADGES["send_message"].label == "Sent"
    assert _MAIL_BADGES["request_link"].label == "Pairing"


# ---- pages ---------------------------------------------------------------------------


def test_unknown_address_signed_out_is_a_404_not_a_sign_in(p2_app) -> None:
    c = client(p2_app)
    r = c.get("/no-such-page")
    assert r.status_code == 404
    assert "Page not found" in r.text
    # A real page still asks to sign in.
    assert c.get("/files").status_code == 303


def test_unknown_address_signed_in_is_a_404(owner_c) -> None:
    r = owner_c.get("/no-such-page")
    assert r.status_code == 404 and "Page not found" in r.text


def test_overview_checklist_and_pending_banner(owner_c, p2_app) -> None:
    page = owner_c.get("/").text
    assert 'id="next-step"' in page and "Get your assistant reading one folder" in page
    assert 'id="pending-banner"' not in page
    _client, token = connect(owner_c)
    # The assistant asks for a file that is not allowed: a request waits for the owner.
    result = call_tool(owner_c, token["access_token"], "read_file", file_id="priv-secret")
    assert result.get("isError") is True
    page = owner_c.get("/").text
    assert 'id="pending-banner"' in page and 'href="/requests">Review</a>' in page


def test_home_page_has_share_tags(p2_app) -> None:
    page = client(p2_app).get("/").text
    assert '<meta name="description"' in page
    assert '<meta property="og:title"' in page
    assert 'property="og:url" content="https://drive-test.example.com/"' in page
    assert "Claude, ChatGPT, Grok or Cursor" in page
    # One statement about what Bot RBAC can see, not two that disagree.
    assert "visible to this server" not in page


def test_contact_email_shows_only_when_set(world, memstore, oauth) -> None:
    from tests.test_mcp_oauth import _app

    plain = client(_app(world, memstore, oauth)).get("/").text
    assert "mailto:" not in plain
    app = _app(world, memstore, oauth, contact_email="help@example.com")
    page = client(app).get("/").text
    assert 'href="mailto:help@example.com"' in page


def test_contact_email_must_be_one_address() -> None:
    from pydantic import ValidationError

    from tests.conftest import make_settings

    with pytest.raises(ValidationError):
        make_settings(contact_email="a@b.com, c@d.com")


def test_nav_has_assistants_and_hides_while_connecting_drive(p2_app) -> None:
    from tests.dash import sign_in

    c = client(p2_app)
    sign_in(c)
    connect_page = c.get("/connect").text
    assert 'href="/files"' not in connect_page.split("</nav>")[0]
    assert login(c).status_code in (200, 303)
    page = c.get("/").text
    nav = page.split('id="site-nav"')[1].split("</nav>")[0]
    assert 'href="/settings#assistants"' in nav
    assert csrf(c, "/")

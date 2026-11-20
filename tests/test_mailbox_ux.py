"""Mailbox pairing cards, invite reuse, declined vs turned off, delivered mail after
turning off, the dashboard badge and summary, the consent page, and structured errors."""

import json
from urllib.parse import parse_qs, urlparse

import pytest

from scoped_drive_mcp.bridge import Mailbox, MailboxError
from scoped_drive_mcp.store import MemoryStore
from tests.conftest import EVE, OWNER_EMAIL, FakeClock
from tests.dash import client, csrf, login, mcp_call
from tests.test_mcp_oauth import CURSOR, auth_params, register

CAROL = "carol@example.com"
DAY = 24 * 3600


def _box(clock: FakeClock) -> Mailbox:
    return Mailbox(MemoryStore(clock=clock), base_url="https://drive-test.example.com", clock=clock)


def _pair(box: Mailbox, a: str = OWNER_EMAIL, b: str = EVE) -> str:
    created = box.request_link(a, new_invite=True)
    box.request_link(b, created["invite_code"])
    box.decide(a, created["link_id"], "approve")
    box.decide(b, created["link_id"], "approve")
    return created["link_id"]


def _card(box: Mailbox, who: str, link_id: str) -> dict:
    return next(link for link in box.list_links(who)["links"] if link["link_id"] == link_id)


# ---- invites ---------------------------------------------------------------------


def test_request_link_reuses_an_unjoined_invite(clock: FakeClock) -> None:
    box = _box(clock)
    first = box.request_link(OWNER_EMAIL)
    assert first["reused"] is False
    assert first["invite_expires_at"]
    again = box.request_link(OWNER_EMAIL)
    assert again["reused"] is True
    assert again["link_id"] == first["link_id"]
    assert again["invite_code"] == first["invite_code"]
    assert len(box.list_links(OWNER_EMAIL)["links"]) == 1

    # new_invite starts a second one in parallel.
    second = box.request_link(OWNER_EMAIL, new_invite=True)
    assert second["link_id"] != first["link_id"] and second["reused"] is False

    # Once someone joined, or the invite expired, a fresh one is minted.
    box.request_link(EVE, second["invite_code"])
    newest = box.request_link(OWNER_EMAIL)
    assert newest["link_id"] == first["link_id"]  # still the open one
    clock.advance(8 * DAY)
    fresh = box.request_link(OWNER_EMAIL)
    assert fresh["reused"] is False and fresh["link_id"] != first["link_id"]
    expired = _card(box, OWNER_EMAIL, first["link_id"])
    assert expired["status"] == "expired"
    assert "invite_code" not in expired
    assert "new invite code" in expired["next_step"]


def test_cancel_invite_kills_the_code_and_removes_the_card(clock: FakeClock) -> None:
    box = _box(clock)
    created = box.request_link(OWNER_EMAIL)
    with pytest.raises(MailboxError) as not_yours:
        box.cancel_invite(EVE, created["link_id"])
    assert not_yours.value.code == "not_found"
    box.cancel_invite(OWNER_EMAIL, created["link_id"])
    assert box.list_links(OWNER_EMAIL)["links"] == []
    with pytest.raises(MailboxError) as gone:
        box.request_link(EVE, created["invite_code"])
    assert gone.value.code == "invite_not_found"
    # A later request_link does not hand back the cancelled code.
    assert box.request_link(OWNER_EMAIL)["link_id"] != created["link_id"]

    joined = box.request_link(OWNER_EMAIL, new_invite=True)
    box.request_link(EVE, joined["invite_code"])
    with pytest.raises(MailboxError) as taken:
        box.cancel_invite(OWNER_EMAIL, joined["link_id"])
    assert taken.value.code == "invalid_state"


def test_joining_a_second_pairing_with_the_same_person_is_refused(clock: FakeClock) -> None:
    box = _box(clock)
    link_id = _pair(box)
    second = box.request_link(OWNER_EMAIL, new_invite=True)
    with pytest.raises(MailboxError) as dup:
        box.request_link(EVE, second["invite_code"])
    assert dup.value.code == "already_paired"
    assert dup.value.details["link_id"] == link_id
    # The invite is still open for someone else.
    assert box.request_link(CAROL, second["invite_code"])["status"] == "pending_approval"
    # After turning the old one off, pairing again works.
    box.revoke(OWNER_EMAIL, link_id)
    third = box.request_link(OWNER_EMAIL, new_invite=True)
    assert box.request_link(EVE, third["invite_code"])["status"] == "pending_approval"


# ---- declined vs turned off --------------------------------------------------------


def test_declined_and_turned_off_are_told_apart(clock: FakeClock) -> None:
    box = _box(clock)
    created = box.request_link(OWNER_EMAIL)
    box.request_link(EVE, created["invite_code"])
    box.decide(EVE, created["link_id"], "deny")
    for who in (OWNER_EMAIL, EVE):
        card = _card(box, who, created["link_id"])
        assert card["status"] == "declined"
        assert card["ended_reason"] == "declined"
        assert card["ended_by"] == EVE
        assert card["ended_at"]
    assert f"{EVE} declined" in _card(box, OWNER_EMAIL, created["link_id"])["next_step"]
    assert _card(box, EVE, created["link_id"])["next_step"].startswith("You declined")
    # Sending is refused exactly as before.
    with pytest.raises(MailboxError) as refused:
        box.send_message(OWNER_EMAIL, created["link_id"], "hi")
    assert refused.value.code == "link_revoked"
    with pytest.raises(MailboxError):
        box.decide(OWNER_EMAIL, created["link_id"], "approve")

    link_id = _pair(box, OWNER_EMAIL, CAROL)
    clock.advance(DAY)
    box.revoke(CAROL, link_id)
    card = _card(box, OWNER_EMAIL, link_id)
    assert card["status"] == "revoked"
    assert card["ended_reason"] == "turned_off"
    assert card["ended_by"] == CAROL
    assert f"{CAROL} turned this pairing off" in card["next_step"]
    assert "Sharing" in card["next_step"]


def test_cancelling_a_pending_pairing_says_cancelled(clock: FakeClock) -> None:
    box = _box(clock)
    created = box.request_link(OWNER_EMAIL)
    box.request_link(EVE, created["invite_code"])
    box.decide(OWNER_EMAIL, created["link_id"], "approve")
    box.revoke(OWNER_EMAIL, created["link_id"])
    card = _card(box, EVE, created["link_id"])
    assert card["status"] == "revoked" and card["ended_reason"] == "cancelled"


def test_dismiss_only_removes_dead_cards_for_that_person(clock: FakeClock) -> None:
    box = _box(clock)
    link_id = _pair(box)
    with pytest.raises(MailboxError) as live:
        box.dismiss(OWNER_EMAIL, link_id)
    assert live.value.code == "invalid_state"
    pending = box.request_link(OWNER_EMAIL, new_invite=True)
    box.request_link(CAROL, pending["invite_code"])
    with pytest.raises(MailboxError):
        box.dismiss(CAROL, pending["link_id"])

    box.revoke(EVE, link_id)
    box.dismiss(OWNER_EMAIL, link_id)
    assert link_id not in {link["link_id"] for link in box.list_links(OWNER_EMAIL)["links"]}
    assert link_id in {link["link_id"] for link in box.list_links(EVE)["links"]}

    stale = box.request_link(EVE, new_invite=True)
    clock.advance(8 * DAY)
    box.dismiss(EVE, stale["link_id"])
    assert stale["link_id"] not in {link["link_id"] for link in box.list_links(EVE)["links"]}


# ---- mail after turning off ------------------------------------------------------


def test_delivered_mail_stays_readable_after_turning_off(clock: FakeClock) -> None:
    box = _box(clock)
    link_id = _pair(box)
    sent = box.send_message(EVE, link_id, "reply you have not read yet")
    box.revoke(EVE, link_id)

    checked = box.check_messages(OWNER_EMAIL)
    assert checked["unread_count"] == 1
    assert checked["latest_preview"][0]["link_status"] == "revoked"
    inbox = box.list_inbox(OWNER_EMAIL)
    assert [m["msg_id"] for m in inbox["messages"]] == [sent["msg_id"]]
    assert inbox["messages"][0]["link_status"] == "revoked"
    assert box.list_inbox(OWNER_EMAIL, link_id=link_id)["messages"][0]["msg_id"] == sent["msg_id"]
    assert box.mark_read(OWNER_EMAIL, [sent["msg_id"]])["marked"] == 1
    assert box.check_messages(OWNER_EMAIL)["unread_count"] == 0
    with pytest.raises(MailboxError) as reply:
        box.reply(OWNER_EMAIL, "thanks", msg_id=sent["msg_id"])
    assert reply.value.code == "link_revoked"
    # A third person still sees nothing.
    with pytest.raises(MailboxError):
        box.list_inbox(CAROL, link_id=link_id)

    # Until it expires.
    clock.advance(15 * DAY)
    assert box.list_inbox(OWNER_EMAIL)["messages"] == []


def test_delete_messages_only_on_a_pairing_that_is_off(clock: FakeClock) -> None:
    box = _box(clock)
    link_id = _pair(box)
    box.send_message(EVE, link_id, "hello")
    with pytest.raises(MailboxError) as on:
        box.delete_messages(OWNER_EMAIL, link_id)
    assert on.value.code == "invalid_state"
    box.revoke(OWNER_EMAIL, link_id)
    assert box.delete_messages(OWNER_EMAIL, link_id)["purged_messages"] == 1
    assert box.list_inbox(OWNER_EMAIL)["messages"] == []


def test_summary_counts(clock: FakeClock) -> None:
    box = _box(clock)
    link_id = _pair(box)
    box.send_message(EVE, link_id, "one")
    created = box.request_link(CAROL)
    box.request_link(OWNER_EMAIL, created["invite_code"])
    assert box.needs_approval_count(OWNER_EMAIL) == 1
    assert box.needs_approval_count(CAROL) == 1
    assert box.summary(OWNER_EMAIL) == {"needs_approval": 1, "active": 1, "unread": 1}
    box.decide(OWNER_EMAIL, created["link_id"], "approve")
    assert box.needs_approval_count(OWNER_EMAIL) == 0
    assert box.needs_approval_count(CAROL) == 1


# ---- dashboard ---------------------------------------------------------------------


def _signed_in(app, code: str):
    c = client(app)
    assert login(c, code).status_code == 303
    return c


def test_cards_say_who_is_waiting_on_whom(p2_app) -> None:
    box = p2_app.state.mailbox
    owner = _signed_in(p2_app, "owner-code")
    eve = _signed_in(p2_app, "eve-code")

    created = box.request_link(OWNER_EMAIL)
    page = owner.get("/bridge").text
    assert f"Waiting for someone to join with code <code>{created['invite_code']}</code>" in page
    assert "Expires " in page
    assert "Cancel invite" in page
    assert "Turn off" not in page and "Delete stored messages" not in page

    box.request_link(EVE, created["invite_code"])
    assert "Needs your approval" in owner.get("/bridge").text
    approve = owner.post(
        f"/bridge/{created['link_id']}/approve", data={"csrf": csrf(owner, "/bridge")}
    )
    assert approve.status_code == 303
    owner_page = owner.get("/bridge").text
    assert f"Waiting for <b>{EVE}</b> to approve" in owner_page
    eve_page = eve.get("/bridge").text
    assert "Needs your approval" in eve_page
    assert f"<b>{OWNER_EMAIL}</b> already approved" in eve_page
    # The nav badge counts what waits on Eve.
    assert 'aria-label="1 waiting for your approval"' in eve_page
    assert "waiting for your approval" not in owner_page


def test_turning_off_says_sharing_stops_and_mail_stays(p2_app) -> None:
    box = p2_app.state.mailbox
    owner = _signed_in(p2_app, "owner-code")
    eve = _signed_in(p2_app, "eve-code")
    created = box.request_link(OWNER_EMAIL)
    box.request_link(EVE, created["invite_code"])
    box.decide(OWNER_EMAIL, created["link_id"], "approve")
    box.decide(EVE, created["link_id"], "approve")
    sent = box.send_message(EVE, created["link_id"], "unread reply")

    page = owner.get("/bridge").text
    assert "Sharing list" in page and "Turn this mailbox off?" in page
    off = eve.post(f"/bridge/{created['link_id']}/revoke", data={"csrf": csrf(eve, "/bridge")})
    assert off.status_code == 303
    flashed = eve.get("/bridge").text
    assert "Sharing list" in flashed
    assert "stay readable" in flashed
    assert box.list_inbox(OWNER_EMAIL)["messages"][0]["msg_id"] == sent["msg_id"]

    owner_page = owner.get("/bridge").text
    assert f"Turned off by {EVE} on " in owner_page
    assert "To pair again, ask your assistant for a new invite code" in owner_page
    assert "Remove from list" in owner_page

    purge = owner.post(
        f"/bridge/{created['link_id']}/purge", data={"csrf": csrf(owner, "/bridge")}
    )
    assert purge.status_code == 303
    assert "Deleted 1 stored message" in owner.get("/bridge").text
    assert box.list_inbox(OWNER_EMAIL)["messages"] == []

    dismiss = owner.post(
        f"/bridge/{created['link_id']}/dismiss", data={"csrf": csrf(owner, "/bridge")}
    )
    assert dismiss.status_code == 303
    assert box.list_links(OWNER_EMAIL)["links"] == []


def test_declined_card_and_cancel_from_the_dashboard(p2_app) -> None:
    box = p2_app.state.mailbox
    owner = _signed_in(p2_app, "owner-code")
    eve = _signed_in(p2_app, "eve-code")
    created = box.request_link(OWNER_EMAIL)
    box.request_link(EVE, created["invite_code"])
    eve.post(f"/bridge/{created['link_id']}/deny", data={"csrf": csrf(eve, "/bridge")})
    page = owner.get("/bridge").text
    assert f"Declined by {EVE} on " in page
    assert "Turned off" not in page
    assert "Declined by you" in eve.get("/bridge").text

    invite = box.request_link(OWNER_EMAIL)
    cancelled = owner.post(
        f"/bridge/{invite['link_id']}/cancel", data={"csrf": csrf(owner, "/bridge")}
    )
    assert cancelled.status_code == 303
    assert invite["invite_code"] not in owner.get("/bridge").text
    with pytest.raises(MailboxError):
        box.request_link(EVE, invite["invite_code"])


def test_overview_summarises_mailbox_and_shared_with_me(p2_app) -> None:
    box = p2_app.state.mailbox
    owner = _signed_in(p2_app, "owner-code")
    created = box.request_link(EVE)
    box.request_link(OWNER_EMAIL, created["invite_code"])
    page = owner.get("/").text
    assert 'id="mailbox-summary"' in page
    assert "1 needs your approval" in page
    assert 'id="shared-summary"' in page
    assert "Nothing shared with you yet" in page


# ---- consent page ------------------------------------------------------------------


def test_consent_names_the_account_mailbox_and_return_host(p2_app) -> None:
    c = _signed_in(p2_app, "owner-code")
    client_id = register(c, CURSOR, name="Cursor").json()["client_id"]
    _verifier, params = auth_params(client_id, CURSOR)
    page = c.get("/oauth/authorize", params=params)
    assert page.status_code == 200
    text = page.text
    assert f"Signed in as <b>{OWNER_EMAIL}</b>" in text
    assert "Use a different account" in text
    assert "Mailbox" in text and "paired" in text
    assert "Shared with me" in text
    assert "Access list" in text
    assert "files you have shared" not in text
    assert "go back to <b>anysphere.cursor-mcp</b>" in text

    # Switching account signs out and comes back to this same consent request.
    switched = c.post(
        "/logout",
        data={"csrf": csrf(c, "/"), "next": "/oauth/authorize?" + page.request.url.query.decode()},
    )
    assert switched.status_code == 303
    location = switched.headers["location"]
    assert location.startswith("/login?")
    assert parse_qs(urlparse(location).query)["next"][0].startswith("/oauth/authorize?")
    # A foreign next is ignored.
    c2 = _signed_in(p2_app, "owner-code")
    away = c2.post("/logout", data={"csrf": csrf(c2, "/"), "next": "//evil.example/"})
    assert away.headers["location"] == "/login?signed_out=1"


# ---- MCP errors --------------------------------------------------------------------


def test_mailbox_and_shared_errors_carry_structured_content(app) -> None:
    c = client(app)
    created = mcp_call(c, "request_link")["structuredContent"]
    blocked = mcp_call(c, "send_message", link_id=created["link_id"], body="early")
    assert blocked["isError"] is True
    assert blocked["structuredContent"]["error"] == "link_pending"
    text = blocked["content"][0]["text"]
    assert text.startswith("Error executing tool send_message: ")
    assert json.loads(text.split(": ", 1)[1])["error"] == "link_pending"

    shared = mcp_call(c, "read_shared_file", owner=EVE, file_id="nope")
    assert shared["isError"] is True
    assert shared["structuredContent"]["error"]
    assert shared["content"][0]["text"].startswith("Error executing tool read_shared_file: ")

    again = mcp_call(c, "request_link")["structuredContent"]
    assert again["reused"] is True and again["link_id"] == created["link_id"]


def test_mailbox_dates_are_local_time_elements() -> None:
    from scoped_drive_mcp.humanize import when

    html = str(when("2026-11-27T01:30:00+00:00", date_only=True))
    assert html.startswith('<time datetime="2026-11-27T01:30:00Z" data-time="date"')
    assert ">Nov 27, 2026</time>" in html

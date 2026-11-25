"""Pairing two of one person's own assistants (say Grok and Claude): the only pairing that
carries mail."""

import pytest

from scoped_drive_mcp.bridge import UNTRUSTED_START, Mailbox, MailboxError, as_assistant
from scoped_drive_mcp.store import MemoryStore
from tests.conftest import OWNER_EMAIL
from tests.dash import client, csrf, login, post
from tests.mail import READER, SENDER, THIRD, self_pair
from tests.test_external_sharing import _error
from tests.test_multi_user import _app, _grok, _mcp

GROK, CLAUDE, CURSOR = SENDER, READER, THIRD
PEOPLE = "/sharing?tab=people"


def _box() -> Mailbox:
    store = MemoryStore(clock=lambda: 1_700_000_000.0)
    return Mailbox(store, base_url="https://drive-test.example.com", clock=store._clock)


def test_two_assistants_on_one_account_can_pair_and_message() -> None:
    box = _box()
    with as_assistant(GROK):
        created = box.request_link(OWNER_EMAIL)
    with as_assistant(CLAUDE):
        joined = box.request_link(OWNER_EMAIL, created["invite_code"])
    assert joined["status"] == "pending_approval"
    assert joined["same_account"] is True
    assert joined["peer_label"] == "Grok"
    assert joined["approval_url"].endswith(PEOPLE)

    # One approval from the human turns it on.
    assert box.decide(OWNER_EMAIL, created["link_id"], "approve")["status"] == "active"

    with as_assistant(CLAUDE):
        sent = box.send_message(OWNER_EMAIL, created["link_id"], "what is on the roadmap?")
        assert box.check_messages(OWNER_EMAIL)["unread_count"] == 0
    with as_assistant(GROK):
        inbox = box.check_messages(OWNER_EMAIL)
        assert inbox["unread_count"] == 1
        assert inbox["latest_preview"][0]["from_assistant"] == "Claude"
        replied = box.reply(OWNER_EMAIL, "Q1: billing", msg_id=sent["msg_id"])
        assert replied["thread_id"] == sent["thread_id"]
        assert box.mark_read(OWNER_EMAIL, [sent["msg_id"]])["marked"] == 1
        assert box.check_messages(OWNER_EMAIL)["unread_count"] == 0
    with as_assistant(CLAUDE):
        messages = box.list_inbox(OWNER_EMAIL)["messages"]
        assert [m["from_assistant"] for m in messages] == ["Grok"]
        assert "Q1: billing" in messages[0]["body"]
        assert box.check_messages(OWNER_EMAIL)["unread_count"] == 1
        assert box.mark_read(OWNER_EMAIL, [replied["msg_id"]])["marked"] == 1
        assert box.check_messages(OWNER_EMAIL)["unread_count"] == 0
    # A third assistant of the same person is not on this link.
    with as_assistant(CURSOR):
        assert box.check_messages(OWNER_EMAIL)["unread_count"] == 0
        with pytest.raises(MailboxError) as exc:
            box.send_message(OWNER_EMAIL, created["link_id"], "hi")
        assert exc.value.code == "not_found"


def test_own_assistants_pair_and_message_through_the_mcp_tools(world, memstore, oauth) -> None:
    """The whole journey a person goes through: connect two assistants, pair them over
    MCP, approve once on the dashboard, exchange mail, then disconnect one of them."""
    app = _app(world, memstore, oauth)
    owner = client(app)
    assert login(owner).status_code == 303
    grok, claude = _grok(owner, "Grok Ada"), _grok(owner, "Claude Ada")

    created = _mcp(owner, grok, "request_link")["structuredContent"]
    joined = _mcp(owner, claude, "request_link", invite_code=created["invite_code"])
    assert joined["structuredContent"]["same_account"] is True
    link_id = created["link_id"]
    assert _error(_mcp(owner, grok, "send_message", link_id=link_id, body="x"))["error"] == (
        "link_pending"
    )

    page = owner.get(PEOPLE).text
    assert "Grok Ada ↔ Claude Ada" in page
    assert "pair two of your own assistants" in page
    assert page.count(f"/bridge/{link_id}/approve") == 1
    done = owner.post(f"/bridge/{link_id}/approve", data={"csrf": csrf(owner, PEOPLE)})
    assert done.status_code == 303

    sent = _mcp(owner, grok, "send_message", link_id=link_id, body="what is on the roadmap?")
    assert sent["isError"] is False, sent
    checked = _mcp(owner, claude, "check_messages")["structuredContent"]
    assert checked["unread_count"] == 1
    assert checked["latest_preview"][0]["from_assistant"] == "Grok Ada"
    [mail] = _mcp(owner, claude, "list_inbox")["structuredContent"]["messages"]
    assert mail["body"].startswith(UNTRUSTED_START) and "roadmap" in mail["body"]
    msg_id = sent["structuredContent"]["msg_id"]
    replied = _mcp(owner, claude, "reply", msg_id=msg_id, body="Q1: billing")
    assert replied["isError"] is False, replied
    assert _mcp(owner, grok, "check_messages")["structuredContent"]["unread_count"] == 1

    # Disconnecting Claude on Settings warns that, and does, end its pairing.
    grok_grant, claude_grant = app.state.mailbox.list_links(OWNER_EMAIL)["links"][0]["grant_ids"]
    settings = owner.get("/settings").text
    assert f"its pairing with Grok Ada …{grok_grant[-5:]} ends" in settings
    assert f"its pairing with Claude Ada …{claude_grant[-5:]} ends" in settings
    assert post(owner, "/oauth/grants/revoke", grant_id=claude_grant).status_code == 303
    after = _mcp(owner, grok, "send_message", link_id=link_id, body="still there?")
    assert _error(after)["error"] == "link_revoked"


def test_rejoining_your_own_invite_or_an_invite_without_an_assistant_does_not_pair() -> None:
    box = _box()
    with as_assistant(GROK):
        created = box.request_link(OWNER_EMAIL)
        again = box.request_link(OWNER_EMAIL, created["invite_code"])
    assert again["status"] == "awaiting_peer"
    assert "same_account" not in again
    # An API token (no grant) re-entering its account's code just gets the invite back.
    again = box.request_link(OWNER_EMAIL, created["invite_code"])
    assert again["status"] == "awaiting_peer"
    assert "same_account" not in again
    # An invite made without a grant (before this feature, or over a token) is not joinable
    # as a same-account pairing either.
    legacy = box.request_link(OWNER_EMAIL, new_invite=True)
    with as_assistant(CLAUDE):
        back = box.request_link(OWNER_EMAIL, legacy["invite_code"])
    assert back["status"] == "awaiting_peer"


def test_another_assistant_does_not_reuse_your_open_invite() -> None:
    box = _box()
    with as_assistant(GROK):
        grok_invite = box.request_link(OWNER_EMAIL)
    with as_assistant(CLAUDE):
        claude_invite = box.request_link(OWNER_EMAIL)
    assert claude_invite["link_id"] != grok_invite["link_id"]


def test_second_join_by_a_third_assistant_is_refused_and_pair_is_unique() -> None:
    box = _box()
    link_id = self_pair(box)
    code = box._link(link_id)["invite_code"]
    with as_assistant(CURSOR), pytest.raises(MailboxError) as taken:
        box.request_link(OWNER_EMAIL, code)
    assert taken.value.code == "invite_taken"
    with as_assistant(GROK):
        fresh = box.request_link(OWNER_EMAIL, new_invite=True)
    with as_assistant(CLAUDE), pytest.raises(MailboxError) as exc:
        box.request_link(OWNER_EMAIL, fresh["invite_code"])
    assert exc.value.code == "already_paired"


def test_same_account_link_shares_nothing_and_names_its_two_apps() -> None:
    box = _box()
    self_pair(box)
    with as_assistant(GROK):
        assert box.active_peers(OWNER_EMAIL) == []
    assert box.active_peers(OWNER_EMAIL) == []
    # The dashboard uses these to tell apart two connections with the same name.
    link = box.list_links(OWNER_EMAIL)["links"][0]
    assert link["grant_ids"] == [GROK.grant_id, CLAUDE.grant_id]
    assert link["assistants"] == ["Grok", "Claude"]


def test_a_join_that_stopped_halfway_can_be_retried() -> None:
    box = _box()
    with as_assistant(GROK):
        created = box.request_link(OWNER_EMAIL)
    link_id = created["link_id"]
    # Simulate a join that claimed the invite but failed before writing the link.
    box.store.set(f"bridge:selfclaim:{link_id}", CLAUDE.grant_id)
    box.store.set(f"bridge:peer:{link_id}", OWNER_EMAIL)
    with as_assistant(CLAUDE):
        joined = box.request_link(OWNER_EMAIL, created["invite_code"])
    assert joined["same_account"] is True
    assert box.decide(OWNER_EMAIL, link_id, "approve")["status"] == "active"


def test_revoking_an_assistant_ends_its_links_and_open_invites() -> None:
    box = _box()
    active = self_pair(box)
    pending = self_pair(box, GROK, CURSOR, approve=False)
    with as_assistant(THIRD):
        invite = box.request_link(OWNER_EMAIL, new_invite=True)
    with as_assistant(CLAUDE):
        open_invite = box.request_link(OWNER_EMAIL, new_invite=True)
    assert box.end_assistant_links(OWNER_EMAIL, CLAUDE.grant_id) == 2
    with as_assistant(GROK), pytest.raises(MailboxError) as exc:
        box.send_message(OWNER_EMAIL, active, "still there?")
    assert exc.value.code == "link_revoked"
    assert box.end_assistant_links(OWNER_EMAIL, CURSOR.grant_id) == 2
    links = {x["link_id"]: x for x in box.list_links(OWNER_EMAIL)["links"]}
    for ended in (pending, invite["link_id"], open_invite["link_id"]):
        assert links[ended]["ended_reason"] == "cancelled"


def test_an_unknown_grant_revoke_calls_no_mailbox_hook() -> None:
    from scoped_drive_mcp.mcp_oauth import McpOAuth

    seen: list[tuple[str, str]] = []
    oauth = McpOAuth(MemoryStore(), "https://drive-test.example.com", OWNER_EMAIL)
    oauth.on_revoke = lambda email, grant: seen.append((email, grant))
    assert oauth.revoke("not-a-grant") is False
    assert seen == []


def test_account_send_cap_counts_both_assistants_together() -> None:
    box = _box()
    link_id = self_pair(box)
    with as_assistant(GROK):
        box.send_message(OWNER_EMAIL, link_id, "one")
    with as_assistant(CLAUDE):
        box.send_message(OWNER_EMAIL, link_id, "two")
    bucket = int(box._now()) // 3600
    assert box.store.get(f"bridge:rate:{OWNER_EMAIL}:{bucket}") == "2"

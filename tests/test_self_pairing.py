"""Pairing two of one person's own assistants (say Grok and Claude), and its Edge Config switch."""

import pytest

from scoped_drive_mcp.auth import Principal
from scoped_drive_mcp.bridge import Assistant, Mailbox, MailboxError, as_assistant
from scoped_drive_mcp.config import Role
from scoped_drive_mcp.flags import EdgeConfigFlags, self_pairing_allowed
from scoped_drive_mcp.store import MemoryStore
from tests.conftest import OWNER_EMAIL
from tests.dash import client, csrf, login

GROK = Assistant("grant-grok", "Grok")
CLAUDE = Assistant("grant-claude", "Claude")
CURSOR = Assistant("grant-cursor", "Cursor")
EVE = "eve@example.com"


def _box(allowed: bool = True) -> Mailbox:
    store = MemoryStore(clock=lambda: 1_700_000_000.0)
    return Mailbox(
        store,
        base_url="https://drive-test.example.com",
        clock=store._clock,
        self_pairing=lambda _email: allowed,
    )


def _self_pair(box: Mailbox, approve: bool = True) -> str:
    with as_assistant(GROK):
        created = box.request_link(OWNER_EMAIL)
    with as_assistant(CLAUDE):
        joined = box.request_link(OWNER_EMAIL, created["invite_code"])
    assert joined["same_account"] is True
    if approve:
        box.decide(OWNER_EMAIL, created["link_id"], "approve")
    return created["link_id"]


def test_two_assistants_on_one_account_can_pair_and_message() -> None:
    box = _box()
    with as_assistant(GROK):
        created = box.request_link(OWNER_EMAIL)
    with as_assistant(CLAUDE):
        joined = box.request_link(OWNER_EMAIL, created["invite_code"])
    assert joined["status"] == "pending_approval"
    assert joined["peer_label"] == "Grok"
    assert joined["approval_url"].endswith("/bridge")

    # One approval from the human turns it on.
    assert box.decide(OWNER_EMAIL, created["link_id"], "approve")["status"] == "active"

    with as_assistant(CLAUDE):
        sent = box.send_message(OWNER_EMAIL, created["link_id"], "what is on the roadmap?")
        assert box.check_messages(OWNER_EMAIL)["unread_count"] == 0
    with as_assistant(GROK):
        inbox = box.check_messages(OWNER_EMAIL)
        assert inbox["unread_count"] == 1
        assert inbox["latest_preview"][0]["from_assistant"] == "Claude"
        box.reply(OWNER_EMAIL, "Q1: billing", msg_id=sent["msg_id"])
        box.mark_read(OWNER_EMAIL, [sent["msg_id"]])
        assert box.check_messages(OWNER_EMAIL)["unread_count"] == 0
    with as_assistant(CLAUDE):
        messages = box.list_inbox(OWNER_EMAIL)["messages"]
        assert [m["from_assistant"] for m in messages] == ["Grok"]
        assert "Q1: billing" in messages[0]["body"]
    # A third assistant of the same person is not on this link.
    with as_assistant(CURSOR):
        assert box.check_messages(OWNER_EMAIL)["unread_count"] == 0
        with pytest.raises(MailboxError) as exc:
            box.send_message(OWNER_EMAIL, created["link_id"], "hi")
        assert exc.value.code == "not_found"


def test_same_assistant_joining_own_invite_still_returns_link() -> None:
    box = _box()
    with as_assistant(GROK):
        created = box.request_link(OWNER_EMAIL)
        again = box.request_link(OWNER_EMAIL, created["invite_code"])
    assert again["status"] == "awaiting_peer"
    assert "same_account" not in again


def test_another_assistant_does_not_reuse_your_open_invite() -> None:
    box = _box()
    with as_assistant(GROK):
        grok_invite = box.request_link(OWNER_EMAIL)
    with as_assistant(CLAUDE):
        claude_invite = box.request_link(OWNER_EMAIL)
    assert claude_invite["link_id"] != grok_invite["link_id"]


def test_legacy_token_cannot_self_pair() -> None:
    box = _box()
    with as_assistant(GROK):
        created = box.request_link(OWNER_EMAIL)
    with pytest.raises(MailboxError) as exc:
        box.request_link(OWNER_EMAIL, created["invite_code"])
    assert exc.value.code == "assistant_required"


def test_second_join_by_a_third_assistant_is_refused_and_pair_is_unique() -> None:
    box = _box()
    link_id = _self_pair(box)
    with as_assistant(CURSOR):
        # The invite is used; this assistant just sees the card, it does not join.
        link = next(x for x in box.list_links(OWNER_EMAIL)["links"] if x["link_id"] == link_id)
        assert link["same_account"] is True
    with as_assistant(GROK):
        fresh = box.request_link(OWNER_EMAIL, new_invite=True)
    with as_assistant(CLAUDE), pytest.raises(MailboxError) as exc:
        box.request_link(OWNER_EMAIL, fresh["invite_code"])
    assert exc.value.code == "already_paired"


def test_same_account_link_shares_nothing() -> None:
    box = _box()
    _self_pair(box)
    with as_assistant(GROK):
        assert box.active_peers(OWNER_EMAIL) == []
    assert box.active_peers(OWNER_EMAIL) == []


def test_revoking_an_assistant_ends_its_same_account_links() -> None:
    box = _box()
    link_id = _self_pair(box)
    assert box.end_assistant_links(OWNER_EMAIL, CLAUDE.grant_id) == 1
    with as_assistant(GROK), pytest.raises(MailboxError) as exc:
        box.send_message(OWNER_EMAIL, link_id, "still there?")
    assert exc.value.code == "link_revoked"


def test_cross_person_links_ignore_assistant_identity() -> None:
    box = _box()
    with as_assistant(GROK):
        created = box.request_link(OWNER_EMAIL)
    with as_assistant(Assistant("grant-eve", "Muse")):
        box.request_link(EVE, created["invite_code"])
    box.decide(OWNER_EMAIL, created["link_id"], "approve")
    box.decide(EVE, created["link_id"], "approve")
    with as_assistant(CLAUDE):
        # Any of the owner's assistants can use a link with another person, as before.
        box.send_message(OWNER_EMAIL, created["link_id"], "hello eve")
    assert box.check_messages(EVE)["unread_count"] == 1
    assert box.active_peers(OWNER_EMAIL) == [EVE]


def test_self_pairing_off_for_domain_blocks_join_and_send() -> None:
    state = {"on": True}
    store = MemoryStore(clock=lambda: 1_700_000_000.0)
    box = Mailbox(store, clock=store._clock, self_pairing=lambda _e: state["on"])
    link_id = _self_pair(box)
    with as_assistant(GROK):
        box.send_message(OWNER_EMAIL, link_id, "before")
    state["on"] = False
    with as_assistant(CLAUDE):
        with pytest.raises(MailboxError) as exc:
            box.send_message(OWNER_EMAIL, link_id, "after")
        assert exc.value.code == "self_pairing_off"
        # Mail on the switched-off feature is not surfaced either.
        assert box.check_messages(OWNER_EMAIL)["unread_count"] == 0
    link = box.list_links(OWNER_EMAIL)["links"][0]
    assert link["disabled_by_org"] is True
    with as_assistant(GROK):
        fresh = box.request_link(OWNER_EMAIL, new_invite=True)
    with as_assistant(CURSOR), pytest.raises(MailboxError) as exc:
        box.request_link(OWNER_EMAIL, fresh["invite_code"])
    assert exc.value.code == "self_pairing_off"


def test_each_assistant_gets_its_own_webhook_slot_once_paired() -> None:
    box = _box()
    _self_pair(box)
    assert box._hook_owner(OWNER_EMAIL) == OWNER_EMAIL
    with as_assistant(GROK):
        assert box._hook_owner(OWNER_EMAIL) == f"{OWNER_EMAIL}#{GROK.grant_id}"
    with as_assistant(CURSOR):
        assert box._hook_owner(OWNER_EMAIL) == OWNER_EMAIL


# ---- Edge Config switch ------------------------------------------------------------


def test_self_pairing_rules() -> None:
    assert self_pairing_allowed(None, "a@acme.com") is True
    assert self_pairing_allowed({"enabled": True}, "a@acme.com") is True
    assert self_pairing_allowed({"enabled": False}, "a@acme.com") is False
    rule = {"enabled": True, "off_for_domains": ["ACME.com", "@other.org"]}
    assert self_pairing_allowed(rule, "a@acme.com") is False
    assert self_pairing_allowed(rule, "b@other.org") is False
    assert self_pairing_allowed(rule, "c@fine.io") is True
    assert self_pairing_allowed("garbage", "c@fine.io") is False


def test_self_pairing_flag_defaults_on_without_edge_config() -> None:
    def fetch(_key: str) -> None:
        raise AssertionError("no network call without EDGE_CONFIG")

    assert EdgeConfigFlags(None, fetch=fetch).self_pairing_enabled("a@acme.com") is True


def test_flag_fetch_error_uses_cache_then_fails_closed() -> None:
    now = {"t": 0.0}
    calls = {"n": 0, "fail": False}

    def fetch(_key: str) -> dict:
        calls["n"] += 1
        if calls["fail"]:
            raise OSError("down")
        return {"enabled": True, "off_for_domains": ["acme.com"]}

    url = "https://edge-config.vercel.com/ecfg_x?token=t"
    flags = EdgeConfigFlags(url, fetch, lambda: now["t"])
    assert flags.self_pairing_enabled("a@fine.io") is True
    assert flags.self_pairing_enabled("a@acme.com") is False
    assert calls["n"] == 1  # cached
    now["t"] = 100.0
    calls["fail"] = True
    assert flags.self_pairing_enabled("a@fine.io") is True  # last good value

    cold = EdgeConfigFlags("https://edge-config.vercel.com/ecfg_x?token=t", fetch, lambda: 0.0)
    assert cold.self_pairing_enabled("a@fine.io") is False


# ---- wiring ------------------------------------------------------------------------


def test_oauth_principal_carries_grant() -> None:
    principal = Principal("oauth:Grok", Role.ADMIN, OWNER_EMAIL, "g1", "Grok")
    assert principal.grant_id == "g1"
    assert principal.client_name == "Grok"


def test_dashboard_shows_assistant_names_and_one_approve(p2_app) -> None:
    box = p2_app.state.mailbox
    link_id = _self_pair(box, approve=False)
    owner = client(p2_app)
    login(owner)
    page = owner.get("/bridge")
    assert "Grok ↔ Claude" in page.text
    assert "pair two of your own assistants" in page.text
    assert page.text.count(f"/bridge/{link_id}/approve") == 1
    done = owner.post(f"/bridge/{link_id}/approve", data={"csrf": csrf(owner, "/bridge")})
    assert done.status_code == 303
    assert box.list_links(OWNER_EMAIL)["links"][0]["status"] == "active"

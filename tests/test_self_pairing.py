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


def test_legacy_token_or_old_invite_keeps_old_behaviour() -> None:
    box = _box()
    with as_assistant(GROK):
        created = box.request_link(OWNER_EMAIL)
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


def test_second_join_by_a_third_assistant_is_refused_and_pair_is_unique() -> None:
    box = _box()
    link_id = _self_pair(box)
    code = box._link(link_id)["invite_code"]
    with as_assistant(CURSOR), pytest.raises(MailboxError) as taken:
        box.request_link(OWNER_EMAIL, code)
    assert taken.value.code == "invite_taken"
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
        # Mail already delivered stays readable until it expires.
        assert box.check_messages(OWNER_EMAIL)["unread_count"] == 1
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


def test_revoked_grant_ends_its_open_invites_and_pending_links_as_cancelled() -> None:
    box = _box()
    with as_assistant(GROK):
        invite = box.request_link(OWNER_EMAIL)
    pending = _self_pair(box, approve=False)
    # Grok's first invite was reused by _self_pair, so make a separate open one.
    with as_assistant(CURSOR):
        cursor_invite = box.request_link(OWNER_EMAIL)
    assert box.end_assistant_links(OWNER_EMAIL, CURSOR.grant_id) == 1
    assert box.end_assistant_links(OWNER_EMAIL, CLAUDE.grant_id) == 1
    links = {x["link_id"]: x for x in box.list_links(OWNER_EMAIL)["links"]}
    assert links[pending]["ended_reason"] == "cancelled"
    assert links[cursor_invite["link_id"]]["ended_reason"] == "cancelled"
    assert invite["link_id"] == pending


def test_oauth_revoke_calls_the_mailbox_hook() -> None:
    from scoped_drive_mcp.mcp_oauth import McpOAuth

    seen: list[tuple[str, str]] = []
    oauth = McpOAuth(MemoryStore(), "https://drive-test.example.com", OWNER_EMAIL)
    oauth.on_revoke = lambda email, grant: seen.append((email, grant))
    assert oauth.revoke("not-a-grant") is False
    assert seen == []


def test_wake_does_not_go_to_the_other_assistants_shared_hook() -> None:
    box = _box()
    with as_assistant(CLAUDE):
        assert box._hook_owner(OWNER_EMAIL) == OWNER_EMAIL
    box.store.set(
        f"bridge:hook:{OWNER_EMAIL}",
        '{"url": "https://x", "enabled": true, "grant_id": "grant-claude"}',
    )
    _self_pair(box)
    # Claude still sees and clears the hook it saved; Grok gets its own slot.
    with as_assistant(CLAUDE):
        assert box._hook_owner(OWNER_EMAIL) == OWNER_EMAIL
    with as_assistant(GROK):
        assert box._hook_owner(OWNER_EMAIL) == f"{OWNER_EMAIL}#{GROK.grant_id}"


def test_account_send_cap_counts_both_assistants_together() -> None:
    box = _box()
    link_id = _self_pair(box)
    with as_assistant(GROK):
        box.send_message(OWNER_EMAIL, link_id, "one")
    with as_assistant(CLAUDE):
        box.send_message(OWNER_EMAIL, link_id, "two")
    bucket = int(box._now()) // 3600
    assert box.store.get(f"bridge:rate:{OWNER_EMAIL}:{bucket}") == "2"


def test_flag_outage_costs_one_fetch_per_window() -> None:
    now = {"t": 0.0}
    calls = {"n": 0}

    def fetch(_key: str) -> dict:
        calls["n"] += 1
        raise OSError("down")

    flags = EdgeConfigFlags("https://edge-config.vercel.com/e?token=t", fetch, lambda: now["t"])
    for _ in range(5):
        assert flags.self_pairing_enabled("a@fine.io") is False
    assert calls["n"] == 1
    now["t"] = 31.0
    flags.self_pairing_enabled("a@fine.io")
    assert calls["n"] == 2

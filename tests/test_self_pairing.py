"""Pairing two of one person's own assistants (say Grok and Claude), and its Edge Config switch."""

import pytest

from scoped_drive_mcp.auth import Principal
from scoped_drive_mcp.bridge import Assistant, Mailbox, MailboxError, as_assistant
from scoped_drive_mcp.config import Role
from scoped_drive_mcp.flags import EdgeConfigFlags, self_pairing_allowed
from scoped_drive_mcp.store import MemoryStore
from tests.conftest import OWNER_EMAIL
from tests.dash import client, csrf, login
from tests.mail import legacy_peer_mail

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
    assert joined["approval_url"].endswith("/sharing?tab=people")

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


def test_cross_person_links_share_documents_but_carry_no_mail() -> None:
    box = _box()
    with as_assistant(GROK):
        created = box.request_link(OWNER_EMAIL)
    with as_assistant(Assistant("grant-eve", "Muse")):
        joined = box.request_link(EVE, created["invite_code"])
    assert "same_account" not in joined
    box.decide(OWNER_EMAIL, created["link_id"], "approve")
    box.decide(EVE, created["link_id"], "approve")
    # Whichever of the owner's assistants tries, another person's assistant is not reached.
    for assistant in (GROK, CLAUDE, None):
        with as_assistant(assistant), pytest.raises(MailboxError) as exc:
            box.send_message(OWNER_EMAIL, created["link_id"], "hello eve")
        assert exc.value.code == "peer_mail_off"
    with as_assistant(Assistant("grant-eve", "Muse")), pytest.raises(MailboxError) as back:
        box.send_message(EVE, created["link_id"], "hello owner")
    assert back.value.code == "peer_mail_off"
    assert box.check_messages(EVE)["unread_count"] == 0
    assert box.active_peers(OWNER_EMAIL) == [EVE]
    assert box.active_peers(EVE) == [OWNER_EMAIL]


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
    page = owner.get("/sharing?tab=people")
    assert "Grok ↔ Claude" in page.text
    assert "pair two of your own assistants" in page.text
    assert page.text.count(f"/bridge/{link_id}/approve") == 1
    done = owner.post(
        f"/bridge/{link_id}/approve", data={"csrf": csrf(owner, "/sharing?tab=people")}
    )
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


def test_disabled_pending_pairing_can_still_be_ended(p2_app) -> None:
    box = p2_app.state.mailbox
    link_id = _self_pair(box, approve=False)
    box.self_pairing = lambda _email: False
    owner = client(p2_app)
    login(owner)
    page = owner.get("/sharing?tab=people")
    assert "Turned off by your organisation" in page.text
    assert f"/bridge/{link_id}/revoke" in page.text


# ---- wake-ups: one slot per app ------------------------------------------------------

HOOK = "https://api2.cursor.sh/automations/webhook/"


def _wake_box(posts: list[dict]) -> Mailbox:
    import base64

    from scoped_drive_mcp.wake import WakeSettings

    store = MemoryStore(clock=lambda: 1_700_000_000.0)
    return Mailbox(
        store,
        base_url="https://drive-test.example.com",
        clock=store._clock,
        wake=WakeSettings(
            enabled=True,
            kek=base64.b64decode(base64.b64encode(b"k" * 32)),
            allowlist=("api2.cursor.sh",),
            lookup=lambda _host: ["8.8.8.8"],
            poster=lambda request: posts.append(request) or 200,
        ),
    )


def _urls(posts: list[dict]) -> list[str]:
    return [f"https://{post['hostname']}{post['path']}" for post in posts]


def test_each_app_saves_its_own_hook_and_only_its_mail_wakes_it() -> None:
    posts: list[dict] = []
    box = _wake_box(posts)
    with as_assistant(CURSOR):
        box.set_webhook(OWNER_EMAIL, HOOK + "cursor", sender_key="cursor-key-1234")
    with as_assistant(CLAUDE):
        assert box.get_webhook(OWNER_EMAIL)["configured"] is False  # not Cursor's
        box.set_webhook(OWNER_EMAIL, HOOK + "claude", sender_key="claude-key-1234")
    with as_assistant(CURSOR):
        assert box.get_webhook(OWNER_EMAIL)["url"] == HOOK + "cursor"  # not replaced
    assert box.webhook_apps(OWNER_EMAIL) == sorted([CLAUDE.grant_id, CURSOR.grant_id])

    with as_assistant(CURSOR):
        created = box.request_link(OWNER_EMAIL)
    with as_assistant(CLAUDE):
        box.request_link(OWNER_EMAIL, created["invite_code"])
    box.decide(OWNER_EMAIL, created["link_id"], "approve")

    with as_assistant(CURSOR):
        box.send_message(OWNER_EMAIL, created["link_id"], "hi claude")
    assert _urls(posts) == [HOOK + "claude"]
    with as_assistant(CLAUDE):
        box.send_message(OWNER_EMAIL, created["link_id"], "hi cursor")
    assert _urls(posts) == [HOOK + "claude", HOOK + "cursor"]


def test_another_person_can_wake_none_of_your_assistants() -> None:
    posts: list[dict] = []
    box = _wake_box(posts)
    with as_assistant(CURSOR):
        box.set_webhook(OWNER_EMAIL, HOOK + "cursor", sender_key="cursor-key-1234")
    with as_assistant(CLAUDE):
        box.set_webhook(OWNER_EMAIL, HOOK + "claude", sender_key="claude-key-1234")
    box.set_webhook(OWNER_EMAIL, HOOK + "account", sender_key="account-key-123", app="")
    created = box.request_link(EVE)
    box.request_link(OWNER_EMAIL, created["invite_code"])
    box.decide(OWNER_EMAIL, created["link_id"], "approve")
    box.decide(EVE, created["link_id"], "approve")

    with pytest.raises(MailboxError) as exc:
        box.send_message(EVE, created["link_id"], "hello")
    assert exc.value.code == "peer_mail_off"
    assert posts == []
    # Even an old message addressed to the account wakes nothing.
    legacy_peer_mail(box, created["link_id"], EVE, OWNER_EMAIL, "from before")
    assert posts == []
    with as_assistant(CLAUDE):
        assert box.check_messages(OWNER_EMAIL)["unread_count"] == 0


def test_account_hook_never_wakes_for_one_apps_mail_and_can_be_moved() -> None:
    posts: list[dict] = []
    box = _wake_box(posts)
    # A hook saved before apps had their own slots sits on the account.
    box.set_webhook(OWNER_EMAIL, HOOK + "old", sender_key="old-key-12345")
    link_id = _self_pair(box)
    with as_assistant(GROK):
        box.send_message(OWNER_EMAIL, link_id, "to claude")
    assert posts == []  # it would have woken whoever saved it, maybe the sender

    box.move_webhook(OWNER_EMAIL, GROK.grant_id)
    assert box.get_webhook(OWNER_EMAIL, "")["configured"] is False
    with as_assistant(GROK):
        assert box.get_webhook(OWNER_EMAIL)["url"] == HOOK + "old"
    with as_assistant(CLAUDE):
        box.send_message(OWNER_EMAIL, link_id, "to grok")
    assert _urls(posts) == [HOOK + "old"]


def test_disconnecting_an_app_drops_its_hook() -> None:
    box = _wake_box([])
    with as_assistant(CLAUDE):
        box.set_webhook(OWNER_EMAIL, HOOK + "claude", sender_key="claude-key-1234")
    box.end_assistant_links(OWNER_EMAIL, CLAUDE.grant_id)
    assert box.webhook_apps(OWNER_EMAIL) == []
    with as_assistant(CLAUDE):
        assert box.get_webhook(OWNER_EMAIL)["configured"] is False


def test_move_refuses_to_overwrite_an_apps_hook() -> None:
    box = _wake_box([])
    box.set_webhook(OWNER_EMAIL, HOOK + "old", sender_key="old-key-12345")
    with as_assistant(CURSOR):
        box.set_webhook(OWNER_EMAIL, HOOK + "cursor", sender_key="cursor-key-1234")
    with pytest.raises(MailboxError) as exc:
        box.move_webhook(OWNER_EMAIL, CURSOR.grant_id)
    assert exc.value.code == "invalid_state"
    with as_assistant(CURSOR):
        assert box.get_webhook(OWNER_EMAIL)["url"] == HOOK + "cursor"
    assert box.get_webhook(OWNER_EMAIL, "")["url"] == HOOK + "old"


def test_only_an_apps_own_slot_is_a_wake_target() -> None:
    posts: list[dict] = []
    box = _wake_box(posts)
    _self_pair(box)
    with as_assistant(GROK):
        box.set_webhook(OWNER_EMAIL, HOOK + "grok", sender_key="grok-key-12345")
    box.set_webhook(OWNER_EMAIL, HOOK + "account", sender_key="account-key-123", app="")
    box.store.delete(f"bridge:hookapps:{OWNER_EMAIL}")  # saved before the index existed
    grok = f"{OWNER_EMAIL}#{GROK.grant_id}"
    assert [slot for slot, _ in box._wake_targets(grok)] == [grok]
    assert box._wake_targets(f"{OWNER_EMAIL}#{CLAUDE.grant_id}") == []
    # The account-wide address served mail from other people; it wakes nobody now.
    assert box._wake_targets(OWNER_EMAIL) == []


def test_same_account_link_names_its_two_apps() -> None:
    # The dashboard uses these to tell apart two connections with the same name.
    box = _box()
    _self_pair(box)
    link = box.list_links(OWNER_EMAIL)["links"][0]
    assert link["grant_ids"] == [GROK.grant_id, CLAUDE.grant_id]
    assert link["assistants"] == ["Grok", "Claude"]


def test_there_is_no_primary_app_any_more() -> None:
    box = _wake_box([])
    assert not hasattr(box, "set_primary")
    assert not hasattr(box, "get_primary")


def test_move_a_hook_from_one_app_to_another() -> None:
    posts: list[dict] = []
    box = _wake_box(posts)
    link_id = _self_pair(box)
    with as_assistant(CURSOR):  # an older connection that is not paired
        box.set_webhook(OWNER_EMAIL, HOOK + "cursor", sender_key="cursor-key-1234")
    box.move_webhook(OWNER_EMAIL, GROK.grant_id, from_app=CURSOR.grant_id)
    with as_assistant(CURSOR):
        assert box.get_webhook(OWNER_EMAIL)["configured"] is False
    assert CURSOR.grant_id not in box.webhook_apps(OWNER_EMAIL)
    with as_assistant(CLAUDE):
        box.send_message(OWNER_EMAIL, link_id, "wake grok")
    assert _urls(posts) == [HOOK + "cursor"]
    with pytest.raises(MailboxError):
        box.move_webhook(OWNER_EMAIL, GROK.grant_id, from_app=GROK.grant_id)

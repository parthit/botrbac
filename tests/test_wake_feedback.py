"""Wake-ups say what happened: the sender learns whether the other assistant was started,
the dashboard flags paired assistants that cannot be woken, and a test wake can be sent."""

from scoped_drive_mcp.bridge import as_assistant
from tests.conftest import OWNER_EMAIL
from tests.test_self_pairing import CLAUDE, GROK, HOOK, _self_pair, _wake_box


def test_send_says_no_wakeup_when_the_recipient_has_none() -> None:
    posts: list[dict] = []
    box = _wake_box(posts)
    link_id = _self_pair(box)
    with as_assistant(CLAUDE):
        sent = box.send_message(OWNER_EMAIL, link_id, "hi grok")
    assert sent["wake"]["status"] == "no_wakeup"
    assert "Grok has no wake-up saved" in sent["wake"]["hint"]
    assert "Settings" in sent["wake"]["hint"]
    assert posts == []


def test_send_says_sent_when_the_recipient_was_woken() -> None:
    posts: list[dict] = []
    box = _wake_box(posts)
    link_id = _self_pair(box)
    with as_assistant(GROK):
        box.set_webhook(OWNER_EMAIL, HOOK + "grok", sender_key="grok-key-1234")
    with as_assistant(CLAUDE):
        sent = box.send_message(OWNER_EMAIL, link_id, "hi grok")
    assert sent["wake"] == {
        "status": "sent",
        "hint": "Grok was woken. The message is in its inbox.",
    }
    last = box.get_webhook(OWNER_EMAIL, GROK.grant_id)["last_wake"]
    assert last["ok"] is True and last["http"] == 200


def test_send_says_failed_and_records_the_http_status() -> None:
    import base64

    from scoped_drive_mcp.bridge import Mailbox
    from scoped_drive_mcp.store import MemoryStore
    from scoped_drive_mcp.wake import WakeSettings

    store = MemoryStore(clock=lambda: 1_700_000_000.0)
    box = Mailbox(
        store,
        base_url="https://drive-test.example.com",
        clock=store._clock,
        wake=WakeSettings(
            enabled=True,
            kek=base64.b64decode(base64.b64encode(b"k" * 32)),
            allowlist=("api2.cursor.sh",),
            lookup=lambda _host: ["8.8.8.8"],
            poster=lambda _request: 401,
        ),
    )
    link_id = _self_pair(box)
    with as_assistant(GROK):
        box.set_webhook(OWNER_EMAIL, HOOK + "grok", sender_key="grok-key-1234")
    with as_assistant(CLAUDE):
        sent = box.send_message(OWNER_EMAIL, link_id, "hi grok")
    assert sent["wake"]["status"] == "failed"
    last = box.get_webhook(OWNER_EMAIL, GROK.grant_id)["last_wake"]
    assert last["ok"] is False and last["http"] == 401


def test_paused_wakeup_is_reported_as_paused() -> None:
    posts: list[dict] = []
    box = _wake_box(posts)
    link_id = _self_pair(box)
    with as_assistant(GROK):
        box.set_webhook(OWNER_EMAIL, HOOK + "grok", sender_key="grok-key-1234", enabled=False)
    with as_assistant(CLAUDE):
        sent = box.send_message(OWNER_EMAIL, link_id, "hi grok")
    assert sent["wake"]["status"] == "paused" and posts == []
    missing = box.missing_wakeups(OWNER_EMAIL)
    assert {m["assistant"] for m in missing} == {"Grok", "Claude"}
    assert next(m for m in missing if m["assistant"] == "Grok")["paused"] is True


def test_the_account_hook_never_wakes_an_own_assistant_and_that_is_flagged() -> None:
    """What went wrong on Nov 20: the only hook sat in the account slot."""
    posts: list[dict] = []
    box = _wake_box(posts)
    link_id = _self_pair(box)
    box.set_webhook(OWNER_EMAIL, HOOK + "account", sender_key="acct-key-1234", app="")
    assert {m["assistant"] for m in box.missing_wakeups(OWNER_EMAIL)} == {"Grok", "Claude"}
    with as_assistant(CLAUDE):
        sent = box.send_message(OWNER_EMAIL, link_id, "hi grok")
    assert sent["wake"]["status"] == "no_wakeup" and posts == []
    # Giving it to Grok fixes it.
    box.move_webhook(OWNER_EMAIL, GROK.grant_id, from_app="")
    assert [m["assistant"] for m in box.missing_wakeups(OWNER_EMAIL)] == ["Claude"]
    with as_assistant(CLAUDE):
        sent = box.send_message(OWNER_EMAIL, link_id, "again")
    assert sent["wake"]["status"] == "sent" and len(posts) == 1


def test_test_wake_pings_the_hook_and_records_the_result() -> None:
    posts: list[dict] = []
    box = _wake_box(posts)
    with as_assistant(GROK):
        box.set_webhook(OWNER_EMAIL, HOOK + "grok", sender_key="grok-key-1234")
    result = box.test_webhook(OWNER_EMAIL, GROK.grant_id)
    assert result == {"ok": True, "http": 200}
    assert len(posts) == 1 and '"link_id":"test"' in posts[0]["body"]
    assert box.get_webhook(OWNER_EMAIL, GROK.grant_id)["last_wake"]["ok"] is True
    # Removing the hook drops its history too.
    box.clear_webhook(OWNER_EMAIL, GROK.grant_id)
    assert box.get_webhook(OWNER_EMAIL, GROK.grant_id)["last_wake"] is None


def test_replayed_send_does_not_ping_twice() -> None:
    posts: list[dict] = []
    box = _wake_box(posts)
    link_id = _self_pair(box)
    with as_assistant(GROK):
        box.set_webhook(OWNER_EMAIL, HOOK + "grok", sender_key="grok-key-1234")
    with as_assistant(CLAUDE):
        first = box.send_message(OWNER_EMAIL, link_id, "hi", idempotency_key="k1")
        again = box.send_message(OWNER_EMAIL, link_id, "hi", idempotency_key="k1")
    assert first["wake"]["status"] == "sent"
    assert again["idempotent_replay"] is True and len(posts) == 1


def test_settings_page_puts_each_wakeup_on_its_assistant(world, memstore, oauth) -> None:
    import base64
    import re

    from scoped_drive_mcp.wake import WakeSettings
    from tests.dash import client, csrf, login, post
    from tests.test_multi_user import _app, _grok

    posts: list[dict] = []
    app = _app(world, memstore, oauth)
    app.state.mailbox.wake = WakeSettings(
        enabled=True,
        kek=base64.b64decode(base64.b64encode(b"k" * 32)),
        allowlist=("api2.cursor.sh",),
        lookup=lambda _host: ["8.8.8.8"],
        poster=lambda request: posts.append(request) or 200,
    )
    owner = client(app)
    assert login(owner).status_code == 303
    _grok(owner, "Grok Ada")
    page = owner.get("/settings").text
    assert "Add a wake-up for Grok Ada" in page
    grant = re.search(r'id="app-([^"]+)"', page).group(1)

    # A wake-up pasted without saying which assistant it starts is refused, not filed
    # under the account slot that never fires for mail between your own assistants.
    token = csrf(owner, "/settings")
    r = owner.post(
        "/bridge/webhook",
        data={"csrf": token, "action": "save", "url": HOOK + "x", "sender_key": "k-1234"},
    )
    assert r.status_code == 303
    assert "Choose which assistant this wake-up starts" in owner.get("/settings").text
    assert app.state.mailbox.get_webhook(OWNER_EMAIL, "")["configured"] is False

    saved = post(
        owner,
        "/bridge/webhook",
        action="save",
        app=grant,
        url=HOOK + "grok",
        sender_key="grok-key-1234",
    )
    assert saved.headers["location"].startswith("/settings")
    page = owner.get("/settings").text
    assert "Key ends in <code>1234</code>" in page and "No wake sent yet" in page

    post(owner, "/bridge/webhook", action="test", app=grant)
    page = owner.get("/settings").text
    assert "Test wake sent (HTTP 200)" in page and "delivered" in page
    assert len(posts) == 1

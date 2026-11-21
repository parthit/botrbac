"""Wake-up pings for the mailbox that runs inside the Drive app."""

import base64
import json

import pytest

from scoped_drive_mcp.bridge import Mailbox, MailboxError, as_assistant
from scoped_drive_mcp.store import MemoryStore
from scoped_drive_mcp.wake import WakeSettings, _public
from tests.conftest import OWNER_EMAIL
from tests.mail import READER, SENDER, cross_pair, legacy_peer_mail, self_pair

EVE = "eve@example.com"
KEK = base64.b64encode(b"k" * 32).decode()
URL = "https://api2.cursor.sh/automations/webhook/abc"
SECRET = "sk_live_test_key_99"


def _box(posts: list[dict[str, str]], status: int = 200) -> Mailbox:
    store = MemoryStore(clock=lambda: 1_700_000_000.0)

    def poster(request: dict[str, str]) -> int:
        posts.append(request)
        return status

    return Mailbox(
        store,
        base_url="https://drive-test.example.com",
        clock=store._clock,
        wake=WakeSettings(
            enabled=True,
            kek=base64.b64decode(KEK),
            allowlist=("api2.cursor.sh",),
            lookup=lambda host: ["8.8.8.8"] if host == "api2.cursor.sh" else ["127.0.0.1"],
            poster=poster,
        ),
    )


# Mail goes from SENDER to READER, two assistants of OWNER_EMAIL. READER's wake-up lives
# in its own app slot, which is the only one mail to it wakes.
APP = READER.grant_id


def _pair(box: Mailbox) -> str:
    return self_pair(box)


def _check_reader(box: Mailbox) -> dict:
    with as_assistant(READER):
        return box.check_messages(OWNER_EMAIL)


def _send(box: Mailbox, link_id: str, body: str, **kw):
    with as_assistant(SENDER):
        return box.send_message(OWNER_EMAIL, link_id, body, **kw)


def test_ping_has_ids_and_not_the_message() -> None:
    posts: list[dict[str, str]] = []
    box = _box(posts)
    link_id = _pair(box)
    saved = box.set_webhook(OWNER_EMAIL, URL, sender_key=SECRET, app=APP)
    assert saved["secret_hint"] == SECRET[-4:]
    assert "ciphertext" not in saved
    sent = _send(box, link_id, "Dinner is at 7.")
    assert posts[0]["body"].find("Dinner is at 7.") == -1
    body = json.loads(posts[0]["body"])
    assert body["msg_id"] == sent["msg_id"]
    assert body["link_id"] == link_id
    assert posts[0]["authorization"] == f"Bearer {SECRET}"
    assert "x-automation-key" not in posts[0]
    replay = _send(box, link_id, "Dinner is at 7.", idempotency_key="same")
    _send(box, link_id, "Dinner is at 7.", idempotency_key="same")
    assert replay["idempotent_replay"] is False
    assert len(posts) == 2


def test_idempotent_replay_does_not_ping_twice() -> None:
    posts: list[dict[str, str]] = []
    box = _box(posts)
    link_id = _pair(box)
    box.set_webhook(OWNER_EMAIL, URL, sender_key=SECRET, app=APP)
    _send(box, link_id, "once", idempotency_key="k1")
    _send(box, link_id, "once", idempotency_key="k1")
    assert len(posts) == 1


def test_private_address_and_other_hosts_are_rejected() -> None:
    posts: list[dict[str, str]] = []
    box = _box(posts)
    with pytest.raises(MailboxError) as other:
        box.set_webhook(EVE, "https://example.com/hook", sender_key=SECRET)
    assert other.value.code == "webhook_host_not_allowed"
    box.wake = WakeSettings(
        enabled=True,
        kek=base64.b64decode(KEK),
        allowlist=("api2.cursor.sh", "evil.example"),
        lookup=lambda host: ["10.1.2.3"] if host == "evil.example" else ["8.8.8.8"],
        poster=lambda request: posts.append(request) or 200,
    )
    with pytest.raises(MailboxError) as private:
        box.set_webhook(EVE, "https://evil.example/hook", sender_key=SECRET)
    assert private.value.code == "invalid_webhook_url"
    assert posts == []


def test_a_failed_ping_does_not_restore_an_old_webhook() -> None:
    posts: list[dict[str, str]] = []
    box = _box(posts)

    def rotate_then_fail(request: dict[str, str]) -> int:
        posts.append(request)
        box.set_webhook(OWNER_EMAIL, URL, sender_key="rotated-key-1234", app=APP)
        raise ValueError("http_500")

    box.wake = WakeSettings(
        enabled=True,
        kek=base64.b64decode(KEK),
        allowlist=("api2.cursor.sh",),
        lookup=lambda _host: ["8.8.8.8"],
        poster=rotate_then_fail,
    )
    link_id = _pair(box)
    box.set_webhook(OWNER_EMAIL, URL, sender_key=SECRET, app=APP)
    _send(box, link_id, "during rotate")
    saved = box.get_webhook(OWNER_EMAIL, APP)
    assert saved["secret_hint"] == "1234"
    assert saved["last_error"] is None


def test_a_successful_ping_clears_the_previous_error() -> None:
    calls = {"n": 0}

    def flaky(request: dict[str, str]) -> int:
        calls["n"] += 1
        if calls["n"] == 1:
            raise ValueError("http_500")
        return 200

    store = MemoryStore(clock=lambda: 1_700_000_000.0)
    box = Mailbox(
        store,
        base_url="https://drive-test.example.com",
        clock=store._clock,
        wake=WakeSettings(
            enabled=True,
            kek=base64.b64decode(KEK),
            allowlist=("api2.cursor.sh",),
            lookup=lambda _host: ["8.8.8.8"],
            poster=flaky,
        ),
    )
    link_id = _pair(box)
    box.set_webhook(OWNER_EMAIL, URL, sender_key=SECRET, app=APP)
    _send(box, link_id, "first")
    assert box.get_webhook(OWNER_EMAIL, APP)["last_error"] == "http_status"
    _send(box, link_id, "second")
    assert box.get_webhook(OWNER_EMAIL, APP)["last_error"] is None


def test_disabled_webhook_does_not_call_out() -> None:
    store = MemoryStore(clock=lambda: 1_700_000_000.0)
    box = Mailbox(store, base_url="https://drive-test.example.com", clock=store._clock)
    link_id = _pair(box)
    assert box.get_webhook(OWNER_EMAIL, APP)["available"] is False
    with pytest.raises(MailboxError) as disabled:
        box.set_webhook(OWNER_EMAIL, URL, sender_key=SECRET, app=APP)
    assert disabled.value.code == "webhook_disabled"
    _send(box, link_id, "still stored")
    assert _check_reader(box)["unread_count"] == 1


def test_public_address_helper_rejects_mapped_loopback() -> None:
    assert _public("8.8.8.8") is True
    assert _public("127.0.0.1") is False
    assert _public("10.1.2.3") is False
    assert _public("169.254.169.254") is False
    assert _public("::ffff:127.0.0.1") is False


CLAUDE_URL = "https://api.anthropic.com/v1/claude_code/routines/trig_01ABCdef/fire"
CLAUDE_KEY = "sk-ant-oat01-test-routine-token-7788"


def _claude_box(posts: list[dict[str, str]]) -> Mailbox:
    store = MemoryStore(clock=lambda: 1_700_000_000.0)
    return Mailbox(
        store,
        base_url="https://drive-test.example.com",
        clock=store._clock,
        wake=WakeSettings(
            enabled=True,
            kek=base64.b64decode(KEK),
            allowlist=("api2.cursor.sh", "api.anthropic.com"),
            lookup=lambda _host: ["8.8.8.8"],
            poster=lambda request: posts.append(request) or 200,
        ),
    )


def test_claude_routine_ping_has_anthropic_headers_and_ids_in_text() -> None:
    posts: list[dict[str, str]] = []
    box = _claude_box(posts)
    link_id = _pair(box)
    saved = box.set_webhook(
        OWNER_EMAIL, CLAUDE_URL, sender_key=CLAUDE_KEY, auth_scheme="claude_routine", app=APP
    )
    assert saved["auth_scheme"] == "claude_routine"
    sent = _send(box, link_id, "Dinner is at 7.")
    request = posts[0]
    assert request["hostname"] == "api.anthropic.com"
    assert request["path"] == "/v1/claude_code/routines/trig_01ABCdef/fire"
    assert request["authorization"] == f"Bearer {CLAUDE_KEY}"
    assert request["anthropic-version"] == "2023-06-01"
    assert request["anthropic-beta"] == "experimental-cc-routine-2026-04-01"
    assert "x-automation-key" not in request
    assert "Dinner is at 7." not in request["body"]
    body = json.loads(request["body"])
    assert set(body) == {"text"}
    event = json.loads(body["text"])
    assert event["type"] == "bot_bridge.message_available"
    assert event["msg_id"] == sent["msg_id"]
    assert event["link_id"] == link_id


def test_claude_routine_scheme_only_targets_a_routine_fire_url() -> None:
    posts: list[dict[str, str]] = []
    box = _claude_box(posts)
    for url in (
        URL,  # Grok host with the Claude scheme
        "https://api.anthropic.com/v1/messages",
        "https://api.anthropic.com/v1/claude_code/routines/trig_1/fire/extra",
    ):
        with pytest.raises(MailboxError) as bad:
            box.set_webhook(EVE, url, sender_key=CLAUDE_KEY, auth_scheme="claude_routine")
        assert bad.value.code == "invalid_webhook_url"
    for scheme in ("bearer", "bearer_and_x_automation_key"):
        with pytest.raises(MailboxError) as wrong:
            box.set_webhook(EVE, CLAUDE_URL, sender_key=CLAUDE_KEY, auth_scheme=scheme)
        assert wrong.value.code == "invalid_webhook_url"
    assert posts == []


def test_saved_key_is_not_carried_to_a_different_host() -> None:
    posts: list[dict[str, str]] = []
    box = _claude_box(posts)
    box.set_webhook(EVE, URL, sender_key=SECRET)
    with pytest.raises(MailboxError) as missing:
        box.set_webhook(EVE, CLAUDE_URL, auth_scheme="claude_routine")
    assert missing.value.code == "secret_required"
    assert box.get_webhook(EVE)["url"] == URL
    box.set_webhook(EVE, CLAUDE_URL, sender_key=CLAUDE_KEY, auth_scheme="claude_routine")
    # Same routine: the saved key is kept (e.g. turning wake-ups off and on).
    kept = box.set_webhook(EVE, CLAUDE_URL, auth_scheme="claude_routine")
    assert kept["secret_hint"] == CLAUDE_KEY[-4:]


def test_saved_key_is_not_carried_to_a_different_claude_routine() -> None:
    posts: list[dict[str, str]] = []
    box = _claude_box(posts)
    box.set_webhook(EVE, CLAUDE_URL, sender_key=CLAUDE_KEY, auth_scheme="claude_routine")
    other_routine = "https://api.anthropic.com/v1/claude_code/routines/trig_02/fire"
    # A routine's token only starts that one routine, so a new routine needs its own.
    with pytest.raises(MailboxError) as missing:
        box.set_webhook(EVE, other_routine, auth_scheme="claude_routine")
    assert missing.value.code == "secret_required"
    assert box.get_webhook(EVE)["url"] == CLAUDE_URL
    moved = box.set_webhook(
        EVE, other_routine, sender_key="sk-new-routine-key-9876", auth_scheme="claude_routine"
    )
    assert moved["secret_hint"] == "9876"


def test_anthropic_is_on_the_default_allowlist() -> None:
    assert "api.anthropic.com" in WakeSettings().allowlist
    assert "api2.cursor.sh" in WakeSettings().allowlist


@pytest.mark.parametrize(("status", "error"), [(204, None), (202, None), (302, "http_status")])
def test_any_2xx_counts_as_delivered(status: int, error: str | None) -> None:
    posts: list[dict[str, str]] = []
    box = _box(posts, status=status)
    link_id = _pair(box)
    box.set_webhook(OWNER_EMAIL, URL, sender_key=SECRET, app=APP)
    _send(box, link_id, "hello")
    assert len(posts) == 1
    assert box.get_webhook(OWNER_EMAIL, APP).get("last_error") == error


def test_no_wake_fires_for_a_pairing_between_two_people() -> None:
    posts: list[dict[str, str]] = []
    box = _box(posts)
    link_id = cross_pair(box, OWNER_EMAIL, EVE)
    # Every slot that could be woken: the account-wide one and an app's own.
    box.set_webhook(OWNER_EMAIL, URL, sender_key=SECRET, app="")
    box.set_webhook(OWNER_EMAIL, URL, sender_key=SECRET, app=APP)
    box.set_webhook(EVE, URL, sender_key=SECRET)
    with pytest.raises(MailboxError) as off:
        box.send_message(EVE, link_id, "wake up")
    assert off.value.code == "peer_mail_off"
    assert posts == []
    # Mail addressed to the whole account (the only way another person's mail was
    # addressed) has no hook to wake, even if an old message is in the store.
    assert box._wake_targets(OWNER_EMAIL) == []
    legacy_peer_mail(box, link_id, EVE, OWNER_EMAIL, "old")
    assert posts == []

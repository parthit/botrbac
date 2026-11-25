"""Wake-up pings for the mailbox: one hook per app, what a ping carries, where it may go,
and what the sender and the dashboard are told about it."""

import base64
import http.server
import json
import re
import socket
import ssl
import threading

import pytest

from scoped_drive_mcp import wake as wake_module
from scoped_drive_mcp.bridge import Mailbox, MailboxError, as_assistant
from scoped_drive_mcp.server import INSTRUCTIONS, WATCH_MAIL
from scoped_drive_mcp.store import MemoryStore
from scoped_drive_mcp.wake import WakeSettings, _public, seal
from tests.conftest import EVE, OWNER_EMAIL
from tests.dash import client, csrf, login, mcp_call, post
from tests.mail import READER, SENDER, THIRD, cross_pair, legacy_peer_mail, self_pair
from tests.test_multi_user import _app, _grok

GROK, CLAUDE, CURSOR = SENDER, READER, THIRD
KEK = b"k" * 32
URL = "https://api2.cursor.sh/automations/webhook/abc"
HOOK = "https://api2.cursor.sh/automations/webhook/"
SECRET = "sk_live_test_key_99"
CLAUDE_URL = "https://api.anthropic.com/v1/claude_code/routines/trig_01ABCdef/fire"
CLAUDE_KEY = "sk-ant-oat01-test-routine-token-7788"
# Mail goes from GROK to CLAUDE unless a test says otherwise. CLAUDE's wake-up lives in
# its own app slot, which is the only one mail to it wakes.
APP = CLAUDE.grant_id


def _settings(posts: list[dict], status: int = 200, poster=None, **kw) -> WakeSettings:
    def record(request: dict[str, str]) -> int:
        posts.append(request)
        return status

    return WakeSettings(
        kek=KEK,
        allowlist=kw.pop("allowlist", ("api2.cursor.sh", "api.anthropic.com")),
        lookup=kw.pop("lookup", lambda _host: ["8.8.8.8"]),
        poster=poster or record,
    )


def _wake_box(posts: list[dict], status: int = 200, poster=None, **kw) -> Mailbox:
    store = MemoryStore(clock=lambda: 1_700_000_000.0)
    return Mailbox(
        store,
        base_url="https://drive-test.example.com",
        clock=store._clock,
        wake=_settings(posts, status, poster, **kw),
    )


def _send(box: Mailbox, link_id: str, body: str, who=GROK, **kw):
    with as_assistant(who):
        return box.send_message(OWNER_EMAIL, link_id, body, **kw)


def _urls(posts: list[dict]) -> list[str]:
    return [f"https://{post['hostname']}{post['path']}" for post in posts]


def _hook(box: Mailbox, who, name: str, **kw) -> None:
    with as_assistant(who):
        box.set_webhook(OWNER_EMAIL, HOOK + name, **kw)


# ---- what a ping carries --------------------------------------------------------------


def test_ping_has_ids_and_not_the_message() -> None:
    posts: list[dict] = []
    box = _wake_box(posts)
    link_id = self_pair(box)
    saved = box.set_webhook(OWNER_EMAIL, URL, sender_key=SECRET, app=APP)
    assert saved["secret_hint"] == SECRET[-4:]
    assert "ciphertext" not in saved
    sent = _send(box, link_id, "Dinner is at 7.")
    assert "Dinner is at 7." not in posts[0]["body"]
    body = json.loads(posts[0]["body"])
    assert body["msg_id"] == sent["msg_id"]
    assert body["link_id"] == link_id
    assert posts[0]["authorization"] == f"Bearer {SECRET}"
    assert "x-automation-key" not in posts[0]


def test_claude_routine_ping_has_anthropic_headers_and_ids_in_text() -> None:
    posts: list[dict] = []
    box = _wake_box(posts)
    link_id = self_pair(box)
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


def test_the_real_post_goes_to_the_checked_address_with_the_hosts_name(monkeypatch) -> None:
    """DNS is looked up once, when the URL is checked. The connection goes to that
    address, so a second lookup cannot point the ping (and its key) somewhere private,
    while TLS still checks the certificate for the hook's own host name."""
    seen: list[tuple[str, str, dict]] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - http.server's name
            length = int(self.headers["content-length"])
            headers = {k.lower(): v for k, v in self.headers.items()}
            seen.append((self.path, self.rfile.read(length).decode(), headers))
            self.send_response(202)
            self.send_header("content-length", "0")
            self.end_headers()

        def log_message(self, *_args) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    dialed: list[tuple] = []
    wrapped: list[str] = []
    real_connect = socket.create_connection

    def connect(address, timeout=None, *args):
        dialed.append(address)
        return real_connect(("127.0.0.1", server.server_port), timeout)

    class PlainContext:
        """Stands in for TLS so the request can be read; records the SNI name."""

        post_handshake_auth = None

        def set_alpn_protocols(self, _protocols) -> None:
            pass

        def wrap_socket(self, sock, server_hostname=None):
            wrapped.append(server_hostname)
            return sock

    monkeypatch.setattr(socket, "create_connection", connect)
    monkeypatch.setattr(ssl, "_create_default_https_context", PlainContext)
    try:
        status = wake_module._post(
            {
                "hostname": "api2.cursor.sh",
                "path": "/automations/webhook/abc",
                "address": "93.184.216.34",
                "body": '{"msg_id":"m1"}',
                "authorization": "Bearer key",
            }
        )
    finally:
        server.shutdown()
        server.server_close()
    assert status == 202
    assert dialed == [("93.184.216.34", 443)]
    assert wrapped == ["api2.cursor.sh"]
    [(path, body, headers)] = seen
    assert path == "/automations/webhook/abc" and body == '{"msg_id":"m1"}'
    assert headers["authorization"] == "Bearer key"
    assert headers["host"] == "api2.cursor.sh"
    # The routing fields are never sent as headers.
    assert not {"hostname", "address", "path", "body"} & set(headers)

    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *_a, **_k: [(0, 0, 0, "", ("93.184.216.34", 443))]
    )
    assert wake_module._lookup("api2.cursor.sh") == ["93.184.216.34"]


# ---- where a ping may go --------------------------------------------------------------


def test_private_address_and_other_hosts_are_rejected() -> None:
    posts: list[dict] = []
    box = _wake_box(posts)
    with pytest.raises(MailboxError) as other:
        box.set_webhook(EVE, "https://example.com/hook", sender_key=SECRET)
    assert other.value.code == "webhook_host_not_allowed"
    box.wake = _settings(
        posts,
        allowlist=("api2.cursor.sh", "evil.example"),
        lookup=lambda host: ["10.1.2.3"] if host == "evil.example" else ["8.8.8.8"],
    )
    with pytest.raises(MailboxError) as private:
        box.set_webhook(EVE, "https://evil.example/hook", sender_key=SECRET)
    assert private.value.code == "invalid_webhook_url"
    assert posts == []


def test_public_address_helper_rejects_mapped_loopback() -> None:
    assert _public("8.8.8.8") is True
    assert _public("127.0.0.1") is False
    assert _public("10.1.2.3") is False
    assert _public("169.254.169.254") is False
    assert _public("::ffff:127.0.0.1") is False


def test_claude_routine_scheme_only_targets_a_routine_fire_url() -> None:
    posts: list[dict] = []
    box = _wake_box(posts)
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


def test_anthropic_is_on_the_default_allowlist() -> None:
    assert "api.anthropic.com" in WakeSettings().allowlist
    assert "api2.cursor.sh" in WakeSettings().allowlist


def test_saved_key_is_not_carried_to_a_different_host() -> None:
    box = _wake_box([])
    box.set_webhook(EVE, URL, sender_key=SECRET)
    with pytest.raises(MailboxError) as missing:
        box.set_webhook(EVE, CLAUDE_URL, auth_scheme="claude_routine")
    assert missing.value.code == "secret_required"
    assert box.get_webhook(EVE)["url"] == URL
    box.set_webhook(EVE, CLAUDE_URL, sender_key=CLAUDE_KEY, auth_scheme="claude_routine")
    # Same routine: the saved key is kept (e.g. turning wake-ups off and on).
    kept = box.set_webhook(EVE, CLAUDE_URL, auth_scheme="claude_routine")
    assert kept["secret_hint"] == CLAUDE_KEY[-4:]

    # A routine's token only starts that one routine, so a new routine needs its own.
    other_routine = "https://api.anthropic.com/v1/claude_code/routines/trig_02/fire"
    with pytest.raises(MailboxError) as missing:
        box.set_webhook(EVE, other_routine, auth_scheme="claude_routine")
    assert missing.value.code == "secret_required"
    assert box.get_webhook(EVE)["url"] == CLAUDE_URL
    moved = box.set_webhook(
        EVE, other_routine, sender_key="sk-new-routine-key-9876", auth_scheme="claude_routine"
    )
    assert moved["secret_hint"] == "9876"


def test_disabled_webhook_does_not_call_out() -> None:
    store = MemoryStore(clock=lambda: 1_700_000_000.0)
    box = Mailbox(store, base_url="https://drive-test.example.com", clock=store._clock)
    link_id = self_pair(box)
    assert box.get_webhook(OWNER_EMAIL, APP)["available"] is False
    with pytest.raises(MailboxError) as disabled:
        box.set_webhook(OWNER_EMAIL, URL, sender_key=SECRET, app=APP)
    assert disabled.value.code == "webhook_disabled"
    _send(box, link_id, "still stored")
    with as_assistant(CLAUDE):
        assert box.check_messages(OWNER_EMAIL)["unread_count"] == 1


# ---- one slot per app ------------------------------------------------------------------


def test_each_app_saves_its_own_hook_and_only_its_mail_wakes_it() -> None:
    posts: list[dict] = []
    box = _wake_box(posts)
    _hook(box, CURSOR, "cursor", sender_key="cursor-key-1234")
    with as_assistant(CLAUDE):
        assert box.get_webhook(OWNER_EMAIL)["configured"] is False  # not Cursor's
    _hook(box, CLAUDE, "claude", sender_key="claude-key-1234")
    with as_assistant(CURSOR):
        assert box.get_webhook(OWNER_EMAIL)["url"] == HOOK + "cursor"  # not replaced
    assert box.webhook_apps(OWNER_EMAIL) == sorted([CLAUDE.grant_id, CURSOR.grant_id])

    link_id = self_pair(box, CURSOR, CLAUDE)
    _send(box, link_id, "hi claude", CURSOR)
    assert _urls(posts) == [HOOK + "claude"]
    _send(box, link_id, "hi cursor", CLAUDE)
    assert _urls(posts) == [HOOK + "claude", HOOK + "cursor"]


def test_another_person_can_wake_none_of_your_assistants() -> None:
    posts: list[dict] = []
    box = _wake_box(posts)
    # Every slot that could be woken: the account-wide one and each app's own.
    _hook(box, CURSOR, "cursor", sender_key="cursor-key-1234")
    _hook(box, CLAUDE, "claude", sender_key="claude-key-1234")
    box.set_webhook(OWNER_EMAIL, HOOK + "account", sender_key="account-key-123", app="")
    box.set_webhook(EVE, URL, sender_key=SECRET)
    link_id = cross_pair(box, EVE, OWNER_EMAIL)

    with pytest.raises(MailboxError) as exc:
        box.send_message(EVE, link_id, "hello")
    assert exc.value.code == "peer_mail_off"
    assert posts == []
    # Mail addressed to the whole account (the only way another person's mail was
    # addressed) has no hook to wake, even if an old message is in the store.
    assert box._wake_targets(OWNER_EMAIL) == []
    legacy_peer_mail(box, link_id, EVE, OWNER_EMAIL, "from before")
    assert posts == []
    with as_assistant(CLAUDE):
        assert box.check_messages(OWNER_EMAIL)["unread_count"] == 0


def test_only_an_apps_own_slot_is_a_wake_target() -> None:
    box = _wake_box([])
    self_pair(box)
    _hook(box, GROK, "grok", sender_key="grok-key-12345")
    box.set_webhook(OWNER_EMAIL, HOOK + "account", sender_key="account-key-123", app="")
    box.store.delete(f"bridge:hookapps:{OWNER_EMAIL}")  # saved before the index existed
    grok = f"{OWNER_EMAIL}#{GROK.grant_id}"
    assert [slot for slot, _ in box._wake_targets(grok)] == [grok]
    assert box._wake_targets(f"{OWNER_EMAIL}#{CLAUDE.grant_id}") == []
    # The account-wide address served mail from other people; it wakes nobody now.
    assert box._wake_targets(OWNER_EMAIL) == []


def test_the_account_hook_never_wakes_an_own_assistant_and_that_is_flagged() -> None:
    """What went wrong on Nov 20: the only hook sat in the account slot. It would have
    woken whoever saved it, maybe the sender."""
    posts: list[dict] = []
    box = _wake_box(posts)
    box.set_webhook(OWNER_EMAIL, HOOK + "account", sender_key="acct-key-1234", app="")
    link_id = self_pair(box)
    assert {m["assistant"] for m in box.missing_wakeups(OWNER_EMAIL)} == {"Grok", "Claude"}
    sent = _send(box, link_id, "hi claude")
    assert sent["wake"]["status"] == "no_wakeup" and posts == []

    # Giving it to Claude fixes it.
    box.move_webhook(OWNER_EMAIL, CLAUDE.grant_id, from_app="")
    assert box.get_webhook(OWNER_EMAIL, "")["configured"] is False
    with as_assistant(CLAUDE):
        assert box.get_webhook(OWNER_EMAIL)["url"] == HOOK + "account"
    assert [m["assistant"] for m in box.missing_wakeups(OWNER_EMAIL)] == ["Grok"]
    sent = _send(box, link_id, "again")
    assert sent["wake"]["status"] == "sent"
    assert _urls(posts) == [HOOK + "account"]


def test_move_a_hook_from_one_app_to_another() -> None:
    posts: list[dict] = []
    box = _wake_box(posts)
    link_id = self_pair(box)
    _hook(box, CURSOR, "cursor", sender_key="cursor-key-1234")  # an older, unpaired app
    box.move_webhook(OWNER_EMAIL, GROK.grant_id, from_app=CURSOR.grant_id)
    with as_assistant(CURSOR):
        assert box.get_webhook(OWNER_EMAIL)["configured"] is False
    assert CURSOR.grant_id not in box.webhook_apps(OWNER_EMAIL)
    _send(box, link_id, "wake grok", CLAUDE)
    assert _urls(posts) == [HOOK + "cursor"]
    with pytest.raises(MailboxError):
        box.move_webhook(OWNER_EMAIL, GROK.grant_id, from_app=GROK.grant_id)
    # There is no "primary app" any more: each app has its own slot.
    assert not hasattr(box, "set_primary") and not hasattr(box, "get_primary")


def test_move_refuses_to_overwrite_an_apps_hook() -> None:
    box = _wake_box([])
    box.set_webhook(OWNER_EMAIL, HOOK + "old", sender_key="old-key-12345")
    _hook(box, CURSOR, "cursor", sender_key="cursor-key-1234")
    with pytest.raises(MailboxError) as exc:
        box.move_webhook(OWNER_EMAIL, CURSOR.grant_id)
    assert exc.value.code == "invalid_state"
    with as_assistant(CURSOR):
        assert box.get_webhook(OWNER_EMAIL)["url"] == HOOK + "cursor"
    assert box.get_webhook(OWNER_EMAIL, "")["url"] == HOOK + "old"


def test_disconnecting_an_app_drops_its_hook() -> None:
    box = _wake_box([])
    _hook(box, CLAUDE, "claude", sender_key="claude-key-1234")
    box.end_assistant_links(OWNER_EMAIL, CLAUDE.grant_id)
    assert box.webhook_apps(OWNER_EMAIL) == []
    with as_assistant(CLAUDE):
        assert box.get_webhook(OWNER_EMAIL)["configured"] is False


def test_a_wake_up_copied_to_another_slot_does_not_fire() -> None:
    # Someone who can write to the store copies a saved wake-up into another slot. Its
    # key was sealed for the slot it was saved in, so it does not open anywhere else.
    posts: list[dict] = []
    box = _wake_box(posts)
    box.set_webhook(OWNER_EMAIL, URL, sender_key=SECRET, app=APP)
    saved = box.store.get(f"bridge:hook:{OWNER_EMAIL}#{APP}")
    box.store.set(f"bridge:hook:{EVE}", saved)
    assert box.test_webhook(EVE, "")["ok"] is False
    assert posts == []
    assert box.test_webhook(OWNER_EMAIL, APP)["ok"] is True


def test_a_wake_up_saved_before_keys_were_bound_still_fires_and_is_bound() -> None:
    box = _wake_box([])
    box.set_webhook(OWNER_EMAIL, URL, sender_key=SECRET, app=APP)
    slot = f"bridge:hook:{OWNER_EMAIL}#{APP}"
    old = json.loads(box.store.get(slot))
    old["ciphertext"], old["nonce"] = seal(SECRET, KEK)
    del old["bound"]
    box.store.set(slot, json.dumps(old))
    assert box.test_webhook(OWNER_EMAIL, APP)["ok"] is True
    assert json.loads(box.store.get(slot))["bound"] is True
    # Moving it to another app seals it again for that slot.
    box.move_webhook(OWNER_EMAIL, GROK.grant_id, APP)
    assert box.test_webhook(OWNER_EMAIL, GROK.grant_id)["ok"] is True


# ---- what the sender is told -------------------------------------------------------------


def test_send_says_no_wakeup_when_the_recipient_has_none() -> None:
    posts: list[dict] = []
    box = _wake_box(posts)
    link_id = self_pair(box)
    sent = _send(box, link_id, "hi grok", CLAUDE)
    assert sent["wake"]["status"] == "no_wakeup"
    assert "Grok has no wake-up saved" in sent["wake"]["hint"]
    assert "Settings" in sent["wake"]["hint"]
    assert posts == []


def test_send_says_sent_and_a_replay_neither_pings_again_nor_changes_the_answer() -> None:
    posts: list[dict] = []
    box = _wake_box(posts)
    link_id = self_pair(box)
    # Nobody to wake: the replay repeats "no_wakeup".
    first = _send(box, link_id, "hi", CLAUDE, idempotency_key="k0")
    again = _send(box, link_id, "hi", CLAUDE, idempotency_key="k0")
    assert again["idempotent_replay"] is True
    assert again["wake"] == first["wake"] and first["wake"]["status"] == "no_wakeup"

    _hook(box, GROK, "grok", sender_key="grok-key-1234")
    first = _send(box, link_id, "hi grok", CLAUDE, idempotency_key="k1")
    assert first["wake"] == {
        "status": "sent",
        "hint": "Grok was woken. The message is in its inbox.",
    }
    last = box.get_webhook(OWNER_EMAIL, GROK.grant_id)["last_wake"]
    assert last["ok"] is True and last["http"] == 200
    again = _send(box, link_id, "hi grok", CLAUDE, idempotency_key="k1")
    assert again["idempotent_replay"] is True
    assert again["wake"]["status"] == "sent"
    assert len(posts) == 1


@pytest.mark.parametrize(
    ("status", "error", "outcome"),
    [(200, None, "sent"), (204, None, "sent"), (202, None, "sent"), (302, "http_status", "failed")],
)
def test_any_2xx_counts_as_delivered(status: int, error: str | None, outcome: str) -> None:
    posts: list[dict] = []
    box = _wake_box(posts, status=status)
    link_id = self_pair(box)
    box.set_webhook(OWNER_EMAIL, URL, sender_key=SECRET, app=APP)
    assert _send(box, link_id, "hello")["wake"]["status"] == outcome
    assert len(posts) == 1
    hook = box.get_webhook(OWNER_EMAIL, APP)
    assert hook.get("last_error") == error
    assert hook["last_wake"]["http"] == status


def test_send_says_failed_and_records_the_http_status() -> None:
    box = _wake_box([], status=401)
    link_id = self_pair(box)
    _hook(box, GROK, "grok", sender_key="grok-key-1234")
    sent = _send(box, link_id, "hi grok", CLAUDE)
    assert sent["wake"]["status"] == "failed"
    last = box.get_webhook(OWNER_EMAIL, GROK.grant_id)["last_wake"]
    assert last["ok"] is False and last["http"] == 401


def test_paused_wakeup_is_reported_as_paused() -> None:
    posts: list[dict] = []
    box = _wake_box(posts)
    link_id = self_pair(box)
    _hook(box, GROK, "grok", sender_key="grok-key-1234", enabled=False)
    sent = _send(box, link_id, "hi grok", CLAUDE)
    assert sent["wake"]["status"] == "paused" and posts == []
    missing = box.missing_wakeups(OWNER_EMAIL)
    assert {m["assistant"] for m in missing} == {"Grok", "Claude"}
    assert next(m for m in missing if m["assistant"] == "Grok")["paused"] is True


def test_a_successful_ping_clears_the_previous_error() -> None:
    calls = {"n": 0}

    def flaky(_request: dict[str, str]) -> int:
        calls["n"] += 1
        if calls["n"] == 1:
            raise ValueError("http_500")
        return 200

    box = _wake_box([], poster=flaky)
    link_id = self_pair(box)
    box.set_webhook(OWNER_EMAIL, URL, sender_key=SECRET, app=APP)
    _send(box, link_id, "first")
    assert box.get_webhook(OWNER_EMAIL, APP)["last_error"] == "http_status"
    _send(box, link_id, "second")
    assert box.get_webhook(OWNER_EMAIL, APP)["last_error"] is None


def test_a_failed_ping_does_not_restore_an_old_webhook() -> None:
    posts: list[dict] = []
    box = _wake_box(posts)

    def rotate_then_fail(request: dict[str, str]) -> int:
        posts.append(request)
        box.set_webhook(OWNER_EMAIL, URL, sender_key="rotated-key-1234", app=APP)
        raise ValueError("http_500")

    box.wake = _settings(posts, poster=rotate_then_fail)
    link_id = self_pair(box)
    box.set_webhook(OWNER_EMAIL, URL, sender_key=SECRET, app=APP)
    _send(box, link_id, "during rotate")
    saved = box.get_webhook(OWNER_EMAIL, APP)
    assert saved["secret_hint"] == "1234"
    assert saved["last_error"] is None


def test_a_retry_while_the_ping_is_in_flight_does_not_claim_success() -> None:
    posts: list[dict] = []
    box = _wake_box(posts)
    _hook(box, GROK, "grok", sender_key="grok-key-1234")
    message = {"to": f"{OWNER_EMAIL}#{GROK.grant_id}", "msg_id": "msg_inflight"}
    box.store.set("bridge:woke:msg_inflight", "pending")
    assert box._maybe_wake(message) == {"status": "pending"}
    box.store.set("bridge:woke:msg_inflight", "1")
    assert box._maybe_wake(message) == {"status": "sent"}
    assert posts == []


def test_a_retry_after_a_failed_holder_pings_again_instead_of_claiming_success() -> None:
    posts: list[dict] = []
    box = _wake_box(posts)
    _hook(box, GROK, "grok", sender_key="grok-key-1234")
    message = {
        "to": f"{OWNER_EMAIL}#{GROK.grant_id}",
        "msg_id": "msg_race",
        "link_id": "l",
        "thread_id": "t",
        "created_at": "2026-11-21T00:00:00Z",
    }
    mark = "bridge:woke:msg_race"
    real_set = box.store.set_if_absent
    calls = {"n": 0}

    def lose_once(key, value, ex=None):
        # First try: another call holds the mark, then fails and deletes it before we read.
        if key == mark and calls["n"] == 0:
            calls["n"] += 1
            return False
        return real_set(key, value, ex=ex)

    box.store.set_if_absent = lose_once
    assert box._maybe_wake(message) == {"status": "sent"}
    assert len(posts) == 1  # this call sent the ping itself


# ---- test wakes, history and the dashboard ---------------------------------------------


def test_test_wake_pings_the_hook_and_records_the_result() -> None:
    posts: list[dict] = []
    box = _wake_box(posts)
    _hook(box, GROK, "grok", sender_key="grok-key-1234")
    assert box.test_webhook(OWNER_EMAIL, GROK.grant_id) == {"ok": True, "http": 200}
    assert len(posts) == 1 and '"link_id":"test"' in posts[0]["body"]
    assert box.get_webhook(OWNER_EMAIL, GROK.grant_id)["last_wake"]["ok"] is True
    # Saving the same hook again (say, to pause it) keeps the history.
    _hook(box, GROK, "grok", enabled=False)
    assert box.get_webhook(OWNER_EMAIL, GROK.grant_id)["last_wake"] is not None
    # A new URL starts afresh.
    _hook(box, GROK, "grok2", sender_key="grok-key-5678")
    assert box.get_webhook(OWNER_EMAIL, GROK.grant_id)["last_wake"] is None
    box.test_webhook(OWNER_EMAIL, GROK.grant_id)
    # Removing the hook drops its history too.
    box.clear_webhook(OWNER_EMAIL, GROK.grant_id)
    assert box.get_webhook(OWNER_EMAIL, GROK.grant_id)["last_wake"] is None


def test_one_assistant_in_two_pairings_is_listed_per_sender() -> None:
    box = _wake_box([])
    self_pair(box)  # Grok and Claude
    self_pair(box, CURSOR, CLAUDE)
    claude = [m for m in box.missing_wakeups(OWNER_EMAIL) if m["assistant"] == "Claude"]
    assert sorted(m["sender"] for m in claude) == ["Cursor", "Grok"]


def test_overview_counts_each_unwakeable_assistant_once() -> None:
    from scoped_drive_mcp.dashboard import _env

    rows = [
        {"grant_id": "g-claude", "assistant": "Claude", "sender": "Grok", "paused": False},
        {"grant_id": "g-claude", "assistant": "Claude", "sender": "Cursor", "paused": False},
    ]
    html = _env.get_template("overview.html").render(
        owner="o@example.com",
        nav="/",
        flashes=[],
        grants=[1, 2],
        missing_wakeups=rows,
        allow_count=1,
        pending_count=0,
        drive_connected=True,
        mcp_url="https://x/mcp",
    )
    assert "1 can’t be woken" in html
    assert "Messages from Grok won’t start Claude" in html
    assert "Messages from Cursor won’t start Claude" in html


def test_settings_page_puts_each_wakeup_on_its_assistant(world, memstore, oauth) -> None:
    posts: list[dict] = []
    app = _app(world, memstore, oauth)
    app.state.mailbox.wake = _settings(posts)
    owner = client(app)
    assert login(owner).status_code == 303
    _grok(owner, "Grok Ada")
    page = owner.get("/settings").text
    assert "Add a wake-up for Grok Ada" in page
    grant = re.search(r'id="app-([^"]+)"', page).group(1)

    # A wake-up pasted without saying which assistant it starts is refused, not filed
    # under the account slot that never fires for mail between your own assistants.
    r = owner.post(
        "/bridge/webhook",
        data={
            "csrf": csrf(owner, "/settings"),
            "action": "save",
            "url": HOOK + "x",
            "sender_key": "k-1234",
        },
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


def test_get_webhook_does_not_show_the_assistant_its_url_or_key(app) -> None:
    box = app.state.mailbox
    box.wake = _settings([])
    box.set_webhook(OWNER_EMAIL, URL, sender_key="sk_live_key_1234", app="")
    assert box.get_webhook(OWNER_EMAIL, "")["url"] == URL  # the dashboard still sees it
    shown = mcp_call(client(app), "get_webhook")["structuredContent"]
    assert shown["configured"] is True
    assert "url" not in shown and "secret_hint" not in shown


def test_watch_prompt_does_not_ask_for_a_pasted_url() -> None:
    assert "check_messages" in WATCH_MAIL
    assert "Do not ask the human to paste a webhook URL" in WATCH_MAIL
    assert "watch_mailbox" in INSTRUCTIONS
    assert "Do not ask the human to paste a webhook URL" in INSTRUCTIONS


def test_kek_must_be_32_bytes_of_base64() -> None:
    assert wake_module.decode_kek(base64.b64encode(KEK).decode()) == KEK
    for bad in (None, "  ", "not base64!", base64.b64encode(b"short").decode()):
        assert wake_module.decode_kek(bad) is None

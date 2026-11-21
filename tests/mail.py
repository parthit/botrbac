"""Helpers for mailbox tests.

Mail only goes between one person's own assistants (a same-account pairing). A pairing
with another person shares documents only, so its mail tests use `legacy_peer_mail` to
put a message in the store the way the server wrote them before that was turned off.
"""

from scoped_drive_mcp.bridge import MESSAGE_TTL, Assistant, Mailbox, _id, _iso, as_assistant
from tests.conftest import EVE, OWNER_EMAIL

# Two OAuth apps of OWNER_EMAIL: SENDER writes, READER reads (either can do both).
SENDER = Assistant("grant-grok", "Grok")
READER = Assistant("grant-claude", "Claude")
THIRD = Assistant("grant-cursor", "Cursor")


def self_pair(
    box: Mailbox,
    a: Assistant = SENDER,
    b: Assistant = READER,
    email: str = OWNER_EMAIL,
    approve: bool = True,
) -> str:
    """Pair two assistants of one Google account and (by default) approve it."""
    with as_assistant(a):
        created = box.request_link(email, new_invite=True)
    with as_assistant(b):
        joined = box.request_link(email, created["invite_code"])
    assert joined["same_account"] is True
    if approve:
        assert box.decide(email, created["link_id"], "approve")["status"] == "active"
    return created["link_id"]


def cross_pair(box: Mailbox, a: str = OWNER_EMAIL, b: str = EVE, approve: bool = True) -> str:
    """Pair two people. Both approve by default."""
    created = box.request_link(a, new_invite=True)
    box.request_link(b, created["invite_code"])
    if approve:
        box.decide(a, created["link_id"], "approve")
        box.decide(b, created["link_id"], "approve")
    return created["link_id"]


def legacy_peer_mail(
    box: Mailbox, link_id: str, sender: str, recipient: str, body: str, thread_id: str = "old"
) -> str:
    """Write a message on a cross-account link straight into the store, as the server did
    before mail between people was turned off. Returns its msg_id."""
    now = box._now()
    message = {
        "msg_id": _id("msg"),
        "link_id": link_id,
        "from": sender,
        "to": recipient,
        "body": body,
        "thread_id": thread_id,
        "created_at": _iso(now),
        "read_at": None,
        "expires_at": _iso(now + MESSAGE_TTL),
    }
    box._publish(message)
    return message["msg_id"]

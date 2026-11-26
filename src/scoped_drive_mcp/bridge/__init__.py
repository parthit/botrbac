"""Pairings between people, and the mailbox between one person's own assistants.

Each person is their Google account. The record lives on the root key-value store
(global `bridge:` keys), not in one person's actor prefix.

A pairing between two people carries no messages at all. Once both humans approve it,
each person's assistants may read what the other put on their Sharing list, and nothing
else: another person's assistant can never send text to yours, so it has no way to
prompt yours. Messages only go between one person's own assistants.

A same-account link pairs two assistants of one person (say Grok and Claude, both
signed in with the same Google account). Its sides are OAuth grants, not emails: mail
is addressed to `email#grant_id`, so each assistant has its own inbox. The human
approves it once.

The package is one `Mailbox` class assembled from three parts:

- `pairing.py`  (`PairingMixin`): links, invites, approvals, status, ending a pairing
- `mail.py`     (`MailMixin`): sending, inboxes, threads, read marks, purging, hourly limits
- `webhooks.py` (`WebhookMixin`): wake-up webhooks and the pings sent through them
- `mailbox.py`  (`Mailbox`): the constructor and the clock the three parts share
- `common.py`: constants, `MailboxError`, `Assistant`, untrusted-text wrapping, helpers

Everything the old single module defined is re-exported here.
"""

from .common import (
    _INJECTION,
    _INVITE_ALPHABET,
    _TAG,
    _TOKEN_SHAPE,
    DAY,
    HANDLING,
    HOUR,
    INVITE_TTL,
    LINK_REQUESTS_PER_HOUR,
    MAX_BODY_BYTES,
    MESSAGE_TTL,
    PEER_MAIL_OFF,
    PEER_TTL,
    PER_LINK_PER_HOUR,
    PER_USER_PER_HOUR,
    UNTRUSTED_END,
    UNTRUSTED_START,
    Assistant,
    MailboxError,
    _check_body,
    _digest,
    _email,
    _from_assistant,
    _host,
    _id,
    _iso,
    _key_carries,
    _labels,
    _limit,
    _next_step,
    _parse_since,
    _parties,
    _pending_token,
    _retry,
    _same_target,
    _self_addr,
    _sent,
    _split_pending,
    _wake_error,
    _wake_http,
    _wake_view,
    as_assistant,
    current_assistant,
    neutralize,
    present_untrusted,
    preview_untrusted,
)
from .mailbox import Mailbox

__all__ = [
    "Assistant",
    "DAY",
    "HANDLING",
    "HOUR",
    "INVITE_TTL",
    "LINK_REQUESTS_PER_HOUR",
    "MAX_BODY_BYTES",
    "MESSAGE_TTL",
    "Mailbox",
    "MailboxError",
    "PEER_MAIL_OFF",
    "PEER_TTL",
    "PER_LINK_PER_HOUR",
    "PER_USER_PER_HOUR",
    "UNTRUSTED_END",
    "UNTRUSTED_START",
    "_INJECTION",
    "_INVITE_ALPHABET",
    "_TAG",
    "_TOKEN_SHAPE",
    "_check_body",
    "_digest",
    "_email",
    "_from_assistant",
    "_host",
    "_id",
    "_iso",
    "_key_carries",
    "_labels",
    "_limit",
    "_next_step",
    "_parse_since",
    "_parties",
    "_pending_token",
    "_retry",
    "_same_target",
    "_self_addr",
    "_sent",
    "_split_pending",
    "_wake_error",
    "_wake_http",
    "_wake_view",
    "as_assistant",
    "current_assistant",
    "neutralize",
    "present_untrusted",
    "preview_untrusted",
]

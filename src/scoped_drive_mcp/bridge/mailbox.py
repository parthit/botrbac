"""The `Mailbox` class: the constructor, the clock, and the three parts put together.

Pairing, mail and wake-up webhooks each live in their own module as a mixin. They are
one object on purpose: they share one store, one lock and one clock, and they call each
other's methods through `self` (each mixin lists what it borrows).
"""

import threading
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any

from cryptography.fernet import Fernet

from ..store import KeyValueStore, purpose_fernet
from ..wake import WakeSettings
from .common import _iso
from .mail import MailMixin
from .pairing import PairingMixin
from .webhooks import WebhookMixin


class Mailbox(PairingMixin, MailMixin, WebhookMixin):
    def __init__(
        self,
        store: KeyValueStore,
        base_url: str = "",
        clock: Any = None,
        encryption_key: str | None = None,
        wake: WakeSettings | None = None,
        strict: bool = False,
    ) -> None:
        self.store = store
        # REQUIRE_SIGNED_RECORDS is on: an approval has to name the person who joined.
        self.strict = strict
        self.base_url = base_url.rstrip("/")
        self.clock = clock or time.time
        self._lock = threading.Lock()
        # Mail has its own key, derived from ENCRYPTION_KEY. The Drive sign-in vault uses
        # ENCRYPTION_KEY itself, so with one shared key a message body swapped in the
        # store for a vault record would be decrypted and shown, and a message could be
        # written that the vault accepts.
        self._fernet = purpose_fernet(encryption_key, "mailbox") if encryption_key else None
        # Mail saved before that was encrypted with ENCRYPTION_KEY itself. It is still
        # read until it expires (MESSAGE_TTL), see `_open_body`.
        self._legacy_fernet = Fernet(encryption_key.strip().encode()) if encryption_key else None
        self.wake = wake or WakeSettings()
        # Called with (a, b) when two people stop being paired, so each person's Sharing
        # list stops naming the other: re-pairing later must not bring that access back.
        self.on_unpaired: Callable[[str, str], None] | None = None

    def _now(self) -> float:
        return float(self.clock())

    def _iso(self, at: float | None = None) -> str:
        return _iso(self._now() if at is None else at)

    def _stamp(self, value: str) -> float:
        return datetime.fromisoformat(value).timestamp()

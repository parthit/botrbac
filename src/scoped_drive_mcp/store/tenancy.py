"""Opening each person's store, the users index and dashboard sessions."""

import hashlib
import json
import logging
import secrets
from typing import Any

from .backends import (
    KeyValueStore,
    utc_now,
)
from .keys import (
    USERS_INDEX,
)
from .records import (
    TokenVault,
)
from .wrappers import (
    ActorStore,
    PrefixedStore,
    tenant_prefix,
)

# One logger name for the whole package, the one `store.py` logged under.
logger = logging.getLogger("scoped_drive_mcp.store")


def _session_key(sid: str) -> str:
    return "session:" + hashlib.sha256(sid.encode()).hexdigest()


class TenantDirectory:
    """Opens one person's store without changing `current_actor`.

    The admin uses the legacy keys. Everyone else uses `u:{email}:` on the already
    prefixed store. `users:index` records when each address first signed in.
    """

    def __init__(self, store: KeyValueStore, admin_email: str | None, encryption_key: str | None):
        self.store = store
        self.admin_email = admin_email
        self.encryption_key = encryption_key

    def store_for(self, email: str | None) -> KeyValueStore:
        if email is None or email == self.admin_email:
            return self.store
        return PrefixedStore(self.store, tenant_prefix(email))

    def vault_for(self, email: str | None) -> TokenVault:
        return TokenVault(
            self.store_for(email), self.encryption_key, expected=lambda: email or self.admin_email
        )

    # Dashboard sessions. The cookie carries a random id; the id has to be here too, so
    # signing out ends the session and it cannot outlive `ttl` by being re-signed.
    def open_session(self, email: str, ttl: int) -> str:
        sid = secrets.token_urlsafe(32)
        self.store.set(_session_key(sid), email, ex=ttl)
        return sid

    def session_alive(self, sid: Any, email: str) -> bool:
        if not isinstance(sid, str) or not sid:
            return False
        return self.store.get(_session_key(sid)) == email

    def close_session(self, sid: Any) -> None:
        if isinstance(sid, str) and sid:
            self.store.delete(_session_key(sid))

    def actor_store(self) -> ActorStore:
        return ActorStore(self.store, self.admin_email)

    def has_owner_refresh(self, email: str) -> bool:
        """Any stored Drive sign-in, including an old one that is no longer used."""
        vault = self.vault_for(email)
        record = vault.owner() or vault.legacy_owner()
        return bool(record and record.get("t"))

    def is_known_user(self, email: str) -> bool:
        """Signed in at least once (step 1), or has a stored connection from before."""
        return self.store.hget(USERS_INDEX, email) is not None or self.has_owner_refresh(email)

    def remember_user(self, email: str) -> None:
        if self.store.hget(USERS_INDEX, email) is None:
            self.store.hset(USERS_INDEX, email, json.dumps({"created_at": utc_now()}))

    def created_at(self, email: str) -> str | None:
        raw = self.store.hget(USERS_INDEX, email)
        if not raw:
            return None
        try:
            value = json.loads(raw).get("created_at")
        except ValueError:
            return None
        return str(value) if value else None

    def stored_bot_email(self, email: str) -> str | None:
        record = self.vault_for(email).bot()
        if not record or not record.get("t"):
            return None
        bot = record.get("email")
        return str(bot) if bot else None

    def known_users(self) -> list[str]:
        found = set(self.store.hgetall(USERS_INDEX))
        if self.admin_email and self.has_owner_refresh(self.admin_email):
            found.add(self.admin_email)
        return sorted(found, key=lambda email: (self.created_at(email) or "", email))

    def email_in_use(self, candidate: str, *, except_user: str, reserved_bot: str | None) -> bool:
        """True when `candidate` is someone else's dashboard address or bot address."""
        candidate = candidate.lower()
        dashboards = set(self.store.hgetall(USERS_INDEX))
        if self.admin_email:
            dashboards.add(self.admin_email)
        if candidate in dashboards:
            return True
        if reserved_bot and candidate == reserved_bot and except_user != self.admin_email:
            return True
        for user in dashboards:
            if user == except_user:
                continue
            if self.stored_bot_email(user) == candidate:
                return True
        return False

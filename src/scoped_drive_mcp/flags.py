"""Server-side switches read from Vercel Edge Config.

Edge Config is a small key-value store Vercel serves next to the function. Connecting
one to the project injects `EDGE_CONFIG`, a connection string like
`https://edge-config.vercel.com/ecfg_xxx?token=yyy`. Items are edited in the Vercel
dashboard (Storage → Edge Config) and take effect without a redeploy.

`self_pairing` decides whether one Google account may pair two of its own assistants:

    {"enabled": true, "off_for_domains": ["example.com"]}

Without `EDGE_CONFIG` (local runs, tests) the feature is on. If the read fails, the
last good value is used; with none at all the feature is off, so an organisation that
turned it off never gets it back because of a network blip.
"""

import logging
import threading
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx

SELF_PAIRING_ITEM = "self_pairing"
TERMINAL_ITEM = "terminal"
CACHE_SECONDS = 30.0
TIMEOUT_SECONDS = 2.0

Fetch = Callable[[str], Any]


def self_pairing_allowed(value: Any, email: str) -> bool:
    """Whether the `self_pairing` item allows this person. A missing item means on."""
    if value is None:
        return True
    if not isinstance(value, dict):
        return False
    if value.get("enabled", True) is not True:
        return False
    domain = email.rsplit("@", 1)[-1].strip().lower()
    blocked = value.get("off_for_domains") or []
    if not isinstance(blocked, list):
        return False
    return domain not in {str(item).strip().lower().lstrip("@") for item in blocked}


def terminal_allowed(value: Any, email: str) -> bool:
    """Whether the `terminal` item turns the beta on for this person.

    `{"enabled": true}` is everyone; `{"enabled": true, "emails": [...]}` is only those
    addresses. A missing or malformed item means off: the beta is opt-in.
    """
    if not isinstance(value, dict) or value.get("enabled") is not True:
        return False
    emails = value.get("emails")
    if emails is None:
        return True
    if not isinstance(emails, list):
        return False
    return email.strip().lower() in {str(item).strip().lower() for item in emails}


class EdgeConfigFlags:
    """Reads one Edge Config item, cached per instance."""

    def __init__(
        self,
        connection: str | None,
        fetch: Fetch | None = None,
        clock: Callable[[], float] | None = None,
        ttl: float = CACHE_SECONDS,
    ) -> None:
        self.connection = (connection or "").strip() or None
        self._fetch = fetch or self._http_fetch
        self._clock = clock or time.monotonic
        self._ttl = ttl
        self._lock = threading.Lock()
        # item -> (fetched_at, value); value None means "item not set".
        self._cache: dict[str, tuple[float, Any]] = {}
        # item -> when a read last failed with nothing cached.
        self._failed: dict[str, float] = {}

    def self_pairing_enabled(self, email: str) -> bool:
        if self.connection is None:
            return True
        found, value = self._item(SELF_PAIRING_ITEM)
        if not found:
            return False
        return self_pairing_allowed(value, email)

    def terminal_enabled(self, email: str) -> bool:
        """The Terminal beta. Unlike self_pairing it is off without Edge Config."""
        if self.connection is None:
            return False
        found, value = self._item(TERMINAL_ITEM)
        return found and terminal_allowed(value, email)

    def _item(self, key: str) -> tuple[bool, Any]:
        """(known, value). `known` is False only when nothing was ever read."""
        now = self._clock()
        with self._lock:
            cached = self._cache.get(key)
            failed = self._failed.get(key)
        if cached is not None and now - cached[0] < self._ttl:
            return True, cached[1]
        if cached is None and failed is not None and now - failed < self._ttl:
            return False, None
        try:
            value = self._fetch(key)
        except Exception as exc:  # noqa: BLE001 - any failure falls back to the cache
            logging.getLogger(__name__).warning("edge_config_read_failed %s", type(exc).__name__)
            # Remember the failure for one TTL too, so an outage costs one timeout per
            # window instead of one per call.
            with self._lock:
                if cached is not None:
                    self._cache[key] = (now, cached[1])
                else:
                    self._failed[key] = now
            if cached is not None:
                return True, cached[1]
            return False, None
        with self._lock:
            self._cache[key] = (now, value)
        return True, value

    def _http_fetch(self, key: str) -> Any:
        assert self.connection is not None
        parts = urlsplit(self.connection)
        token = (parse_qs(parts.query).get("token") or [""])[0]
        base = f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}"
        response = httpx.get(
            f"{base}/item/{key}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=TIMEOUT_SECONDS,
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()

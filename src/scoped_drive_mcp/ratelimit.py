"""Fixed-window rate limits backed by the same key/value store as the rest of the app.

Memory, Redis and Postgres all implement `incr`, so the counter is shared across
instances when the deployment has a real store. A store error fails open: a
limiter outage must not take down sign-in or `/mcp`.
"""

import hashlib
import ipaddress
import logging
import os
import time
from collections.abc import Callable

import anyio.to_thread
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .auth import current_principal

logger = logging.getLogger(__name__)


def trusted_proxy_hops() -> int:
    """How many proxies in front of this server add to X-Forwarded-For.

    TRUSTED_PROXY_HOPS when set. Otherwise 1 on Vercel, which replaces the header with the
    caller's address, and 0 elsewhere: the header is then whatever the caller typed."""
    raw = os.environ.get("TRUSTED_PROXY_HOPS", "").strip()
    if raw:
        try:
            return max(0, int(raw))
        except ValueError:
            _warn_once("bad-hops", "TRUSTED_PROXY_HOPS is not a number; using 0")
            return 0
    return 1 if os.environ.get("VERCEL") else 0


_warned: set[str] = set()


def _warn_once(key: str, message: str) -> None:
    if key not in _warned:
        _warned.add(key)
        logger.warning(message)


def client_ip(headers: list[tuple[bytes, bytes]], fallback: str) -> str:
    """The caller's address: the socket peer, or the X-Forwarded-For entry written by the
    outermost proxy this deployment trusts. Entries to the left of that one come from the
    caller and are ignored, so a made-up address does not get its own rate-limit bucket."""
    hops = trusted_proxy_hops()
    if hops:
        chain = [
            part.strip()
            for key, value in headers
            if key.lower() == b"x-forwarded-for"
            for part in value.decode("latin-1", "replace").split(",")
            if part.strip()
        ]
        if len(chain) >= hops:
            return chain[-hops][:80]
        # The proxy this deployment trusts did not write the header. Every caller then
        # shares the proxy's own address, so say so once instead of failing quietly.
        _warn_once(
            "short-xff",
            "X-Forwarded-For has fewer entries than TRUSTED_PROXY_HOPS expects, so rate "
            "limits use the socket address.",
        )
    elif any(key.lower() == b"x-forwarded-for" for key, _ in headers):
        # Behind a reverse proxy every caller then shares the proxy's address, and one
        # of them can use up the limit for all. Said once, so the log is not flooded.
        _warn_once(
            "ignored-xff",
            "X-Forwarded-For is present but ignored, so rate limits use the socket address. "
            "Behind a reverse proxy, set TRUSTED_PROXY_HOPS to the number of proxies.",
        )
    return (fallback or "unknown")[:80]


def address_bucket(address: str) -> str:
    """The rate-limit bucket for one address. An IPv6 caller usually holds a whole /64
    and can pick a new address from it for every request, so IPv6 is counted per /64. An
    IPv4-mapped IPv6 address counts as the IPv4 address it carries. Anything that is not
    an address (a test client's "testclient", "unknown") is used as it is."""
    try:
        parsed = ipaddress.ip_address(address.strip().strip("[]"))
    except ValueError:
        return address
    if isinstance(parsed, ipaddress.IPv6Address):
        if parsed.ipv4_mapped is not None:
            return str(parsed.ipv4_mapped)
        network = ipaddress.IPv6Network((int(parsed) >> 64 << 64, 64))
        return str(network)
    return str(parsed)


def ip_identity(scope: Scope) -> str:
    host = "unknown"
    client = scope.get("client")
    if client:
        host = str(client[0])
    return "ip:" + address_bucket(client_ip(list(scope.get("headers") or []), host))


def principal_identity(_scope: Scope) -> str | None:
    """The caller `BearerAuthMiddleware` resolved, for a limiter placed inside it.

    Keyed on what stays the same while an app keeps working: its connection (OAuth grant
    id) or its `API_TOKENS` name. A raw bearer would not do: every OAuth refresh hands
    out a new access token, and each would start with a fresh allowance."""
    principal = current_principal.get()
    if principal is None:
        return None
    if principal.grant_id:
        return "g:" + principal.grant_id
    digest = hashlib.sha256(principal.token_name.encode()).hexdigest()[:24]
    return "k:" + digest


def _key(name: str, ident: str, window: int, now: float | None = None) -> str:
    bucket = int((now if now is not None else time.time()) // window)
    safe = "".join(ch for ch in ident if ch.isalnum() or ch in ":-_@./")[:80] or "anon"
    return f"rl:{name}:{safe}:{bucket}"


def allow(
    store: object, name: str, ident: str, limit: int, window: int, now: float | None = None
) -> bool:
    """True when this identity is still inside the window. Fail open on store errors."""
    try:
        count = store.incr(_key(name, ident, window, now), ex=window + 5)  # type: ignore[attr-defined]
    except Exception:
        logger.warning("rate limit store failed for %s", name)
        return True
    return int(count) <= limit


class RateLimitApp:
    """ASGI wrapper that counts requests per caller. Over-limit requests get 429 JSON and
    never reach the inner app.

    Placed inside `BearerAuthMiddleware`, so it counts callers whose bearer was already
    accepted, per connection (`principal_identity`): one busy assistant does not throttle
    others behind the same address, and refreshing tokens does not reset the count.
    Callers with no resolved identity are counted per address.
    """

    def __init__(
        self,
        app: ASGIApp,
        store: object,
        *,
        name: str,
        limit: int,
        window: int,
        identify: Callable[[Scope], str | None] = principal_identity,
    ):
        self.app = app
        self.store = store
        self.name = name
        self.limit = limit
        self.window = window
        self.identify = identify

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        ident = self.identify(scope) or ip_identity(scope)
        allowed = await anyio.to_thread.run_sync(
            lambda: allow(self.store, self.name, ident, self.limit, self.window)
        )
        if allowed:
            await self.app(scope, receive, send)
            return
        await _too_many(send, self.window)


class AuthFailureLimitApp:
    """ASGI wrapper around `BearerAuthMiddleware` that limits rejected bearers per address.

    A made-up token cannot be told apart from a real one without asking the auth layer,
    so every request goes through to it. Only an answer of 401 (no token, or a token that
    is not valid) is counted against the caller's address, and once that address used up
    its allowance those 401s become 429. A valid token from the same address is never
    refused by this counter, so someone sending bad tokens from a shared address (an
    office NAT, a hosted assistant's egress) cannot lock out the others there.
    """

    def __init__(self, app: ASGIApp, store: object, *, name: str, limit: int, window: int):
        self.app = app
        self.store = store
        self.name = f"{name}-401"
        self.limit = limit
        self.window = window

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        ip = ip_identity(scope)
        swallowing = False

        async def watch(message: Message) -> None:
            nonlocal swallowing
            if swallowing:
                return
            if message["type"] == "http.response.start" and message["status"] == 401:
                allowed = await anyio.to_thread.run_sync(
                    lambda: allow(self.store, self.name, ip, self.limit, self.window)
                )
                if not allowed:
                    swallowing = True
                    await _too_many(send, self.window)
                    return
            await send(message)

        await self.app(scope, receive, watch)


async def _too_many(send: Send, window: int) -> None:
    body = b'{"error":"rate_limited"}'
    await send(
        {
            "type": "http.response.start",
            "status": 429,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"retry-after", str(window).encode()),
                (b"cache-control", b"no-store"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})

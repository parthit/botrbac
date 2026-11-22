"""Fixed-window rate limits backed by the same key/value store as the rest of the app.

Memory, Redis and Postgres all implement `incr`, so the counter is shared across
instances when the deployment has a real store. A store error fails open: a
limiter outage must not take down sign-in or `/mcp`.
"""

import hashlib
import logging
import os
import time

import anyio.to_thread
from starlette.types import ASGIApp, Message, Receive, Scope, Send

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


def ip_identity(scope: Scope) -> str:
    host = "unknown"
    client = scope.get("client")
    if client:
        host = str(client[0])
    return "ip:" + client_ip(list(scope.get("headers") or []), host)


def _identity_from_scope(scope: Scope) -> str:
    headers = list(scope.get("headers") or [])
    token = ""
    for key, value in headers:
        if key.lower() == b"authorization":
            raw = value.decode("latin-1", "replace").strip()
            parts = raw.split(None, 1)
            token = parts[-1].strip() if parts else ""
            break
    if token:
        digest = hashlib.sha256(token.encode()).hexdigest()[:24]
        return f"t:{digest}"
    return ip_identity(scope)


def _key(name: str, ident: str, window: int, now: float | None = None) -> str:
    bucket = int((now if now is not None else time.time()) // window)
    safe = "".join(ch for ch in ident if ch.isalnum() or ch in ":-_@.")[:80] or "anon"
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


def over(store: object, name: str, ident: str, limit: int, window: int) -> bool:
    """True when this identity already used up its window. Reads only; fails open."""
    try:
        count = store.get(_key(name, ident, window))  # type: ignore[attr-defined]
        return count is not None and int(count) >= limit
    except Exception:
        logger.warning("rate limit store failed for %s", name)
        return False


class RateLimitApp:
    """ASGI wrapper. Over-limit requests get 429 JSON and never reach the inner app.

    Requests are counted per bearer token, so one busy assistant does not throttle
    others behind the same address. A made-up token would get a fresh bucket each
    time, so requests the inner app answers with 401 are also counted per address,
    and an address that keeps failing is refused before the inner app runs.
    """

    def __init__(self, app: ASGIApp, store: object, *, name: str, limit: int, window: int):
        self.app = app
        self.store = store
        self.name = name
        self.limit = limit
        self.window = window

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        ident = _identity_from_scope(scope)
        ip = ip_identity(scope)
        failures = f"{self.name}-401"

        def check() -> bool:
            if over(self.store, failures, ip, self.limit, self.window):
                return False
            return allow(self.store, self.name, ident, self.limit, self.window)

        if await anyio.to_thread.run_sync(check):
            rejected = False

            async def watch(message: Message) -> None:
                nonlocal rejected
                if message["type"] == "http.response.start" and message["status"] == 401:
                    rejected = True
                await send(message)

            await self.app(scope, receive, watch)
            # A request with no token already counts against the address above.
            if rejected and ident != ip:
                await anyio.to_thread.run_sync(
                    lambda: allow(self.store, failures, ip, self.limit, self.window)
                )
            return
        body = b'{"error":"rate_limited"}'
        await send(
            {
                "type": "http.response.start",
                "status": 429,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"retry-after", str(self.window).encode()),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

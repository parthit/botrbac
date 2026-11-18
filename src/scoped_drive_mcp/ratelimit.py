"""Fixed-window rate limits backed by the same key/value store as the rest of the app.

Memory, Redis and Postgres all implement `incr`, so the counter is shared across
instances when the deployment has a real store. A store error fails open: a
limiter outage must not take down sign-in or `/mcp`.
"""

import hashlib
import logging
import time

import anyio.to_thread
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger(__name__)


def client_ip(headers: list[tuple[bytes, bytes]], fallback: str) -> str:
    """First address in X-Forwarded-For, else the socket peer. Capped and stripped."""
    for key, value in headers:
        if key.lower() == b"x-forwarded-for":
            first = value.decode("latin-1", "replace").split(",", 1)[0].strip()
            if first:
                return first[:80]
    return (fallback or "unknown")[:80]


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
    host = "unknown"
    client = scope.get("client")
    if client:
        host = str(client[0])
    return "ip:" + client_ip(headers, host)


def allow(
    store: object, name: str, ident: str, limit: int, window: int, now: float | None = None
) -> bool:
    """True when this identity is still inside the window. Fail open on store errors."""
    bucket = int((now if now is not None else time.time()) // window)
    safe = "".join(ch for ch in ident if ch.isalnum() or ch in ":-_@.")[:80] or "anon"
    key = f"rl:{name}:{safe}:{bucket}"
    try:
        count = store.incr(key, ex=window + 5)  # type: ignore[attr-defined]
    except Exception:
        logger.warning("rate limit store failed for %s", name)
        return True
    return int(count) <= limit


class RateLimitApp:
    """ASGI wrapper. Over-limit requests get 429 JSON and never reach the inner app."""

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
        allowed = await anyio.to_thread.run_sync(
            lambda: allow(self.store, self.name, ident, self.limit, self.window)
        )
        if allowed:
            await self.app(scope, receive, send)
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

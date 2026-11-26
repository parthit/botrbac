"""The storage backends: the `KeyValueStore` protocol and its in-memory, Upstash Redis and
Postgres implementations, with the Lua scripts and SQL they run."""

import logging
import re
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol

# One logger name for the whole package, the one `store.py` logged under.
logger = logging.getLogger("scoped_drive_mcp.store")

_REPLACE_LIST_SCRIPT = """
redis.call('DEL', KEYS[1])
for i = #ARGV, 1, -1 do
    redis.call('LPUSH', KEYS[1], ARGV[i])
end
return #ARGV
"""

_INCR_SCRIPT = """
local n = redis.call('INCR', KEYS[1])
if tonumber(n) == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return n
"""

# Inbox rows are msg_id|link_id|created_epoch|expires_epoch|unread. Anything else is dropped.
_INBOX_TOKEN = re.compile(r"^([^|]+)\|([^|]+)\|([0-9]+)\|([0-9]+)\|([01])$")

_LDROP_EXPIRED_SCRIPT = """
local now = tonumber(ARGV[1])
local removed = 0
for _, value in ipairs(redis.call('LRANGE', KEYS[1], 0, -1)) do
    local expires = string.match(value, '^[^|]+|[^|]+|[0-9]+|([0-9]+)|[01]$')
    if (not expires) or (tonumber(expires) <= now) then
        redis.call('LREM', KEYS[1], 0, value)
        removed = removed + 1
    end
end
return removed
"""

_SWAP_SCRIPT = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
    redis.call('SET', KEYS[1], ARGV[2], 'KEEPTTL')
    return 1
end
return 0
"""

_HSWAP_SCRIPT = """
if redis.call('HGET', KEYS[1], ARGV[1]) == ARGV[2] then
    redis.call('HSET', KEYS[1], ARGV[1], ARGV[3])
    return 1
end
return 0
"""

_LREPLACE_SCRIPT = """
local replaced = 0
local index = 0
while true do
    local value = redis.call('LINDEX', KEYS[1], index)
    if not value then
        break
    end
    if value == ARGV[1] then
        redis.call('LSET', KEYS[1], index, ARGV[2])
        replaced = replaced + 1
    end
    index = index + 1
end
return replaced
"""


def parse_inbox_token(value: str) -> tuple[str, str, int, int, bool] | None:
    """Return msg_id, link_id, created epoch, expires epoch, and unread. None if malformed."""
    match = _INBOX_TOKEN.fullmatch(value)
    if match is None:
        return None
    return (
        match.group(1),
        match.group(2),
        int(match.group(3)),
        int(match.group(4)),
        match.group(5) == "1",
    )


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class KeyValueStore(Protocol):
    def get(self, key: str) -> str | None: ...
    def set(self, key: str, value: str, ex: int | None = None) -> None: ...
    def delete(self, key: str) -> None: ...
    def hset(self, key: str, field: str, value: str) -> None: ...
    def hget(self, key: str, field: str) -> str | None: ...
    def hgetall(self, key: str) -> dict[str, str]: ...
    def hdel(self, key: str, field: str) -> None: ...
    def lpush(self, key: str, value: str) -> None: ...
    def ltrim(self, key: str, start: int, stop: int) -> None: ...
    def lrange(self, key: str, start: int, stop: int) -> list[str]: ...
    def lrem(self, key: str, value: str) -> int: ...
    def lreplace(self, key: str, old: str, new: str) -> int: ...
    def ldrop_expired(self, key: str, now: int) -> int: ...
    def incr(self, key: str, ex: int) -> int: ...
    def set_if_absent(self, key: str, value: str, ex: int) -> bool: ...


class MemoryStore:
    """Thread-safe in-memory store with expiring keys. Per process only."""

    kind = "memory"

    def __init__(self, clock: Callable[[], float] = time.time):
        self._clock = clock
        self._lock = threading.Lock()
        self._values: dict[str, tuple[float | None, Any]] = {}

    def _live(self, key: str) -> Any:
        item = self._values.get(key)
        if item is None:
            return None
        expires, value = item
        if expires is not None and expires <= self._clock():
            del self._values[key]
            return None
        return value

    def get(self, key: str) -> str | None:
        with self._lock:
            value = self._live(key)
            return value if isinstance(value, str) else None

    def getdel(self, key: str) -> str | None:
        """Return a string value and delete it. Expired keys disappear."""
        with self._lock:
            value = self._live(key)
            self._values.pop(key, None)
            return value if isinstance(value, str) else None

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        with self._lock:
            expires = self._clock() + ex if ex else None
            self._values[key] = (expires, value)

    def swap(self, key: str, old: str, new: str) -> bool:
        """Replace a string with `new` only if it still says `old`. Keeps its expiry."""
        with self._lock:
            if self._live(key) != old:
                return False
            self._values[key] = (self._values[key][0], new)
            return True

    def hswap(self, key: str, field: str, old: str, new: str) -> bool:
        """Replace one hash field with `new` only if it still says `old`."""
        with self._lock:
            current = self._live(key)
            if not isinstance(current, dict) or current.get(field) != old:
                return False
            current[field] = new
            return True

    def delete(self, key: str) -> None:
        with self._lock:
            self._values.pop(key, None)

    def hset(self, key: str, field: str, value: str) -> None:
        with self._lock:
            current = self._live(key)
            if not isinstance(current, dict):
                current = {}
                self._values[key] = (None, current)
            current[field] = value

    def hget(self, key: str, field: str) -> str | None:
        with self._lock:
            current = self._live(key)
            return current.get(field) if isinstance(current, dict) else None

    def hgetall(self, key: str) -> dict[str, str]:
        with self._lock:
            current = self._live(key)
            return dict(current) if isinstance(current, dict) else {}

    def hdel(self, key: str, field: str) -> None:
        with self._lock:
            current = self._live(key)
            if isinstance(current, dict):
                current.pop(field, None)

    def lpush(self, key: str, value: str) -> None:
        with self._lock:
            current = self._live(key)
            if not isinstance(current, list):
                current = []
                self._values[key] = (None, current)
            current.insert(0, value)

    def ltrim(self, key: str, start: int, stop: int) -> None:
        with self._lock:
            current = self._live(key)
            if isinstance(current, list):
                end = None if stop == -1 else stop + 1
                current[:] = current[start:end]

    def lrange(self, key: str, start: int, stop: int) -> list[str]:
        with self._lock:
            current = self._live(key)
            if not isinstance(current, list):
                return []
            end = None if stop == -1 else stop + 1
            return list(current[start:end])

    def lrem(self, key: str, value: str) -> int:
        with self._lock:
            current = self._live(key)
            if not isinstance(current, list):
                return 0
            kept = [item for item in current if item != value]
            removed = len(current) - len(kept)
            current[:] = kept
            return removed

    def lreplace(self, key: str, old: str, new: str) -> int:
        with self._lock:
            current = self._live(key)
            if not isinstance(current, list):
                return 0
            replaced = 0
            for index, item in enumerate(current):
                if item == old:
                    current[index] = new
                    replaced += 1
            return replaced

    def ldrop_expired(self, key: str, now: int) -> int:
        """Remove expired or malformed inbox rows. A concurrent push of a new row stays."""
        with self._lock:
            current = self._live(key)
            if not isinstance(current, list):
                return 0
            kept = []
            removed = 0
            for item in current:
                parsed = parse_inbox_token(item)
                if parsed is not None and parsed[3] > now:
                    kept.append(item)
                else:
                    removed += 1
            current[:] = kept
            return removed

    def incr(self, key: str, ex: int) -> int:
        """Add one and return the new value. An expired key starts again at 1."""
        with self._lock:
            current = self._live(key)
            if isinstance(current, str) and current.isdigit():
                # A fixed window, like Redis: the first hit sets the expiry, later ones keep it.
                expires = self._values[key][0]
                count = int(current) + 1
            else:
                expires = self._clock() + ex if ex else None
                count = 1
            self._values[key] = (expires, str(count))
            return count

    def set_if_absent(self, key: str, value: str, ex: int) -> bool:
        """Set `key` only when it is missing or expired. True when this caller won."""
        with self._lock:
            if self._live(key) is not None:
                return False
            expires = self._clock() + ex if ex else None
            self._values[key] = (expires, value)
            return True

    def replace_list(self, key: str, items: list[str]) -> None:
        """Replace a list in one step. `items` is newest-first, the same order as `lrange`."""
        with self._lock:
            self._values[key] = (None, list(items))


class RedisStore:
    """Upstash Redis over its REST API (`upstash-redis`)."""

    kind = "redis"

    def __init__(self, url: str, token: str):
        from upstash_redis import Redis

        self._redis = Redis(url=url, token=token, allow_telemetry=False, rest_retries=1)

    def get(self, key: str) -> str | None:
        value = self._redis.get(key)
        return None if value is None else str(value)

    def getdel(self, key: str) -> str | None:
        value = self._redis.getdel(key)
        return None if value is None else str(value)

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        self._redis.set(key, value, ex=ex)

    def delete(self, key: str) -> None:
        self._redis.delete(key)

    def hset(self, key: str, field: str, value: str) -> None:
        self._redis.hset(key, field, value)

    def hget(self, key: str, field: str) -> str | None:
        value = self._redis.hget(key, field)
        return None if value is None else str(value)

    def hgetall(self, key: str) -> dict[str, str]:
        return {str(k): str(v) for k, v in (self._redis.hgetall(key) or {}).items()}

    def hdel(self, key: str, field: str) -> None:
        self._redis.hdel(key, field)

    def lpush(self, key: str, value: str) -> None:
        self._redis.lpush(key, value)

    def ltrim(self, key: str, start: int, stop: int) -> None:
        self._redis.ltrim(key, start, stop)

    def lrange(self, key: str, start: int, stop: int) -> list[str]:
        return [str(v) for v in self._redis.lrange(key, start, stop) or []]

    def lrem(self, key: str, value: str) -> int:
        removed = self._redis.lrem(key, 0, value)
        return int(removed or 0)

    def swap(self, key: str, old: str, new: str) -> bool:
        return bool(self._redis.eval(_SWAP_SCRIPT, keys=[key], args=[old, new]))

    def hswap(self, key: str, field: str, old: str, new: str) -> bool:
        return bool(self._redis.eval(_HSWAP_SCRIPT, keys=[key], args=[field, old, new]))

    def lreplace(self, key: str, old: str, new: str) -> int:
        value = self._redis.eval(_LREPLACE_SCRIPT, keys=[key], args=[old, new])
        return int(value or 0)

    def ldrop_expired(self, key: str, now: int) -> int:
        """Remove expired or malformed inbox rows inside one script. New pushes stay."""
        value = self._redis.eval(_LDROP_EXPIRED_SCRIPT, keys=[key], args=[now])
        return int(value or 0)

    def incr(self, key: str, ex: int) -> int:
        """INCR and, on the first hit, EXPIRE. One script so the TTL cannot be skipped."""
        value = self._redis.eval(_INCR_SCRIPT, keys=[key], args=[ex])
        return int(value)

    def set_if_absent(self, key: str, value: str, ex: int) -> bool:
        """SET NX with a TTL. True only when this caller created the key."""
        result = self._redis.set(key, value, nx=True, ex=ex)
        return result is True or result == "OK"

    def replace_list(self, key: str, items: list[str]) -> None:
        """Replace a list in one Redis script so two copies cannot interleave item by item."""
        self._redis.eval(_REPLACE_LIST_SCRIPT, keys=[key], args=list(items))


# A fixed window, like Redis and MemoryStore: the expiry is set when the counter starts
# (a new row, an expired one, or one that did not hold a number) and kept on later hits,
# so steady traffic cannot keep pushing the window out.
_PG_INCR_SQL = """
INSERT INTO sdm_kv (key, value, expires_at)
VALUES (%s, '1', NOW() + (%s * INTERVAL '1 second'))
ON CONFLICT (key) DO UPDATE
SET value = (
    CASE
        WHEN sdm_kv.expires_at IS NOT NULL AND sdm_kv.expires_at <= NOW() THEN 1
        WHEN sdm_kv.value ~ '^[0-9]+$' THEN sdm_kv.value::bigint + 1
        ELSE 1
    END
)::text,
expires_at = (
    CASE
        WHEN sdm_kv.expires_at IS NOT NULL AND sdm_kv.expires_at <= NOW()
            THEN EXCLUDED.expires_at
        WHEN sdm_kv.value ~ '^[0-9]+$' THEN sdm_kv.expires_at
        ELSE EXCLUDED.expires_at
    END
)
RETURNING value
"""


class PostgresStore:
    """One short Postgres connection per call. No pool (serverless-friendly)."""

    kind = "postgres"

    def __init__(self, url: str):
        self._url = url
        self._ready = False
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return "PostgresStore(kind='postgres')"

    def _connect(self) -> Any:
        import psycopg

        # Neon’s pooled URL is PgBouncer in transaction mode, which rejects
        # psycopg’s automatic prepared statements.
        conn = psycopg.connect(
            self._url, autocommit=True, connect_timeout=5, prepare_threshold=None
        )
        self._ensure(conn)
        return conn

    def _ensure(self, conn: Any) -> None:
        if self._ready:
            return
        with self._lock:
            if self._ready:
                return
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sdm_kv (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    expires_at TIMESTAMPTZ
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sdm_hash (
                    key TEXT NOT NULL,
                    field TEXT NOT NULL,
                    value TEXT NOT NULL,
                    PRIMARY KEY (key, field)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sdm_list (
                    pos BIGSERIAL PRIMARY KEY,
                    key TEXT NOT NULL,
                    value TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS sdm_list_key_pos ON sdm_list (key, pos DESC)")
            self._ready = True

    def _run(self, fn: Callable[[Any], Any]) -> Any:
        with self._connect() as conn:
            return fn(conn)

    def get(self, key: str) -> str | None:
        def read(conn: Any) -> str | None:
            conn.execute(
                """
                DELETE FROM sdm_kv
                WHERE key = %s AND expires_at IS NOT NULL AND expires_at <= NOW()
                """,
                (key,),
            )
            found = conn.execute(
                """
                SELECT value FROM sdm_kv
                WHERE key = %s AND (expires_at IS NULL OR expires_at > NOW())
                """,
                (key,),
            ).fetchone()
            return None if found is None else str(found[0])

        return self._run(read)

    def getdel(self, key: str) -> str | None:
        def take(conn: Any) -> str | None:
            conn.execute(
                """
                DELETE FROM sdm_kv
                WHERE key = %s AND expires_at IS NOT NULL AND expires_at <= NOW()
                """,
                (key,),
            )
            row = conn.execute(
                """
                DELETE FROM sdm_kv
                WHERE key = %s AND (expires_at IS NULL OR expires_at > NOW())
                RETURNING value
                """,
                (key,),
            ).fetchone()
            return None if row is None else str(row[0])

        return self._run(take)

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        def write(conn: Any) -> None:
            if ex:
                conn.execute(
                    """
                    INSERT INTO sdm_kv (key, value, expires_at)
                    VALUES (%s, %s, NOW() + (%s * INTERVAL '1 second'))
                    ON CONFLICT (key) DO UPDATE
                    SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at
                    """,
                    (key, value, ex),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO sdm_kv (key, value, expires_at)
                    VALUES (%s, %s, NULL)
                    ON CONFLICT (key) DO UPDATE
                    SET value = EXCLUDED.value, expires_at = NULL
                    """,
                    (key, value),
                )

        self._run(write)

    def delete(self, key: str) -> None:
        def wipe(conn: Any) -> None:
            conn.execute("DELETE FROM sdm_kv WHERE key = %s", (key,))
            conn.execute("DELETE FROM sdm_hash WHERE key = %s", (key,))
            conn.execute("DELETE FROM sdm_list WHERE key = %s", (key,))

        self._run(wipe)

    def hset(self, key: str, field: str, value: str) -> None:
        def write(conn: Any) -> None:
            conn.execute(
                """
                INSERT INTO sdm_hash (key, field, value) VALUES (%s, %s, %s)
                ON CONFLICT (key, field) DO UPDATE SET value = EXCLUDED.value
                """,
                (key, field, value),
            )

        self._run(write)

    def swap(self, key: str, old: str, new: str) -> bool:
        def write(conn: Any) -> bool:
            row = conn.execute(
                """
                UPDATE sdm_kv SET value = %s
                WHERE key = %s AND value = %s AND (expires_at IS NULL OR expires_at > NOW())
                RETURNING 1
                """,
                (new, key, old),
            ).fetchone()
            return row is not None

        return bool(self._run(write))

    def hswap(self, key: str, field: str, old: str, new: str) -> bool:
        def write(conn: Any) -> bool:
            row = conn.execute(
                """
                UPDATE sdm_hash SET value = %s
                WHERE key = %s AND field = %s AND value = %s
                RETURNING 1
                """,
                (new, key, field, old),
            ).fetchone()
            return row is not None

        return bool(self._run(write))

    def hget(self, key: str, field: str) -> str | None:
        def read(conn: Any) -> str | None:
            row = conn.execute(
                "SELECT value FROM sdm_hash WHERE key = %s AND field = %s", (key, field)
            ).fetchone()
            return None if row is None else str(row[0])

        return self._run(read)

    def hgetall(self, key: str) -> dict[str, str]:
        def read(conn: Any) -> dict[str, str]:
            rows = conn.execute(
                "SELECT field, value FROM sdm_hash WHERE key = %s", (key,)
            ).fetchall()
            return {str(field): str(value) for field, value in rows}

        return self._run(read)

    def hdel(self, key: str, field: str) -> None:
        self._run(
            lambda conn: conn.execute(
                "DELETE FROM sdm_hash WHERE key = %s AND field = %s", (key, field)
            )
        )

    def lpush(self, key: str, value: str) -> None:
        self._run(
            lambda conn: conn.execute(
                "INSERT INTO sdm_list (key, value) VALUES (%s, %s)", (key, value)
            )
        )

    def ltrim(self, key: str, start: int, stop: int) -> None:
        def trim(conn: Any) -> None:
            if stop != -1 and stop < start:
                conn.execute("DELETE FROM sdm_list WHERE key = %s", (key,))
                return
            offset = max(start, 0)
            limit = 1_000_000 if stop == -1 else stop - offset + 1
            conn.execute(
                """
                DELETE FROM sdm_list WHERE key = %s AND pos NOT IN (
                    SELECT pos FROM sdm_list WHERE key = %s
                    ORDER BY pos DESC OFFSET %s LIMIT %s
                )
                """,
                (key, key, offset, limit),
            )

        self._run(trim)

    def lrange(self, key: str, start: int, stop: int) -> list[str]:
        def read(conn: Any) -> list[str]:
            if stop != -1 and stop < start:
                return []
            offset = max(start, 0)
            limit = 1_000_000 if stop == -1 else stop - offset + 1
            rows = conn.execute(
                """
                SELECT value FROM sdm_list WHERE key = %s
                ORDER BY pos DESC OFFSET %s LIMIT %s
                """,
                (key, offset, limit),
            ).fetchall()
            return [str(row[0]) for row in rows]

        return self._run(read)

    def lrem(self, key: str, value: str) -> int:
        def remove(conn: Any) -> int:
            result = conn.execute(
                "DELETE FROM sdm_list WHERE key = %s AND value = %s",
                (key, value),
            )
            return int(result.rowcount or 0)

        return int(self._run(remove))

    def lreplace(self, key: str, old: str, new: str) -> int:
        def swap(conn: Any) -> int:
            result = conn.execute(
                "UPDATE sdm_list SET value = %s WHERE key = %s AND value = %s",
                (new, key, old),
            )
            return int(result.rowcount or 0)

        return int(self._run(swap))

    def ldrop_expired(self, key: str, now: int) -> int:
        """Remove expired or malformed inbox rows. A row inserted concurrently stays."""

        def drop(conn: Any) -> int:
            malformed = conn.execute(
                """
                DELETE FROM sdm_list
                WHERE key = %s
                  AND value !~ '^[^|]+\\|[^|]+\\|[0-9]+\\|[0-9]+\\|[01]$'
                """,
                (key,),
            )
            expired = conn.execute(
                """
                DELETE FROM sdm_list
                WHERE key = %s
                  AND value ~ '^[^|]+\\|[^|]+\\|[0-9]+\\|[0-9]+\\|[01]$'
                  AND split_part(value, '|', 4)::bigint <= %s
                """,
                (key, now),
            )
            return int(malformed.rowcount or 0) + int(expired.rowcount or 0)

        return int(self._run(drop))

    def incr(self, key: str, ex: int) -> int:
        """Add one in a single statement. An expired row starts again at 1."""

        def bump(conn: Any) -> int:
            row = conn.execute(_PG_INCR_SQL, (key, ex)).fetchone()
            return int(row[0])

        return int(self._run(bump))

    def set_if_absent(self, key: str, value: str, ex: int) -> bool:
        """Insert a row only when the key is missing. An expired row is cleared first."""

        def claim(conn: Any) -> bool:
            with conn.transaction():
                conn.execute(
                    """
                    DELETE FROM sdm_kv
                    WHERE key = %s AND expires_at IS NOT NULL AND expires_at <= NOW()
                    """,
                    (key,),
                )
                row = conn.execute(
                    """
                    INSERT INTO sdm_kv (key, value, expires_at)
                    VALUES (%s, %s, NOW() + (%s * INTERVAL '1 second'))
                    ON CONFLICT (key) DO NOTHING
                    RETURNING key
                    """,
                    (key, value, ex),
                ).fetchone()
                return row is not None

        return bool(self._run(claim))

    def replace_list(self, key: str, items: list[str]) -> None:
        """Delete and rewrite a list in one transaction. `items` is newest-first."""

        def write(conn: Any) -> None:
            with conn.transaction():
                conn.execute("DELETE FROM sdm_list WHERE key = %s", (key,))
                for item in reversed(items):
                    conn.execute(
                        "INSERT INTO sdm_list (key, value) VALUES (%s, %s)",
                        (key, item),
                    )

        self._run(write)

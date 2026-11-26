"""One contract for every key-value backend: MemoryStore, PostgresStore and RedisStore.

Production runs on Postgres or Upstash Redis, while the rest of the suite runs on
MemoryStore. These tests pin the behaviour the app relies on, so the three cannot drift
apart: the hand-written SQL and the Lua scripts run against real servers.

Real servers are opt-in (CI starts them as services):
  TEST_DATABASE_URL=postgresql://postgres@127.0.0.1:5432/postgres
  TEST_REDIS_URL=redis://127.0.0.1:6379
Without them only MemoryStore runs. Upstash speaks REST, not the Redis protocol, so a
small RESP client stands in for the `upstash_redis.Redis` object inside RedisStore; the
scripts and commands RedisStore sends are unchanged.
"""

import os
import socket
import time
import uuid
from urllib.parse import urlparse

import pytest

from scoped_drive_mcp.store import MemoryStore, PostgresStore, RedisStore
from scoped_drive_mcp.store import backends as store_module
from tests.conftest import FakeClock

DATABASE_URL = os.environ.get("TEST_DATABASE_URL")
REDIS_URL = os.environ.get("TEST_REDIS_URL")


class Resp:
    """Just enough of a Redis client, with the upstash_redis call shapes RedisStore uses."""

    def __init__(self, url: str) -> None:
        parsed = urlparse(url)
        self._sock = socket.create_connection((parsed.hostname, parsed.port or 6379), timeout=5)
        self._file = self._sock.makefile("rb")

    def _call(self, *args: object):
        out = [f"*{len(args)}\r\n".encode()]
        for arg in args:
            data = str(arg).encode()
            out.append(b"$%d\r\n%s\r\n" % (len(data), data))
        self._sock.sendall(b"".join(out))
        return self._read()

    def _read(self):
        line = self._file.readline()
        kind, rest = line[:1], line[1:-2]
        if kind == b"+":
            return rest.decode()
        if kind == b"-":
            raise RuntimeError(rest.decode())
        if kind == b":":
            return int(rest)
        if kind == b"$":
            if rest == b"-1":
                return None
            data = self._file.read(int(rest) + 2)[:-2]
            return data.decode()
        if kind == b"*":
            return None if rest == b"-1" else [self._read() for _ in range(int(rest))]
        raise RuntimeError(f"unexpected reply {line!r}")

    def __getattr__(self, name: str):
        return lambda *args: self._call(name.upper(), *args)

    def set(self, key, value, ex=None, nx=False):
        args = [key, value] + (["EX", ex] if ex else []) + (["NX"] if nx else [])
        return self._call("SET", *args)

    def delete(self, key):
        return self._call("DEL", key)

    def hgetall(self, key):
        flat = self._call("HGETALL", key)
        return dict(zip(flat[::2], flat[1::2], strict=True))

    def eval(self, script, keys, args):
        return self._call("EVAL", script, len(keys), *keys, *args)

    def close(self) -> None:
        self._file.close()
        self._sock.close()


class Backend:
    def __init__(self, store, wait) -> None:
        self.store = store
        self.wait = wait  # let `seconds` pass for expiry
        self.ns = f"t{uuid.uuid4().hex[:12]}:"  # keys never collide between tests

    def k(self, name: str) -> str:
        return self.ns + name


@pytest.fixture(scope="module")
def pg_store():
    if not DATABASE_URL:
        pytest.skip("TEST_DATABASE_URL is not set")
    return PostgresStore(DATABASE_URL)


@pytest.fixture(scope="module")
def redis_store():
    if not REDIS_URL:
        pytest.skip("TEST_REDIS_URL is not set")
    store = RedisStore.__new__(RedisStore)
    store._redis = Resp(REDIS_URL)
    yield store
    store._redis.close()


@pytest.fixture(params=["memory", "postgres", "redis"])
def b(request) -> Backend:
    if request.param == "memory":
        clock = FakeClock()
        return Backend(MemoryStore(clock=clock), clock.advance)
    store = request.getfixturevalue(f"{'pg' if request.param == 'postgres' else 'redis'}_store")
    return Backend(store, lambda seconds: time.sleep(seconds + 0.2))


def test_strings(b: Backend) -> None:
    s, key = b.store, b.k("s")
    assert s.get(key) is None and s.getdel(key) is None
    s.set(key, "one")
    s.set(key, "two")
    assert s.get(key) == "two"
    assert s.getdel(key) == "two" and s.get(key) is None
    s.set(key, "x")
    s.delete(key)
    assert s.get(key) is None


def test_compare_and_swap(b: Backend) -> None:
    s, key, h = b.store, b.k("cas"), b.k("h")
    assert s.swap(key, "a", "b") is False and s.get(key) is None
    s.set(key, "a")
    assert s.swap(key, "zzz", "b") is False and s.get(key) == "a"
    assert s.swap(key, "a", "b") is True and s.get(key) == "b"

    assert s.hswap(h, "f", "a", "b") is False and s.hget(h, "f") is None
    s.hset(h, "f", "a")
    assert s.hswap(h, "f", "zzz", "b") is False
    assert s.hswap(h, "f", "a", "b") is True and s.hget(h, "f") == "b"


def test_hashes(b: Backend) -> None:
    s, h = b.store, b.k("h")
    assert s.hgetall(h) == {} and s.hget(h, "a") is None
    s.hset(h, "a", "1")
    s.hset(h, "b", "2")
    s.hset(h, "a", "3")
    assert s.hgetall(h) == {"a": "3", "b": "2"}
    s.hdel(h, "a")
    s.hdel(h, "missing")
    assert s.hgetall(h) == {"b": "2"}
    s.delete(h)
    assert s.hgetall(h) == {}


def test_lists_are_newest_first(b: Backend) -> None:
    s, key = b.store, b.k("l")
    assert s.lrange(key, 0, -1) == []
    for value in ("a", "b", "c", "b", "d"):
        s.lpush(key, value)
    assert s.lrange(key, 0, -1) == ["d", "b", "c", "b", "a"]
    assert s.lrange(key, 1, 2) == ["b", "c"]
    assert s.lrange(key, 0, 99) == ["d", "b", "c", "b", "a"]
    assert s.lrange(key, 3, 1) == []

    assert s.lreplace(key, "b", "B") == 2 and s.lreplace(key, "nope", "x") == 0
    assert s.lrange(key, 0, -1) == ["d", "B", "c", "B", "a"]  # in place, order kept
    assert s.lrem(key, "B") == 2 and s.lrem(key, "nope") == 0
    assert s.lrange(key, 0, -1) == ["d", "c", "a"]

    s.ltrim(key, 0, 1)  # keep the newest two, as the capped activity lists do
    assert s.lrange(key, 0, -1) == ["d", "c"]
    s.ltrim(key, 0, 99)
    assert s.lrange(key, 0, -1) == ["d", "c"]
    s.lpush(key, "e")
    assert s.lrange(key, 0, 0) == ["e"]
    s.delete(key)
    assert s.lrange(key, 0, -1) == []


def test_replace_list(b: Backend) -> None:
    s, key = b.store, b.k("rl")
    s.lpush(key, "old")
    s.replace_list(key, ["new3", "new2", "new1"])  # newest-first, like lrange
    assert s.lrange(key, 0, -1) == ["new3", "new2", "new1"]
    s.lpush(key, "new4")
    assert s.lrange(key, 0, 0) == ["new4"]
    s.replace_list(key, [])
    assert s.lrange(key, 0, -1) == []


def test_drop_expired_inbox_rows(b: Backend) -> None:
    s, key, now = b.store, b.k("inbox"), 1_000_000
    rows = [
        f"m1|L1|1|{now + 60}|1",  # live
        f"m2|L1|1|{now}|0",  # expires exactly now: gone
        f"m3|L1|1|{now - 1}|1",  # expired
        "not-a-row",
        f"m4|L1|1|{now + 60}|2",  # bad unread flag
        f"m5|L1|x|{now + 60}|1",  # bad created time
        f"m6|L1|1|{now + 99}|0",  # live
    ]
    s.replace_list(key, rows)
    assert s.ldrop_expired(key, now) == 5
    assert s.lrange(key, 0, -1) == [rows[0], rows[6]]
    assert s.ldrop_expired(key, now) == 0
    assert s.ldrop_expired(b.k("missing"), now) == 0


def test_set_if_absent_claims_once(b: Backend) -> None:
    s, key = b.store, b.k("claim")
    assert s.set_if_absent(key, "first", ex=60) is True
    assert s.set_if_absent(key, "second", ex=60) is False
    assert s.get(key) == "first"
    # The longest TTL the app uses (ten years, mcp_oauth._FOR_GOOD) must be accepted.
    assert s.set_if_absent(b.k("forever"), "1", ex=10 * 365 * 24 * 3600) is True


def test_incr_counts(b: Backend) -> None:
    s, key = b.store, b.k("n")
    assert [s.incr(key, 60) for _ in range(3)] == [1, 2, 3]
    assert s.get(key) == "3"
    assert s.incr(b.k("other"), 60) == 1


def test_expiry(b: Backend) -> None:
    """Everything with a TTL, behind one wait so the real servers cost one second."""
    s = b.store
    s.set(b.k("ttl"), "v", ex=1)
    s.set(b.k("cleared"), "v", ex=1)
    s.set(b.k("cleared"), "v2")  # a plain set drops the earlier TTL
    s.set(b.k("swapped"), "a", ex=1)
    assert s.swap(b.k("swapped"), "a", "b") is True  # a swap keeps the TTL
    s.set(b.k("taken"), "v", ex=1)
    assert s.set_if_absent(b.k("claim"), "1", ex=1) is True
    assert s.incr(b.k("window"), 1) == 1
    assert s.incr(b.k("window"), 1) == 2  # later hits do not push the window out
    s.set(b.k("forever"), "v")

    b.wait(1)

    assert s.get(b.k("ttl")) is None
    assert s.getdel(b.k("taken")) is None
    assert s.get(b.k("cleared")) == "v2"
    assert s.get(b.k("swapped")) is None
    assert s.swap(b.k("swapped"), "b", "c") is False
    assert s.set_if_absent(b.k("claim"), "2", ex=60) is True and s.get(b.k("claim")) == "2"
    assert s.incr(b.k("window"), 60) == 1  # a fresh window starts again at one
    assert s.get(b.k("forever")) == "v"


# ---- Postgres only: connections are reused, and expired rows are swept ----


def test_postgres_reuses_a_fresh_connection(pg_store, monkeypatch) -> None:
    import psycopg

    opened: list[object] = []
    real = psycopg.connect

    def counting(*args, **kwargs):
        conn = real(*args, **kwargs)
        opened.append(conn)
        return conn

    monkeypatch.setattr(psycopg, "connect", counting)
    pg_store.close()
    key = f"t{uuid.uuid4().hex[:12]}:reuse"
    for n in range(10):
        pg_store.set(key, str(n))
        assert pg_store.get(key) == str(n)
    pg_store.incr(key + ":n", 60)
    assert len(opened) == 1

    # One left idle for too long is replaced, not trusted.
    monkeypatch.setattr(store_module, "PG_IDLE_SECONDS", -1.0)
    assert pg_store.get(key) == "9"
    assert len(opened) == 2 and opened[0].closed


def test_postgres_resends_a_read_whose_pooled_connection_died(pg_store) -> None:
    """A pooler can close an idle connection sooner than we stop trusting it."""
    import psycopg

    key = f"t{uuid.uuid4().hex[:12]}:dead"
    pg_store.close()
    pg_store.set(key, "v")
    # Kill the pooled connection the way a pooler does: from the server's side.
    ((conn, _),) = pg_store._idle
    pid = conn.info.backend_pid
    with psycopg.connect(DATABASE_URL, autocommit=True) as other:
        other.execute("SELECT pg_terminate_backend(%s)", (pid,))
    time.sleep(0.2)
    assert pg_store.get(key) == "v"

    # A write is not resent: its answer being lost does not mean it did not run.
    ((conn, _),) = pg_store._idle
    with psycopg.connect(DATABASE_URL, autocommit=True) as other:
        other.execute("SELECT pg_terminate_backend(%s)", (conn.info.backend_pid,))
    time.sleep(0.2)
    with pytest.raises(psycopg.OperationalError):
        pg_store.set(key, "again")
    assert pg_store.get(key) == "v"


def test_postgres_drops_a_connection_after_a_failed_statement(pg_store, monkeypatch) -> None:
    import psycopg

    pg_store.close()
    with pytest.raises(psycopg.Error):
        pg_store._run(lambda conn: conn.execute("SELECT * FROM no_such_table_here"))
    assert pg_store._idle == []
    key = f"t{uuid.uuid4().hex[:12]}:after"
    pg_store.set(key, "ok")
    assert pg_store.get(key) == "ok"


def test_postgres_sweeps_expired_rows_nobody_reads_again(pg_store) -> None:
    ns = f"t{uuid.uuid4().hex[:12]}:"
    for n in range(5):
        pg_store.set(f"{ns}gone{n}", "x", ex=1)
    pg_store.set(f"{ns}kept", "x", ex=600)
    pg_store.set(f"{ns}forever", "x")

    def rows() -> int:
        return pg_store._run(
            lambda conn: conn.execute(
                "SELECT COUNT(*) FROM sdm_kv WHERE key LIKE %s", (ns + "%",)
            ).fetchone()[0]
        )

    assert rows() == 7
    time.sleep(1.3)
    # Reading does not delete (one statement per read); the sweep does, in batches.
    assert pg_store.get(f"{ns}gone0") is None and rows() == 7
    removed = 0
    while (batch := pg_store.sweep_expired(batch=2)) > 0:
        removed += batch
    assert removed >= 5 and rows() == 2
    assert pg_store.sweep_all() == 0
    assert pg_store.get(f"{ns}kept") == "x" and pg_store.get(f"{ns}forever") == "x"

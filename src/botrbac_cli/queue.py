"""Audit rows kept on this computer until the website has them (SQLite).

Rows hold identifiers and decisions only: never tool arguments or results.
"""

import functools
import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from . import state

SEND_BATCH = 500
KEEP_SENT = 5000


def _locked(method):
    """Run under the queue's lock: one statement sequence at a time on the connection."""

    @functools.wraps(method)
    def run(self: "AuditQueue", *args: Any, **kwargs: Any) -> Any:
        with self._lock:
            return method(self, *args, **kwargs)

    return run


class AuditQueue:
    """One connection, shared by the gateway's event loop (which adds rows) and the
    worker thread that syncs them (asyncio.to_thread), hence check_same_thread=False
    and a lock around every use. The lock is not re-entrant: a locked method must not
    call another one."""

    def __init__(self, path: Path | None = None):
        self.path = path or state.home() / "audit.db"
        self._lock = threading.Lock()
        self.db = sqlite3.connect(
            self.path, timeout=10, isolation_level=None, check_same_thread=False
        )
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS rows ("
            " event_id TEXT PRIMARY KEY, ts REAL NOT NULL, body TEXT NOT NULL,"
            " sent INTEGER NOT NULL DEFAULT 0)"
        )

    @_locked
    def add(self, **fields: Any) -> dict[str, Any]:
        row = {"event_id": uuid.uuid4().hex, "ts": time.time(), **fields}
        self.db.execute(
            "INSERT INTO rows (event_id, ts, body) VALUES (?, ?, ?)",
            (row["event_id"], row["ts"], json.dumps(row)),
        )
        return row

    @_locked
    def pending(self, limit: int = SEND_BATCH) -> list[dict[str, Any]]:
        cur = self.db.execute("SELECT body FROM rows WHERE sent = 0 ORDER BY ts LIMIT ?", (limit,))
        return [json.loads(body) for (body,) in cur.fetchall()]

    @_locked
    def mark_sent(self, event_ids: list[str]) -> None:
        self.db.executemany(
            "UPDATE rows SET sent = 1 WHERE event_id = ?", [(e,) for e in event_ids]
        )
        # Keep a local history for `botrbac log`, but not forever.
        self.db.execute(
            "DELETE FROM rows WHERE sent = 1 AND event_id NOT IN "
            "(SELECT event_id FROM rows WHERE sent = 1 ORDER BY ts DESC LIMIT ?)",
            (KEEP_SENT,),
        )

    @_locked
    def mark_rejected(self, event_ids: list[str]) -> None:
        """Rows the server refused one by one. Kept here (state 2), never deleted, so
        `botrbac log` shows them and `botrbac sync --retry-rejected` can send them again."""
        self.db.executemany(
            "UPDATE rows SET sent = 2 WHERE event_id = ?", [(e,) for e in event_ids]
        )

    @_locked
    def rejected(self) -> int:
        return int(self.db.execute("SELECT COUNT(*) FROM rows WHERE sent = 2").fetchone()[0])

    @_locked
    def requeue_rejected(self) -> int:
        return self.db.execute("UPDATE rows SET sent = 0 WHERE sent = 2").rowcount

    @_locked
    def waiting(self) -> int:
        return int(self.db.execute("SELECT COUNT(*) FROM rows WHERE sent = 0").fetchone()[0])

    @_locked
    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        cur = self.db.execute("SELECT body, sent FROM rows ORDER BY ts DESC LIMIT ?", (limit,))
        status = {0: "waiting", 1: "sent", 2: "rejected"}
        return [
            {**json.loads(body), "sent": sent == 1, "status": status.get(sent, "waiting")}
            for body, sent in cur.fetchall()
        ]

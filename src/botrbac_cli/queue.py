"""Audit rows kept on this computer until the website has them (SQLite).

Rows hold identifiers and decisions. With "Record commands" on, a row also holds what
the agent ran, sealed to the website's key (sealing.py): this file never has it as text.
Tool results are never kept.
"""

import contextlib
import functools
import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from . import chain, identity, policy, provenance, sealing, state

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
        self._chain_setup()

    def add(
        self,
        command: str | None = None,
        sealed: dict[str, str | None] | None = None,
        **fields: Any,
    ) -> dict[str, Any]:
        """Queue a row. `command` (what the agent ran) is kept only sealed to the
        website's key, and only when the person turned on "Record commands"; it is
        never written to this file as text. With it go `input_digest` and `input_size`
        of the whole command, before sealing cuts it.

        `sealed` holds other text fields ({"description": ..., "task": ...}), sealed
        the same way with `event_id:<name>` as associated data, so one cannot be moved
        onto another row or another field. Without the key they are dropped."""
        row = {"event_id": uuid.uuid4().hex, "ts": time.time(), **fields}
        version = identity.policy_version()  # goes into the row's `grant` on the site
        if version and "policy_version" not in row:
            row["policy_version"] = version
        extras = {k: v for k, v in (sealed or {}).items() if v is not None}
        if command is None and not extras:
            return self._insert(row)
        # Recording must never cost the row: if the key or the sealing fails, the row
        # is kept without the text, marked so the owner sees some is missing.
        try:
            key = policy.command_key()
        except Exception as exc:  # noqa: BLE001
            key = None
            if command is not None:
                row["command_error"] = type(exc).__name__
        if key and command is not None:
            try:
                text = str(command)
                row["command"] = sealing.seal(key, row["event_id"], text)
                row.update(provenance.input_digest(text))
            except Exception as exc:  # noqa: BLE001
                for name in ("command", "input_digest", "input_size"):
                    row.pop(name, None)
                row["command_error"] = type(exc).__name__
        if key:
            for name, value in extras.items():
                try:
                    row[name] = sealing.seal(key, f"{row['event_id']}:{name}", str(value))
                except Exception:  # noqa: BLE001 - the row matters more than the text
                    row.pop(name, None)
        return self._insert(row)

    @_locked
    def _insert(self, row: dict[str, Any]) -> dict[str, Any]:
        # The hash chain (chain.py) is the last step: every field is in the row by now.
        # BEGIN IMMEDIATE takes SQLite's write lock, so gateways and hooks running in
        # other processes never get the same seq.
        self.db.execute("BEGIN IMMEDIATE")
        try:
            seq, prev = self._chain_tip()
            chain.link(row, seq + 1, prev)
            self.db.execute(
                "INSERT INTO rows (event_id, ts, body, seq) VALUES (?, ?, ?, ?)",
                (row["event_id"], row["ts"], json.dumps(row), row["seq"]),
            )
            self.db.executemany(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                [("seq", str(row["seq"])), ("last_hash", row["row_hash"])],
            )
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        return row

    # ---- hash chain (chain.py) -----------------------------------------------------

    def _chain_setup(self) -> None:
        """The meta table holds the chain's tip. A queue from before the chain starts
        at seq 1; its older rows stay unchained."""
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        columns = {c[1] for c in self.db.execute("PRAGMA table_info(rows)").fetchall()}
        if "seq" not in columns:
            # Another process may have added it first.
            with contextlib.suppress(sqlite3.OperationalError):
                self.db.execute("ALTER TABLE rows ADD COLUMN seq INTEGER")

    def _meta(self, key: str) -> str | None:
        found = self.db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return found[0] if found else None

    def _chain_tip(self) -> tuple[int, str]:
        return int(self._meta("seq") or 0), self._meta("last_hash") or chain.GENESIS

    @_locked
    def chain_rows(self) -> tuple[list[dict[str, Any]], int, int]:
        """Every chained row kept here, in seq order; the highest seq pruned from this
        file once the website had it (rows up to it may be missing); and the newest seq
        given out."""
        cur = self.db.execute("SELECT body FROM rows WHERE seq IS NOT NULL ORDER BY seq, ts")
        rows = [json.loads(body) for (body,) in cur.fetchall()]
        return rows, int(self._meta("pruned_through") or 0), self._chain_tip()[0]

    @_locked
    def pending(self, limit: int = SEND_BATCH) -> list[dict[str, Any]]:
        cur = self.db.execute(
            "SELECT body FROM rows WHERE sent = 0 ORDER BY COALESCE(seq, 0), ts LIMIT ?", (limit,)
        )
        return [json.loads(body) for (body,) in cur.fetchall()]

    @_locked
    def mark_sent(self, event_ids: list[str]) -> None:
        self.db.executemany(
            "UPDATE rows SET sent = 1 WHERE event_id = ?", [(e,) for e in event_ids]
        )
        # Keep a local history for `botrbac log`, but not forever.
        (cut,) = self.db.execute(
            "SELECT MAX(seq) FROM rows WHERE sent = 1 AND event_id NOT IN "
            "(SELECT event_id FROM rows WHERE sent = 1 ORDER BY ts DESC LIMIT ?)",
            (KEEP_SENT,),
        ).fetchone()
        if cut is not None and int(cut) > int(self._meta("pruned_through") or 0):
            # `botrbac verify` expects rows up to here to be gone.
            self.db.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('pruned_through', ?)",
                (str(cut),),
            )
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

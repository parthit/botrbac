"""Audit rows sent by terminals, and the sessions they describe.

The CLI keeps rows on the computer and sends them when it can. Each row has a client
`event_id`, so a batch sent twice is stored once. Rows hold identifiers and decisions
only (never tool arguments or file contents), and every field is capped here too.
"""

import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from botrbac_cli.patterns import is_tool_id

ACTIVITY_KEY = "term:activity:{email}"
SEEN_KEY = "term:seen:{email}:{event_id}"
REVOKED_KEY = "term:revoked:{email}"
ACTIVITY_MAX = 2000
BATCH_MAX = 500
SEEN_TTL = 30 * 24 * 3600
DECISIONS = frozenset({"allow", "deny", "error", "session"})
_ID = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
_WORD = re.compile(r"[^A-Za-z0-9_.:/@ -]+")


class IngestError(ValueError):
    pass


def _word(value: Any, limit: int) -> str:
    return _WORD.sub("", str(value or ""))[:limit].strip()


# How far ahead of the server's clock a terminal's clock may be.
CLOCK_SKEW = 300


def _ts(value: Any, now: float) -> float | None:
    """When it happened on the computer. A time in the future is not believed (it would
    pin the row to the top of the log), so it becomes the time it arrived."""
    try:
        ts = float(value)
    except (TypeError, ValueError):
        return None
    if not 1_500_000_000 < ts <= now + CLOCK_SKEW:
        return None
    return ts


def clean_row(raw: Any, now: float) -> dict[str, Any] | None:
    """A stored row, or None for one that is not worth keeping."""
    if not isinstance(raw, dict):
        return None
    event_id = str(raw.get("event_id") or "")
    decision = str(raw.get("decision") or "")
    if not _ID.match(event_id) or decision not in DECISIONS:
        return None
    tool = str(raw.get("tool") or "")
    if decision != "session" and not is_tool_id(tool):
        return None
    row: dict[str, Any] = {
        "event_id": event_id,
        "ts": _ts(raw.get("ts"), now) or now,
        "decision": decision,
        "tool": tool[:200] if decision != "session" else "",
        "agent": _word(raw.get("agent"), 40),
        "reason": _word(raw.get("reason"), 300),
        "role": _word(raw.get("role"), 64),
        "via": "hook" if raw.get("via") == "hook" else "gateway",
    }
    for key in ("session_id", "parent_session_id"):
        value = str(raw.get(key) or "")
        if _ID.match(value):
            row[key] = value
    if decision == "session":
        # Only the program's name: arguments can hold secrets.
        words = str(raw.get("program") or "").split()
        row["program"] = _word(words[0].rsplit("/", 1)[-1], 40) if words else ""
        if "session_id" not in row:
            return None
    return row


@dataclass
class TerminalActivity:
    store: Any
    clock: Callable[[], float] = field(default=time.time)

    def add(self, email: str, terminal_id: str, terminal_name: str, rows: Any) -> dict[str, int]:
        if not isinstance(rows, list):
            raise IngestError("rows must be a list")
        if len(rows) > BATCH_MAX:
            raise IngestError(f"at most {BATCH_MAX} rows per batch")
        now = self.clock()
        accepted = duplicates = rejected = 0
        key = ACTIVITY_KEY.format(email=email)
        for raw in rows:
            row = clean_row(raw, now)
            if row is None:
                rejected += 1
                continue
            seen = SEEN_KEY.format(email=email, event_id=row["event_id"])
            if not self.store.set_if_absent(seen, "1", ex=SEEN_TTL):
                duplicates += 1
                continue
            row.update(terminal_id=terminal_id, terminal=terminal_name[:80], received=now)
            try:
                self.store.lpush(key, json.dumps(row, separators=(",", ":")))
            except Exception:
                # Not stored: forget the id so the terminal's retry is not taken for a
                # duplicate and dropped.
                self.store.delete(seen)
                raise
            accepted += 1
        if accepted:
            self.store.ltrim(key, 0, ACTIVITY_MAX - 1)
        return {"accepted": accepted, "duplicates": duplicates, "rejected": rejected}

    def recent(self, email: str, limit: int = ACTIVITY_MAX) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for raw in self.store.lrange(ACTIVITY_KEY.format(email=email), 0, limit - 1):
            try:
                out.append(json.loads(raw))
            except ValueError:
                continue
        # Newest by when it happened on the computer, not when it arrived.
        out.sort(key=lambda r: r.get("ts") or 0, reverse=True)
        return out

    # ---- sessions -----------------------------------------------------------------

    def revoke_session(self, email: str, session_id: str) -> bool:
        if not _ID.match(session_id):
            return False
        self.store.hset(REVOKED_KEY.format(email=email), session_id, str(int(self.clock())))
        return True

    def revoked_sessions(self, email: str) -> list[str]:
        return sorted(self.store.hgetall(REVOKED_KEY.format(email=email)))

    def session(self, email: str, session_id: str) -> dict[str, Any] | None:
        """One session and everything started under it, built from the activity rows."""
        rows = self.recent(email)
        starts = {r["session_id"]: r for r in rows if r["decision"] == "session"}
        if session_id not in starts:
            return None
        revoked = set(self.revoked_sessions(email))
        children: dict[str, list[str]] = {}
        for sid, start in starts.items():
            parent = start.get("parent_session_id")
            if parent:
                children.setdefault(parent, []).append(sid)

        def node(sid: str, depth: int) -> dict[str, Any]:
            calls = [r for r in rows if r.get("session_id") == sid and r["decision"] != "session"]
            return {
                "start": starts[sid],
                "calls": len(calls),
                "blocked": [r for r in calls if r["decision"] == "deny"],
                "revoked": sid in revoked,
                "children": [node(c, depth + 1) for c in sorted(children.get(sid, []))]
                if depth < 10
                else [],
            }

        return node(session_id, 0)

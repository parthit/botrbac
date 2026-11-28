"""Audit rows sent by terminals, and the sessions they describe.

The CLI keeps rows on the computer and sends them when it can. Each row has a client
`event_id`, so a batch sent twice is stored once. Rows hold identifiers and decisions,
and every field is capped here too. When the person turns on "Record commands", a row
can also carry what the agent ran, sealed on the computer to the website's key
(botrbac_cli.sealing). It is stored sealed and opened only to show it to its owner.
Tool results and file contents read are never sent.
"""

import contextlib
import json
import logging
import re
import secrets
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

from botrbac_cli import sealing
from botrbac_cli.patterns import is_tool_id

from . import integrity, provenance

ACTIVITY_KEY = "term:activity:{email}"
SEEN_KEY = "term:seen:{email}:{event_id}"
# Blocked rows are kept in a list of their own as well, so a flood of allowed rows from
# one terminal cannot push every block out of the log (see `recent` and `everything`).
DENIES_KEY = "term:denies:{email}"
# Rows stored from one terminal per UTC day (TERMINAL_ACTIVITY_ROWS_PER_DAY). Past it,
# its uploads get 429 and the rows wait on the computer until the next day.
BUDGET_KEY = "term:rowbudget:{terminal_id}:{day}"
ROWS_PER_DAY = 10_000
# One upload at a time per terminal: the chain state is read, judged and written back.
LOCK_KEY = "term:lock:{terminal_id}"
LOCK_TTL = 60
LOCK_TRIES = 10
LOCK_WAIT = 0.1
REVOKED_KEY = "term:revoked:{email}"
SETTINGS_KEY = "term:settings:{email}"
# The most rows the Activity page reads at once. Exports read everything kept.
ACTIVITY_MAX = 2000
# The Activity page: rows per page, and at most how many rows one page request reads
# from the store (in chunks) looking for rows that match its filters.
PAGE_ROWS = 100
PAGE_SCAN = 5000
PAGE_CHUNK = 500
# How long rows are kept (TERMINAL_ACTIVITY_DAYS), and a hard cap on how many
# (TERMINAL_ACTIVITY_MAX_ROWS), whichever comes first.
RETENTION_DAYS = 180
RETENTION_MAX_ROWS = 20_000
TRIM_KEY = "term:trimmed:{email}"
TRIM_EVERY = 3600
BATCH_MAX = 500
SEEN_TTL = 30 * 24 * 3600
# `prompt` (UserPromptSubmit, no tool) and `result` (a finished call) come from hooks.
DECISIONS = frozenset({"allow", "deny", "error", "session", "prompt", "result"})
NO_TOOL = frozenset({"session", "prompt"})
CALLS = frozenset({"allow", "deny", "error"})
# Always used with fullmatch: `$` would also accept a trailing newline.
_ID = re.compile(r"[A-Za-z0-9_-]{8,64}")
# Commas and apostrophes stay: role names have them ("Coding, limited shell"), and a
# reason lists programs as "cmd/curl, cmd/wget". The page and exports escape them.
_WORD = re.compile(r"[^A-Za-z0-9_.:/@ ,'-]+")
# A reason may also list programs ("running cmd/curl, cmd/wget is not in role ...") and
# name what botrbac cannot check ("command substitution $(…)", "<(…)").
_REASON = re.compile(r"[^A-Za-z0-9_.:/@ ,'$()\u2026-]+")
_POLICY_VERSION = re.compile(r"[A-Za-z0-9]{1,32}")


def is_id(value: Any) -> bool:
    """A well-formed event or session id."""
    return isinstance(value, str) and _ID.fullmatch(value) is not None


class IngestError(ValueError):
    pass


class Busy(Exception):
    """Another upload from this terminal is being stored: send again shortly."""


class OverBudget(Exception):
    """This terminal stored its rows for the day. `retry_after` is seconds until the
    next UTC day."""

    def __init__(self, retry_after: int):
        super().__init__("over the daily row budget")
        self.retry_after = retry_after


def _word(value: Any, limit: int) -> str:
    return _WORD.sub("", str(value or ""))[:limit].strip()


def _reason(value: Any, limit: int) -> str:
    return _REASON.sub("", str(value or ""))[:limit].strip()


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


def clean_row(raw: Any, now: float, command_key: Any = None) -> dict[str, Any] | None:
    """A stored row, or None for one that is not worth keeping. A sealed command is
    kept only with `command_key` (recording is on) and only if it opens with it for
    this row; otherwise the row is kept without it."""
    if not isinstance(raw, dict):
        return None
    event_id = str(raw.get("event_id") or "")
    decision = str(raw.get("decision") or "")
    if not is_id(event_id) or decision not in DECISIONS:
        return None
    tool = str(raw.get("tool") or "")
    if decision not in NO_TOOL and not is_tool_id(tool):
        return None
    row: dict[str, Any] = {
        "event_id": event_id,
        "ts": _ts(raw.get("ts"), now) or now,
        "decision": decision,
        "tool": tool[:200] if decision not in NO_TOOL else "",
        "agent": _word(raw.get("agent"), 40),
        "reason": _reason(raw.get("reason"), 300),
        "role": _word(raw.get("role"), 64),
        "via": "hook" if raw.get("via") == "hook" else "gateway",
    }
    for key in ("session_id", "parent_session_id"):
        value = str(raw.get(key) or "")
        if is_id(value):
            row[key] = value
    # Stream C: the version of the policy the CLI decided under (it goes into `grant`).
    version = str(raw.get("policy_version") or "")
    if _POLICY_VERSION.fullmatch(version):
        row["policy_version"] = version
    command = raw.get("command")
    if command_key is not None and isinstance(command, str):
        try:
            sealing.open_sealed(command_key, event_id, command)
        except sealing.SealError:
            pass
        else:
            row["command"] = command
    row.update(provenance.clean_fields(raw, event_id, decision, command_key))
    if command_key is not None and raw.get("command_error") and "command" not in row:
        # The computer could not seal this one: say so, without any of the command.
        row["command_error"] = _word(raw.get("command_error"), 40) or "error"
    if decision == "session":
        # In the clear, only the program's name: arguments can hold secrets. The whole
        # command line is in the sealed `command` when recording is on.
        words = str(raw.get("program") or "").split()
        row["program"] = _word(words[0].rsplit("/", 1)[-1], 40) if words else ""
        if "session_id" not in row:
            return None
    return row


@dataclass
class TerminalActivity:
    store: Any
    clock: Callable[[], float] = field(default=time.time)
    retention_days: int = RETENTION_DAYS
    max_rows: int = RETENTION_MAX_ROWS
    # TERMINAL_ACTIVITY_ROWS_PER_DAY: rows stored from one terminal per UTC day.
    rows_per_day: int = ROWS_PER_DAY
    sleep: Callable[[float], None] = field(default=time.sleep)
    chains: integrity.Chains = field(init=False)

    def __post_init__(self) -> None:
        self.chains = integrity.Chains(self.store, ttl=self.retention_days * 24 * 3600)

    def cutoff(self) -> float:
        return self.clock() - self.retention_days * 24 * 3600

    # ---- one upload at a time per terminal ----------------------------------------

    @contextlib.contextmanager
    def _locked(self, terminal_id: str) -> Iterator[None]:
        """The chain state is read, judged and written back for each upload, so two
        uploads from one terminal at once would undo each other's work. A lock with an
        expiry (SET NX EX), waited on briefly; then Busy, which the CLI takes as a
        temporary failure and sends again at its next sync."""
        key = LOCK_KEY.format(terminal_id=terminal_id)
        token = secrets.token_hex(8)
        for attempt in range(LOCK_TRIES):
            if self.store.set_if_absent(key, token, ex=LOCK_TTL):
                break
            if attempt < LOCK_TRIES - 1:
                self.sleep(LOCK_WAIT)
        else:
            raise Busy("another upload from this terminal is in progress")
        try:
            yield
        finally:
            try:
                if self.store.get(key) == token:
                    self.store.delete(key)
            except Exception:  # noqa: BLE001 - it expires on its own
                logging.getLogger(__name__).warning("could not release an upload lock")

    def _budget_key(self, terminal_id: str) -> str:
        day = int(self.clock() // 86400)
        return BUDGET_KEY.format(terminal_id=terminal_id, day=day)

    def rows_today(self, terminal_id: str) -> int:
        try:
            return int(self.store.get(self._budget_key(terminal_id)) or 0)
        except ValueError:
            return 0

    def add(
        self,
        email: str,
        terminal_id: str,
        terminal_name: str,
        rows: Any,
        command_key: Any = None,
        stamp: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, int]:
        """`command_key`: the private key that opens sealed commands, passed only while
        this person has "Record commands" on. Without it, commands are dropped.
        `stamp`: called with each new row just before it is stored, to set the server's
        own fields (terminal.identity: signed, subject, actor, grant).

        Raises Busy while another upload from this terminal is being stored, and
        OverBudget once it stored `rows_per_day` rows today: nothing is stored, and the
        computer keeps the rows and sends them later."""
        if not isinstance(rows, list):
            raise IngestError("rows must be a list")
        if len(rows) > BATCH_MAX:
            raise IngestError(f"at most {BATCH_MAX} rows per batch")
        with self._locked(terminal_id):
            used = self.rows_today(terminal_id)
            if used >= self.rows_per_day:
                now = self.clock()
                raise OverBudget(max(1, int(86400 - now % 86400)))
            result = self._add(email, terminal_id, terminal_name, rows, command_key, stamp)
            if result["accepted"]:
                self.store.set(
                    self._budget_key(terminal_id),
                    str(used + result["accepted"]),
                    ex=2 * 86400,
                )
        if result["accepted"]:
            self.trim(email)
        return result

    def _add(
        self,
        email: str,
        terminal_id: str,
        terminal_name: str,
        rows: list[Any],
        command_key: Any,
        stamp: Callable[[dict[str, Any]], None] | None,
    ) -> dict[str, int]:
        now = self.clock()
        accepted = duplicates = rejected = edited = 0
        key = ACTIVITY_KEY.format(email=email)
        chained = self.chains.batch(email, terminal_id)
        for raw in integrity.ordered(rows):
            # The hash covers exactly what the computer sent: work it out before
            # clean_row drops or cuts anything.
            link = integrity.link_of(raw)
            row = clean_row(raw, now, command_key)
            if row is None:
                chained.judge(link)  # refused, but sent: not a gap in the chain
                rejected += 1
                continue
            seen = SEEN_KEY.format(email=email, event_id=row["event_id"])
            # The id remembers the row's hash, so a row sent again with other contents
            # (edited on the computer after it was sent) is told apart from a retry.
            marker = link.row_hash if link is not None else "1"
            if not self.store.set_if_absent(seen, marker, ex=self.seen_ttl()):
                first = self.store.get(seen)
                if link is not None and first not in (None, "1", link.row_hash):
                    chained.note_fork()
                    edited += 1
                else:
                    duplicates += 1
                continue
            row.update(chained.judge(link))
            row.update(terminal_id=terminal_id, terminal=terminal_name[:80], received=now)
            if stamp is not None:
                stamp(row)
            text = json.dumps(row, separators=(",", ":"))
            try:
                self.store.lpush(key, text)
            except Exception:
                # Not stored: forget the id so the terminal's retry is not taken for a
                # duplicate and dropped.
                self.store.delete(seen)
                raise
            if row["decision"] == "deny":
                try:
                    self.store.lpush(DENIES_KEY.format(email=email), text)
                except Exception:  # noqa: BLE001 - it is in the main log already
                    logging.getLogger(__name__).warning("could not keep a blocked row apart")
            accepted += 1
        chained.commit()
        out = {"accepted": accepted, "duplicates": duplicates, "rejected": rejected}
        if edited:
            out["edited"] = edited
        return out

    def trim(self, email: str, force: bool = False) -> None:
        """Keep at most max_rows (and as many blocked rows apart), and (about once an
        hour) nothing older than retention_days."""
        key = ACTIVITY_KEY.format(email=email)
        denies = DENIES_KEY.format(email=email)
        if force or self.store.set_if_absent(TRIM_KEY.format(email=email), "1", ex=TRIM_EVERY):
            integrity.trim_by_age(self.store, key, self.cutoff(), self.max_rows)
            integrity.trim_by_age(self.store, denies, self.cutoff(), self.max_rows)
        else:
            self.store.ltrim(key, 0, self.max_rows - 1)
            self.store.ltrim(denies, 0, self.max_rows - 1)

    def everything(self, email: str) -> Any:
        """Every row kept, newest received first, a chunk at a time (for exports). Each
        row once, and only rows that had arrived when the export started; blocked rows
        that left the main log (kept apart) come last."""
        return integrity.read_all(
            self.store,
            ACTIVITY_KEY.format(email=email),
            self.cutoff(),
            self.max_rows,
            also=(DENIES_KEY.format(email=email),),
            until=self.clock(),
        )

    def seen_ttl(self) -> int:
        """How long a stored row's id is remembered: as long as rows are kept, so a batch
        sent again (even validly signed) after 30 days is still a duplicate. How many
        there can be is bounded by `rows_per_day` per terminal."""
        return max(SEEN_TTL, int(self.retention_days) * 24 * 3600)

    def _read(self, key: str, limit: int) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for raw in self.store.lrange(key, 0, limit - 1):
            try:
                row = json.loads(raw)
            except ValueError:
                continue
            if isinstance(row, dict):
                out.append(row)
        return out

    def page(
        self,
        email: str,
        keep: Callable[[dict[str, Any]], bool],
        *,
        after: str | None = None,
        count: int = PAGE_ROWS,
        blocked: bool = False,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """One page of the Activity log: up to `count` rows `keep` accepts, newest
        received first, starting after the cursor `after` (from the previous page).

        Reads at most PAGE_SCAN rows from the store per call, so a page costs the same
        whatever the log's size. With `blocked`, it reads the blocked rows kept apart,
        which hold every block still kept. The cursor is "<position>:<received>:<event
        id>" of the last row shown; rows pushed in front since then shift positions, so
        rows are skipped until that row (or anything older than it) is passed.
        Returns the rows and the next cursor (None when the log ends)."""
        key = (DENIES_KEY if blocked else ACTIVITY_KEY).format(email=email)
        pos, anchor_received, anchor_id = 0, None, None
        if after:
            parts = after.split(":")
            try:
                if len(parts) == 3:
                    pos = min(max(0, int(parts[0])), 10_000_000)
                    if is_id(parts[2]):
                        anchor_received, anchor_id = float(parts[1]), parts[2]
            except ValueError:
                pos, anchor_received, anchor_id = 0, None, None
        skipping = anchor_id is not None
        if skipping:
            # Start at the last row shown: if nothing arrived since, it is the first row
            # read, and rows of its own upload (same arrival time) after it still show.
            pos = max(0, pos - 1)
        cutoff = self.cutoff()
        out: list[dict[str, Any]] = []
        scanned = 0
        while scanned < PAGE_SCAN:
            raws = self.store.lrange(key, pos, pos + PAGE_CHUNK - 1)
            if not raws:
                return out, None
            for raw in raws:
                pos += 1
                scanned += 1
                try:
                    row = json.loads(raw)
                except ValueError:
                    continue
                if not isinstance(row, dict):
                    continue
                received = float(row.get("received") or row.get("ts") or 0)
                if skipping:
                    if row.get("event_id") == anchor_id:
                        skipping = False
                        continue
                    if anchor_received is not None and received >= anchor_received:
                        continue
                    skipping = False
                if received < cutoff:
                    return out, None
                if keep(row):
                    out.append(row)
                    if len(out) >= count:
                        last_id = row.get("event_id") if is_id(row.get("event_id")) else ""
                        return out, f"{pos}:{received!r}:{last_id}"
            if len(raws) < PAGE_CHUNK:
                return out, None
        # Read as far as one page may: there may be more beyond, so offer a cursor.
        last = out[-1] if out else None
        if last is not None and is_id(last.get("event_id")):
            got = float(last.get("received") or last.get("ts") or 0)
            return out, f"{pos}:{got!r}:{last['event_id']}"
        return out, f"{pos}:0:"

    def recent(self, email: str, limit: int = ACTIVITY_MAX) -> list[dict[str, Any]]:
        """The newest `limit` rows, and blocked rows kept apart that are not among them
        (so blocks stay visible after a flood of allowed rows)."""
        out = self._read(ACTIVITY_KEY.format(email=email), limit)
        ids = {r.get("event_id") for r in out}
        cutoff = self.cutoff()
        for row in self._read(DENIES_KEY.format(email=email), limit):
            if row.get("event_id") in ids:
                continue
            if float(row.get("received") or row.get("ts") or 0) < cutoff:
                continue
            ids.add(row.get("event_id"))
            out.append(row)
        # Newest by when it happened on the computer, not when it arrived.
        out.sort(key=lambda r: r.get("ts") or 0, reverse=True)
        return out

    # ---- recording commands -------------------------------------------------------

    def records_commands(self, email: str) -> bool:
        return self.store.hget(SETTINGS_KEY.format(email=email), "record_commands") == "1"

    def set_records_commands(self, email: str, on: bool) -> None:
        self.store.hset(SETTINGS_KEY.format(email=email), "record_commands", "1" if on else "0")

    # ---- sessions -----------------------------------------------------------------

    def revoke_session(self, email: str, session_id: str) -> bool:
        """Any well-formed id: revocations are per person, so revoking one that is not
        (or no longer) in the log affects only this person's own terminals."""
        if not is_id(session_id):
            return False
        self.store.hset(REVOKED_KEY.format(email=email), session_id, str(int(self.clock())))
        return True

    def revoked_sessions(self, email: str) -> list[str]:
        return sorted(self.store.hgetall(REVOKED_KEY.format(email=email)))

    def session(self, email: str, session_id: str, stub: bool = False) -> dict[str, Any] | None:
        """One session and everything started under it, built from the activity rows.
        Without its start row (aged out of the newest rows, or never sent), None; with
        `stub`, a minimal tree for a well-formed id instead (`aged_out` set), built from
        whatever rows of it are still here, so it can still be seen and revoked."""
        if not is_id(session_id):
            return None
        rows = self.recent(email)
        starts = {r["session_id"]: r for r in rows if r.get("decision") == "session"}
        aged_out = session_id not in starts
        if aged_out:
            if not stub:
                return None
            mine = [r for r in rows if r.get("session_id") == session_id]
            first = min(mine, key=lambda r: r.get("ts") or 0) if mine else {}
            starts[session_id] = {
                "session_id": session_id,
                "decision": "session",
                "terminal": first.get("terminal") or "an unknown computer",
                "terminal_id": first.get("terminal_id") or "",
                "role": first.get("role") or "unknown",
                "agent": first.get("agent") or "",
                "ts": first.get("ts"),
                "aged_out": True,
            }
        revoked = set(self.revoked_sessions(email))
        children: dict[str, list[str]] = {}
        for sid, start in starts.items():
            parent = start.get("parent_session_id")
            if parent:
                children.setdefault(parent, []).append(sid)

        def node(sid: str, depth: int) -> dict[str, Any]:
            calls = [r for r in rows if r.get("session_id") == sid and r["decision"] in CALLS]
            return {
                "start": starts[sid],
                "calls": len(calls),
                "blocked": [r for r in calls if r["decision"] == "deny"],
                "revoked": sid in revoked,
                "children": [node(c, depth + 1) for c in sorted(children.get(sid, []))]
                if depth < 10
                else [],
            }

        tree = node(session_id, 0)
        if aged_out:
            tree["aged_out"] = True
        return tree

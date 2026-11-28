"""Checking each terminal's hash chain, signed checkpoints, and how long rows are kept.

The CLI chains its audit rows (botrbac_cli.chain): `seq`, `prev_hash`, `row_hash`. Here
each row's hash is worked out again over exactly the fields the computer sent, before
ingest.clean_row drops or cuts anything, and checked against the last row accepted
from that terminal. The stored row gets `chain`:

- ok         the next seq, and it links to the row before it
- gap        rows are missing before it (deleted on the computer, or not sent yet)
- fork       its seq was already used by another row, it does not link to the row
             before it, or its hash does not match its contents (edited)
- unchained  sent by a CLI from before the chain

A row sent again (same event_id) is a duplicate and is not judged again. A row that
arrives late into a gap is `ok` when it links to the rows on either side of it. The
first chained row from a terminal starts its chain (`start`): a computer that logs in
again is a new terminal here, and its seq goes on from where it was.
"""

import json
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from botrbac_cli import chain

CHAIN_KEY = "term:chain:{email}"
LINK_KEY = "term:chainlink:{email}:{terminal_id}:{seq}"

OK, GAP, FORK, UNCHAINED = "ok", "gap", "fork", "unchained"


@dataclass(frozen=True)
class Link:
    seq: int
    prev_hash: str
    row_hash: str
    intact: bool  # the row's hash matches what it holds


def link_of(raw: Any) -> Link | None:
    """The chain fields of a row as sent, or None for a row without them."""
    if not isinstance(raw, dict):
        return None
    seq, prev, claimed = raw.get("seq"), raw.get("prev_hash"), raw.get("row_hash")
    if not (chain.is_seq(seq) and chain.is_hash(prev) and chain.is_hash(claimed)):
        return None
    try:
        intact = chain.row_hash(raw) == claimed
    except (TypeError, ValueError):
        intact = False
    return Link(seq, prev, claimed, intact)


def ordered(rows: list[Any]) -> list[Any]:
    """Rows in seq order (rows without a seq first, as they came)."""

    def key(raw: Any) -> int:
        seq = raw.get("seq") if isinstance(raw, dict) else None
        return seq if chain.is_seq(seq) else 0

    return sorted(rows, key=key)


def _empty() -> dict[str, Any]:
    return {
        "seq": 0,
        "hash": chain.GENESIS,
        "start": 0,
        "missing": 0,
        "forks": 0,
        "ok": 0,
        "unchained": 0,
    }


@dataclass
class ChainBatch:
    """One audit POST's rows from one terminal, judged in seq order."""

    store: Any
    email: str
    terminal_id: str
    ttl: int
    state: dict[str, Any] = field(default_factory=_empty)
    changed: bool = False

    def _key(self, seq: int) -> str:
        return LINK_KEY.format(email=self.email, terminal_id=self.terminal_id, seq=seq)

    def _known(self, seq: int) -> tuple[str, str] | None:
        if seq < 1:
            return None
        value = self.store.get(self._key(seq))
        if not value or ":" not in value:
            return None
        row_hash, prev = value.split(":", 1)
        return row_hash, prev

    def judge(self, link: Link | None) -> dict[str, Any]:
        """The fields to set on the stored row, and the terminal's chain moved on."""
        self.changed = True
        if link is None:
            self.state["unchained"] += 1
            return {"chain": UNCHAINED}
        status = self._status(link)
        if status == FORK:
            self.state["forks"] += 1
        elif status == OK:
            self.state["ok"] += 1
        if link.intact:
            self.store.set_if_absent(
                self._key(link.seq), f"{link.row_hash}:{link.prev_hash}", ex=self.ttl
            )
        return {"chain": status, "seq": link.seq, "row_hash": link.row_hash}

    def _status(self, link: Link) -> str:
        last = int(self.state["seq"])
        if not link.intact:
            return FORK  # edited after it was hashed
        if last == 0:
            # The first chained row this site gets from the terminal starts its chain
            # here. Above 1 (the computer logged in again, so it is a new terminal
            # here), the Terminals page says where it starts.
            self.state.update(seq=link.seq, hash=link.row_hash, start=link.seq)
            return OK if link.seq > 1 or link.prev_hash == chain.GENESIS else FORK
        if link.seq > last:
            tip = self.state["hash"]
            self.state["seq"], self.state["hash"] = link.seq, link.row_hash
            if link.seq == last + 1:
                return OK if link.prev_hash == tip else FORK
            self.state["missing"] += link.seq - last - 1
            return GAP
        seen = self._known(link.seq)
        if seen is not None:
            return OK if seen[0] == link.row_hash else FORK
        # A row arriving late, into a gap: it must link to its neighbours.
        before, after = self._known(link.seq - 1), self._known(link.seq + 1)
        if link.seq == 1 and link.prev_hash != chain.GENESIS:
            return FORK
        if (before and before[0] != link.prev_hash) or (after and after[1] != link.row_hash):
            return FORK
        if before or after or link.seq == 1:
            self.state["missing"] = max(int(self.state["missing"]) - 1, 0)
            return OK
        return GAP

    def commit(self) -> None:
        if self.changed:
            self.state["checked_at"] = time.time()
            self.store.hset(
                CHAIN_KEY.format(email=self.email), self.terminal_id, json.dumps(self.state)
            )


@dataclass
class Chains:
    store: Any
    ttl: int = 180 * 24 * 3600

    def batch(self, email: str, terminal_id: str) -> ChainBatch:
        state = self.state(email, terminal_id) or _empty()
        return ChainBatch(self.store, email, terminal_id, self.ttl, state)

    def state(self, email: str, terminal_id: str) -> dict[str, Any] | None:
        raw = self.store.hget(CHAIN_KEY.format(email=email), terminal_id)
        try:
            data = json.loads(raw) if raw else None
        except ValueError:
            return None
        if not isinstance(data, dict):
            return None
        return {**_empty(), **data}

    def summary(self, email: str) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for terminal_id, raw in self.store.hgetall(CHAIN_KEY.format(email=email)).items():
            try:
                data = json.loads(raw)
            except ValueError:
                continue
            if isinstance(data, dict):
                out[terminal_id] = {**_empty(), **data}
        return out

    def tip(self, email: str, terminal_id: str) -> tuple[int, str] | None:
        """(seq, row_hash) of the newest chained row accepted from this terminal."""
        state = self.state(email, terminal_id)
        if not state or not chain.is_seq(state.get("seq")):
            return None
        return int(state["seq"]), str(state["hash"])

    def forget(self, email: str, terminal_id: str) -> None:
        self.store.hdel(CHAIN_KEY.format(email=email), terminal_id)


# ---- retention ------------------------------------------------------------------


def _arrived(raw: str) -> float:
    try:
        row = json.loads(raw)
        return float(row.get("received") or row.get("ts") or 0)
    except (ValueError, TypeError, AttributeError):
        return 0.0


def trim_by_age(store: Any, key: str, cutoff: float, max_rows: int) -> int:
    """Drop rows older than `cutoff` from the tail of a newest-first list, and keep at
    most `max_rows`. Rows are pushed as they arrive, so `received` only grows toward
    the head: a binary search finds where old rows start with about 15 reads, without
    reading the whole list. Returns how many rows are kept (at most)."""
    store.ltrim(key, 0, max_rows - 1)
    lo, hi = 0, max_rows  # the first old (or missing) index is in [lo, hi]
    while lo < hi:
        mid = (lo + hi) // 2
        found = store.lrange(key, mid, mid)
        if found and _arrived(found[0]) >= cutoff:
            lo = mid + 1
        else:
            hi = mid
    if lo < max_rows and store.lrange(key, lo, lo):
        if lo:
            store.ltrim(key, 0, lo - 1)
        else:
            store.ltrim(key, 1, 0)  # empties the list: every row is too old
    return lo


def read_all(
    store: Any, key: str, cutoff: float, max_rows: int, chunk: int = 1000
) -> Iterator[dict[str, Any]]:
    """Every row within retention, newest received first, read a chunk at a time."""
    for start in range(0, max_rows, chunk):
        batch = store.lrange(key, start, min(start + chunk, max_rows) - 1)
        for raw in batch:
            try:
                row = json.loads(raw)
            except ValueError:
                continue
            if isinstance(row, dict) and float(row.get("received") or row.get("ts") or 0) >= cutoff:
                yield row
        if len(batch) < chunk:
            return

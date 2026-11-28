"""A hash chain over this computer's audit rows, and the website's signed checkpoints.

Each row gets `seq` (1, 2, 3… per terminal), `prev_hash` (the row before's `row_hash`,
or 64 zeros for the first) and `row_hash`: sha256 over the row's canonical JSON without
`row_hash`. Deleting, reordering or editing a row breaks the chain, and the website
notices when it next gets the rows. Code running as this user can still add new rows
that never happened: the chain shows what was removed or changed, not what is true.

The website signs a checkpoint, {kind, terminal_id, seq, row_hash, ts}, with the same
key as the policy (pinned at login), and `botrbac verify` checks this computer's
audit.db against it.

Shared with the server (scoped_drive_mcp.terminal.integrity), so both hash the same way.
"""

import contextlib
import hashlib
import json
import re
from typing import Any

from . import signing

GENESIS = "0" * 64
CHECKPOINT_KIND = "botrbac.checkpoint.v1"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _plain(value: Any) -> Any:
    """Floats that are whole numbers become ints (1.0 -> 1), as in RFC 8785, so the
    JSON is the same whichever language reads and writes the row."""
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, float) and value.is_integer() and abs(value) < 2**53:
        return int(value)
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_plain(v) for v in value]
    return value


def canonical_json(value: Any) -> bytes:
    """Sorted keys, no whitespace, UTF-8 (RFC 8785-style for strings, numbers, bools,
    null, lists and objects). NaN and infinity are refused."""
    text = json.dumps(
        _plain(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    # A lone surrogate (from JSON "\ud800") is kept as is, the same on both sides.
    return text.encode("utf-8", errors="surrogatepass")


def row_hash(row: dict[str, Any]) -> str:
    """sha256 over the row without its own `row_hash`."""
    body = {k: v for k, v in row.items() if k != "row_hash"}
    return hashlib.sha256(canonical_json(body)).hexdigest()


def link(row: dict[str, Any], seq: int, prev_hash: str) -> dict[str, Any]:
    """Chain a finished row: the last step before it is written. Returns the row."""
    row["seq"] = int(seq)
    row["prev_hash"] = prev_hash
    row.pop("row_hash", None)
    row["row_hash"] = row_hash(row)
    return row


def is_hash(value: Any) -> bool:
    return isinstance(value, str) and bool(_HEX64.match(value))


def is_seq(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value < 2**53


# ---- checkpoints ------------------------------------------------------------------


def checkpoint_body(terminal_id: str, seq: int, hash_: str, ts: float) -> dict[str, Any]:
    return {
        "kind": CHECKPOINT_KIND,
        "terminal_id": terminal_id,
        "seq": int(seq),
        "row_hash": hash_,
        "ts": ts,
    }


def verify_checkpoint(public_key: str | None, checkpoint: Any) -> bool:
    """Whether `checkpoint` was signed by the website whose key was pinned at login."""
    if not public_key or not isinstance(checkpoint, dict):
        return False
    if checkpoint.get("kind") != CHECKPOINT_KIND:
        return False
    if not is_seq(checkpoint.get("seq")) or not is_hash(checkpoint.get("row_hash")):
        return False
    return signing.verify(public_key, checkpoint)


def remember_checkpoint(response: Any) -> None:
    """Keep the newest checkpoint from an audit POST's answer in state.json."""
    from . import state

    checkpoint = response.get("checkpoint") if isinstance(response, dict) else None
    if not isinstance(checkpoint, dict) or not is_seq(checkpoint.get("seq")):
        return
    data = state.read_json("state.json", {}) or {}
    old = data.get("checkpoint") or {}
    if (
        isinstance(old, dict)
        and old.get("terminal_id") == checkpoint.get("terminal_id")
        and is_seq(old.get("seq"))
        and old["seq"] > checkpoint["seq"]
    ):
        return
    data["checkpoint"] = checkpoint
    # Never costs the sync: the next answer brings a newer one.
    with contextlib.suppress(OSError):
        state.write_json("state.json", data)


# ---- walking a local chain --------------------------------------------------------


def walk(rows: list[dict[str, Any]], pruned_through: int = 0, tip: int = 0) -> dict[str, Any]:
    """Check rows (in seq order) link up. Rows up to `pruned_through` may have been
    deleted on purpose (sent, and older than the local history keeps); `tip` is the
    newest seq given out. Returns the first and last seq, the hash at each seq, and the
    problems found: [(seq, what)]."""
    problems: list[tuple[int, str]] = []
    hashes: dict[int, str] = {}
    prev: dict[str, Any] | None = None
    unchained = 0
    for row in rows:
        seq = row.get("seq")
        if not is_seq(seq):
            unchained += 1
            continue
        if row_hash(row) != row.get("row_hash"):
            problems.append((seq, "edited: its hash does not match its contents"))
        if prev is not None:
            if seq == prev["seq"]:
                problems.append((seq, "two rows with the same seq"))
            elif seq != prev["seq"] + 1:
                if seq - 1 > pruned_through:
                    problems.append((seq, _missing(max(prev["seq"], pruned_through) + 1, seq)))
            elif row.get("prev_hash") != prev.get("row_hash"):
                problems.append((seq, "does not link to the row before it"))
        elif seq == 1 and row.get("prev_hash") != GENESIS:
            problems.append((seq, "first row does not start the chain"))
        elif seq - 1 > pruned_through:
            problems.append((seq, _missing(pruned_through + 1, seq)))
        hashes[seq] = str(row.get("row_hash"))
        prev = row
    seqs = sorted(hashes)
    newest = max(seqs[-1] if seqs else 0, pruned_through)
    if tip > newest:
        problems.append((tip, _missing(newest + 1, tip + 1) + " (the newest)"))
    return {
        "first": seqs[0] if seqs else None,
        "last": seqs[-1] if seqs else None,
        "count": len(seqs),
        "unchained": unchained,
        "hashes": hashes,
        "problems": problems,
    }


def _missing(first: int, stop: int) -> str:
    if first == stop - 1:
        return f"row {first} is missing"
    return f"rows {first}-{stop - 1} are missing"

"""Sending queued audit rows, and fetching the policy, whenever the server answers."""

import sys
from typing import Any

from . import policy, state
from .api import ApiError
from .hooks import hook_report
from .queue import SEND_BATCH, AuditQueue

# Answers that will be the same however often the batch is sent again.
PERMANENT = frozenset({400, 413, 422})


class _Budget:
    """At most this many requests per batch while narrowing down a refusal, so a server
    that refuses everything costs a handful of requests, not one per row. Rows not
    tried before it runs out simply stay waiting; what was settled is kept, so every
    sync makes progress."""

    def __init__(self, requests: int = 24):
        self.left = requests

    def spend(self) -> bool:
        if self.left <= 0:
            return False
        self.left -= 1
        return True


def _forget_report() -> None:
    """A refused tools/unguarded report won't be accepted next time either: drop it, so
    each later sync doesn't spend a request (and a warning) on it again. Fresh tools
    are collected again as the gateway sees them."""
    data = state.read_json("state.json", {}) or {}
    data.pop("tools", None)
    data.pop("unguarded", None)
    state.write_json("state.json", data)


def _coverage(unguarded: Any) -> dict[str, Any]:
    """agents.coverage_summary, or an empty report if looking fails: it must never stop
    the rows being sent."""
    from .agents import coverage_summary

    try:
        return coverage_summary(unguarded=unguarded if isinstance(unguarded, list) else None)
    except Exception:  # noqa: BLE001
        return {}


def _send(
    api: Any, rows: list[dict[str, Any]], meta: dict[str, Any], budget: _Budget | None = None
) -> tuple[list[str], list[str]]:
    """(sent ids, refused ids). A permanent refusal is narrowed down by sending halves,
    so one bad row (or a batch that is only too large) never costs the good rows; the
    tools/unguarded report is dropped first in case it is what was refused. Temporary
    errors are raised to the caller, which keeps every row for the next sync."""
    budget = budget or _Budget()
    ids = [r["event_id"] for r in rows]
    if not budget.spend():
        return [], []  # not tried this time: these rows stay waiting
    try:
        api.send_audit({"rows": rows, **meta})
        return ids, []
    except ApiError as exc:
        if exc.status not in PERMANENT:
            raise
        too_large = exc.status == 413
    if too_large and len(rows) > 1:
        # Too large is about the batch, not the report: split it and keep the report.
        half = len(rows) // 2
        sent_a, refused_a = _send(api, rows[:half], meta, budget)
        rest = {k: v for k, v in meta.items() if k == "queued"}
        sent_b, refused_b = _send(api, rows[half:], rest, budget)
        return sent_a + sent_b, refused_a + refused_b
    if "tools" in meta or "unguarded" in meta:
        print(
            "botrbac: the server refused this computer's tool report; sending rows without it",
            file=sys.stderr,
        )
        _forget_report()
        return _send(api, rows, {k: v for k, v in meta.items() if k == "queued"}, budget)
    if len(rows) <= 1:
        # One row refused on its own (or nothing to narrow down): set it aside. A single
        # waiting row can't tell a bad row from a bad server, but it is kept and can be
        # sent again with --retry-rejected.
        return [], ids
    half = len(rows) // 2
    sent_a, refused_a = _send(api, rows[:half], meta, budget)
    sent_b, refused_b = _send(api, rows[half:], meta, budget)
    return sent_a + sent_b, refused_a + refused_b


def _probe(api: Any, row: dict[str, Any]) -> bool:
    """Whether the server takes one row on its own (any failure counts as no)."""
    try:
        api.send_audit({"rows": [row]})
    except Exception:  # noqa: BLE001
        return False
    return True


def sync(api: Any, queue: AuditQueue) -> dict[str, Any]:
    """Send everything waiting, in batches. Stops quietly at the first temporary failure
    (offline, server error) and still fetches the policy."""
    sent = rejected = 0
    extra = state.read_json("state.json", {}) or {}
    first = True
    while True:
        rows = queue.pending(SEND_BATCH)
        if not rows and not first:
            break
        meta: dict[str, Any] = {"queued": max(queue.waiting() - len(rows), 0)}
        if first:
            hooks = hook_report()
            if hooks:
                meta["hooks"] = hooks
            meta["tools"] = extra.get("tools") or []
            if "unguarded" in extra:
                meta["unguarded"] = extra["unguarded"]
            meta["coverage"] = _coverage(extra.get("unguarded"))
        clean = [{k: v for k, v in r.items() if k not in ("sent", "status")} for r in rows]
        try:
            ok, refused = _send(api, clean, meta)
        except Exception as exc:  # noqa: BLE001 - offline or server trouble: keep the rows
            # Still fetch the policy: a role change or a revoked session must reach
            # this computer even when the audit upload is failing.
            fresh = policy.refresh(api)
            return {
                "sent": sent,
                "waiting": queue.waiting(),
                "error": str(exc) or "offline",
                "policy": bool(fresh),
            }
        queue.mark_sent(ok)
        if refused:
            # Nothing accepted and several refused: bad rows, or a server refusing
            # everything (a bad deploy)? If the cap stopped before every row was tried,
            # try one untried row from the far end to tell them apart.
            if not ok and len(refused) > 1:
                settled = set(refused)
                untried = [r for r in clean if r["event_id"] not in settled]
                if untried and _probe(api, untried[-1]):
                    ok = [untried[-1]["event_id"]]
                    queue.mark_sent(ok)
            if not ok and len(refused) > 1:
                fresh = policy.refresh(api)
                return {
                    "sent": sent,
                    "waiting": queue.waiting(),
                    "error": "the server refused every row",
                    "policy": bool(fresh),
                }
            queue.mark_rejected(refused)
            print(
                f"botrbac: the server refused {len(refused)} audit row(s); kept on this "
                "computer (botrbac log, botrbac sync --retry-rejected)",
                file=sys.stderr,
            )
        sent += len(ok)
        rejected += len(refused)
        first = False
        if len(rows) < SEND_BATCH:
            break
    fresh = policy.refresh(api)
    result: dict[str, Any] = {"sent": sent, "waiting": queue.waiting(), "policy": bool(fresh)}
    if rejected:
        result["rejected"] = rejected
    return result

"""Sending queued audit rows, and fetching the policy, whenever the server answers."""

import sys
from typing import Any

from . import policy, state
from .api import ApiError
from .queue import SEND_BATCH, AuditQueue

# Answers that will be the same however often the batch is sent again.
PERMANENT = frozenset({400, 413, 422})


class _Budget:
    """At most this many requests per sync while narrowing down a refusal, so a server
    that refuses everything costs a handful of requests, not one per row."""

    def __init__(self, requests: int = 24):
        self.left = requests

    def spend(self) -> None:
        if self.left <= 0:
            raise ApiError(503, "too_many_refusals")  # temporary: keep every row
        self.left -= 1


def _send(
    api: Any, rows: list[dict[str, Any]], meta: dict[str, Any], budget: _Budget | None = None
) -> tuple[list[str], list[str]]:
    """(sent ids, refused ids). A permanent refusal is narrowed down by sending halves,
    so one bad row (or a batch that is only too large) never costs the good rows; the
    tools/unguarded report is dropped first in case it is what was refused. Temporary
    errors are raised to the caller, which keeps every row for the next sync."""
    budget = budget or _Budget()
    ids = [r["event_id"] for r in rows]
    budget.spend()
    try:
        api.send_audit({"rows": rows, **meta})
        return ids, []
    except ApiError as exc:
        if exc.status not in PERMANENT:
            raise
    if "tools" in meta or "unguarded" in meta:
        print(
            "botrbac: the server refused this computer's tool report; sending rows without it",
            file=sys.stderr,
        )
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
            meta["tools"] = extra.get("tools") or []
            if "unguarded" in extra:
                meta["unguarded"] = extra["unguarded"]
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
            # Every row refused on its own looks like the server, not the rows: keep
            # them waiting rather than set aside a whole queue because of a bad deploy.
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

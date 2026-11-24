"""Sending queued audit rows, and fetching the policy, whenever the server answers."""

from typing import Any

from . import policy, state
from .queue import SEND_BATCH, AuditQueue


def sync(api: Any, queue: AuditQueue) -> dict[str, Any]:
    """Send everything waiting, in batches. Stops quietly at the first failure."""
    sent = 0
    extra = state.read_json("state.json", {}) or {}
    first = True
    while True:
        rows = queue.pending(SEND_BATCH)
        if not rows and not first:
            break
        body: dict[str, Any] = {
            "rows": [{k: v for k, v in r.items() if k != "sent"} for r in rows],
            "queued": max(queue.waiting() - len(rows), 0),
        }
        if first:
            body["tools"] = extra.get("tools") or []
            if "unguarded" in extra:
                body["unguarded"] = extra["unguarded"]
        try:
            api.send_audit(body)
        except Exception as exc:  # noqa: BLE001 - offline: keep the rows
            return {"sent": sent, "waiting": queue.waiting(), "error": str(exc) or "offline"}
        queue.mark_sent([r["event_id"] for r in rows])
        sent += len(rows)
        first = False
        if len(rows) < SEND_BATCH:
            break
    fresh = policy.refresh(api)
    return {"sent": sent, "waiting": queue.waiting(), "policy": bool(fresh)}

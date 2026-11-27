"""JSON-lines audit log on stdout (shows up in Vercel runtime logs), optionally mirrored to
extra sinks such as the capped Redis activity list shown on the dashboard.

Only identifiers and decisions are logged: never file contents, names, queries or secrets.
"""

import hashlib
import json
import logging
import re
import sys
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any, Literal

logger = logging.getLogger(__name__)

Decision = Literal["allow", "deny", "error"]
Sink = Callable[[dict[str, Any]], None]

_sinks: list[Sink] = []
_MAX_ID = 200
_MAX_REASON = 300


def set_sinks(sinks: Iterable[Sink]) -> None:
    """Replace the extra sinks (stdout is always written)."""
    _sinks[:] = list(sinks)


def app_tag(grant_id: str) -> str:
    """A short, stable name for one connected app in logs and Activity. A hash, so the
    grant id itself (a store key) is never written out."""
    return hashlib.sha256(f"app\x00{grant_id}".encode()).hexdigest()[:12]


def actor_tag(email: str) -> str:
    """Whose account a server-log line belongs to, without writing the address."""
    return hashlib.sha256(f"actor\x00{email.strip().lower()}".encode()).hexdigest()[:12]


def _actor() -> str | None:
    from .auth import current_actor

    email = current_actor.get()
    return actor_tag(email) if email else None


# Shown on the person's own Activity page, which needs them, but never written to the
# server log: item and role names (the person's own words).
_ACTIVITY_ONLY = ("name", "label")
# An email address anywhere in a logged value (a paired person in `person`, `guest`,
# `owner`, `audience` or a `guest:<email> (App)` token name) becomes its tag.
_EMAIL = re.compile(r"[^\s,;:<>()\[\]\"']+@[^\s,;:<>()\[\]\"']+\.[A-Za-z]{2,}")


def _scrub(value: Any) -> Any:
    if isinstance(value, str) and "@" in value:
        return _EMAIL.sub(lambda m: actor_tag(m.group(0)), value)
    return value


def _emit(record: dict[str, Any]) -> None:
    # Only the server log gets the account tag; the Activity sink is already per account.
    line = {k: _scrub(v) for k, v in record.items() if k not in _ACTIVITY_ONLY}
    actor = _actor()
    if actor and "actor" not in line:
        line["actor"] = actor
    sys.stdout.write(json.dumps(line, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    for sink in list(_sinks):
        try:
            sink(record)
        except Exception:
            logger.warning("audit sink failed", exc_info=True)


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def audit(
    *,
    tool: str,
    decision: Decision,
    reason: str,
    token_name: str | None,
    role: str | None,
    **ids: str | None,
) -> None:
    record: dict[str, Any] = {
        "ts": _now(),
        "event": "tool_call",
        "token_name": token_name,
        "role": role,
        "tool": tool,
    }
    # Ids come straight from tool arguments. Cap them so a caller cannot write
    # arbitrarily large rows into the log (a guest's calls land on the owner's log).
    record.update({k: v[:_MAX_ID] for k, v in ids.items() if v is not None})
    record["decision"] = decision
    record["reason"] = reason[:_MAX_REASON]
    if decision == "allow" and _changes_something(tool):
        # Kept on Activity whatever else happens (store.records.ActivityLog).
        record["kind"] = "change"
    _emit(record)


def _changes_something(tool: str) -> bool:
    from .policy import changes_something  # policy imports this module

    return changes_something(tool)


def audit_auth_failure(reason: str, path: str) -> None:
    # The path is whatever the caller asked for; cap it like a tool argument.
    _emit(
        {
            "ts": _now(),
            "event": "auth",
            "path": str(path)[:_MAX_ID],
            "decision": "deny",
            "reason": str(reason)[:_MAX_REASON],
        }
    )


def audit_owner(action: str, decision: Decision = "allow", **fields: str | None) -> None:
    """Dashboard actions: sign-in, grant, revoke, request decisions."""
    record: dict[str, Any] = {"ts": _now(), "event": "owner", "action": action}
    # Some fields carry form input (ids, addresses, names); cap each text one.
    record.update(
        {k: v[:_MAX_ID] if isinstance(v, str) else v for k, v in fields.items() if v is not None}
    )
    record["decision"] = decision
    _emit(record)

"""Deciding whether a tool may run, from the policy cached on this computer.

The server's policy is cached with the time it was fetched. Without internet the cache
is used for the role's offline grace (days), then every tool is blocked until the
terminal can check in again. No cache at all also blocks everything.
"""

import os
import time
from dataclasses import dataclass, field
from typing import Any

from . import state
from .patterns import chain_allows

SESSION_ENV = "BOTRBAC_SESSION"
REFRESH_AFTER = 300  # seconds before a gateway asks the server again


@dataclass
class Decision:
    allowed: bool
    reason: str
    role: str


def load_cached() -> dict[str, Any] | None:
    data = state.read_json("policy.json")
    return data if isinstance(data, dict) and "policy" in data else None


def save(policy: dict[str, Any]) -> None:
    state.write_json("policy.json", {"policy": policy, "fetched_at": time.time()})


def refresh(api: Any) -> dict[str, Any] | None:
    """Fetch and cache the policy; None when the server cannot be reached."""
    try:
        policy = api.policy()
    except Exception:  # noqa: BLE001 - offline, server down, or logged out
        return None
    save(policy)
    return policy


def load_session(session_id: str | None) -> dict[str, Any] | None:
    if not session_id:
        return None
    if not session_id.replace("-", "").isalnum():
        return None
    data = state.read_json(f"sessions/{session_id}.json")
    return data if isinstance(data, dict) else None


@dataclass
class Enforcer:
    """Checks tools against the terminal's role plus any `botrbac run --role` narrowing."""

    session_id: str | None = field(default_factory=lambda: os.environ.get(SESSION_ENV))
    clock: Any = time.time

    def _state(self) -> tuple[dict[str, Any] | None, str]:
        cached = load_cached()
        if cached is None:
            return None, "no policy yet: run botrbac login"
        policy = cached["policy"]
        days = int(policy.get("role", {}).get("offline_days") or 7)
        if self.clock() - float(cached.get("fetched_at") or 0) > days * 86400:
            return None, f"offline for more than {days} days: connect to the internet"
        return policy, ""

    def stale(self) -> bool:
        cached = load_cached()
        return cached is None or self.clock() - float(cached.get("fetched_at") or 0) > REFRESH_AFTER

    def chain(self) -> tuple[list[list[str]], str, str]:
        """(pattern lists, role name, reason when nothing is allowed)."""
        policy, why = self._state()
        if policy is None:
            return [], "", why
        role = policy.get("role") or {}
        chain = [list(role.get("patterns") or [])]
        name = str(role.get("name") or role.get("id") or "")
        if self.session_id:
            session = load_session(self.session_id)
            if session is None:
                return [], name, "unknown session"
            ids = [str(s) for s in session.get("lineage") or [self.session_id]]
            if set(ids) & set(policy.get("revoked_sessions") or []):
                return [], name, "this session was revoked on the website"
            chain += [list(p) for p in session.get("chain") or []]
            name = str(session.get("role_name") or name)
        return chain, name, ""

    def decide(self, tool: str) -> Decision:
        chain, name, why = self.chain()
        if why:
            return Decision(False, why, name)
        if chain_allows(chain, tool):
            return Decision(True, "ok", name)
        return Decision(False, f"not in role {name!r}", name)


def session_fields() -> dict[str, Any]:
    """Session ids for an audit row, when running inside `botrbac run`."""
    session = load_session(os.environ.get(SESSION_ENV))
    if not session:
        return {}
    out = {"session_id": session.get("id")}
    if session.get("parent"):
        out["parent_session_id"] = session["parent"]
    return out

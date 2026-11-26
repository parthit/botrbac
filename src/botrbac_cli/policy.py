"""Deciding whether a tool may run, from the policy cached on this computer.

The server's policy is cached with the time it was fetched. Without internet the cache
is used for the role's offline grace (days), then every tool is blocked until the
terminal can check in again. No cache at all also blocks everything.
"""

import os
import time
from dataclasses import dataclass, field
from typing import Any

from . import signing, state
from .patterns import chain_allows, chain_allows_command, has_command_rules

SESSION_ENV = "BOTRBAC_SESSION"
REFRESH_AFTER = 300  # seconds before a gateway asks the server again
CLOCK_SKEW = 300


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
        pinned = (state.read_json("credentials.json", {}) or {}).get("policy_key")
        # A signed policy with no key to check it against means the key was removed.
        if (pinned or policy.get("signature")) and not signing.verify(pinned or "", policy):
            return None, (
                "botrbac's saved role was changed on this computer, so every tool is "
                "blocked: run botrbac sync"
            )
        days = int(policy.get("role", {}).get("offline_days") or 7)
        age = self.clock() - float(cached.get("fetched_at") or 0)
        if pinned:
            # The fetch time is not signed, so editing it could stretch the offline
            # grace. The server's issue time is signed: count from it too, allowing a
            # day for this computer's clock being off.
            age = max(age, self.clock() - float(policy.get("issued_at") or 0) - 86400)
        if age > days * 86400:
            return None, f"offline for more than {days} days: connect to the internet"
        if age < -CLOCK_SKEW:
            # Fetched "in the future": the clock was moved back. Don't let that keep an
            # old policy alive; check in again.
            return None, "this computer's clock moved back: connect to the internet"
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

    def limits_commands(self) -> bool:
        """Whether any role in force has `cmd/` patterns (so a shell tool's command is
        checked program by program). Without any, the shell tool is all or nothing."""
        chain, _name, _why = self.chain()
        return any(has_command_rules(patterns) for patterns in chain)

    def decide_programs(self, programs: list[str]) -> Decision:
        chain, name, why = self.chain()
        if why:
            return Decision(False, why, name)
        refused = [p for p in programs if not chain_allows_command(chain, p)]
        if refused:
            listed = ", ".join(f"cmd/{p}" for p in refused[:5])
            return Decision(False, f"running {listed} is not in role {name!r}", name)
        return Decision(True, "ok", name)


def command_key() -> str | None:
    """The website's public key for sealing commands, when the person turned on
    "Record commands". Only from a policy whose signature checks out, so an edited
    cache cannot point the commands at another key (and blocks every tool anyway)."""
    pol, _why = Enforcer()._state()
    key = (pol or {}).get("command_key")
    return key if isinstance(key, str) and key else None


def session_fields() -> dict[str, Any]:
    """Session ids for an audit row, when running inside `botrbac run`."""
    session = load_session(os.environ.get(SESSION_ENV))
    if not session:
        return {}
    out = {"session_id": session.get("id")}
    if session.get("parent"):
        out["parent_session_id"] = session["parent"]
    return out

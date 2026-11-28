"""Deciding whether a tool may run, from the policy cached on this computer.

The server's policy is cached with the time it was fetched. Without internet the cache
is used for the role's offline grace (days), then every tool is blocked until the
terminal can check in again. No cache at all also blocks everything.

The policy must carry the server's signature whenever a key is known on this computer
(credentials.json, terminal_key.json or state.json: removing it from one file does not
switch checking off), or the server is the default site, or nobody is logged in here
(no credentials.json blocks everything). Only a self-hosted server that has never sent
a key (one without ENCRYPTION_KEY) may hand out unsigned policies. A signed policy must
also be for this terminal and no older than the newest one this computer has accepted,
so an old, wider policy cannot be put back.
"""

import os
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from . import identity, signing, state
from .api import DEFAULT_SERVER
from .patterns import chain_allows, chain_allows_command, has_command_rules

SESSION_ENV = "BOTRBAC_SESSION"
REFRESH_AFTER = 300  # seconds before a gateway asks the server again
CLOCK_SKEW = 300


@dataclass
class Decision:
    allowed: bool
    reason: str
    role: str


_SITE_CACHE: dict[tuple[str, int], str] = {}


def _site() -> str:
    """The site from login, scheme and host only, or "" when unknown. Cached per version of
    credentials.json, so a busy gateway does not read it on every denied call."""
    path = state.home() / "credentials.json"
    try:
        key = (str(path), path.stat().st_mtime_ns)
    except OSError:
        return ""
    if key not in _SITE_CACHE:
        creds = state.read_json("credentials.json") or {}
        server = str(creds.get("server") or "") if isinstance(creds, dict) else ""
        parts = urlsplit(server)
        ok = parts.scheme in ("https", "http") and parts.netloc
        _SITE_CACHE.clear()
        _SITE_CACHE[key] = f"{parts.scheme}://{parts.netloc}" if ok else ""
    return _SITE_CACHE[key]


def fix_hint(pattern: str) -> str:
    """What a blocked agent should tell its person: the pattern to add, and where. Names
    the site from login (scheme and host only), or the Terminal page when it is unknown."""
    site = _site()
    roles = f"{site}/terminal/roles" if site else "the Terminal page"
    return (
        "This is the person's rule, not a fault to work around. If the tool is needed, ask "
        f"them to add {pattern} to this computer's role at {roles} (a built-in role such as "
        "Read-only cannot be edited: make a new role there and give it to the computer), "
        "or to give the computer a wider role on the Terminal page."
    )


def load_cached() -> dict[str, Any] | None:
    data = state.read_json("policy.json")
    return data if isinstance(data, dict) and "policy" in data else None


NEWEST = "policy_issued_at"  # in state.json: the newest signed policy accepted here


def pinned_keys(creds: dict[str, Any] | None = None) -> set[str]:
    """Every policy key this computer has been given, from any of the files that keep
    one. A signed policy must check out against all of them."""
    if creds is None:
        creds = state.read_json("credentials.json", {}) or {}
    found = [creds.get("policy_key") if isinstance(creds, dict) else None]
    for name in ("state.json", identity.KEY_FILE):
        data = state.read_json(name, {})
        found.append(data.get("policy_key") if isinstance(data, dict) else None)
    return {k for k in found if isinstance(k, str) and k}


def _default_server(creds: dict[str, Any]) -> bool:
    server = str(creds.get("server") or "").rstrip("/")
    return not server or server == DEFAULT_SERVER.rstrip("/")


def _issued(policy: dict[str, Any]) -> float:
    try:
        return float(policy.get("issued_at") or 0)
    except (TypeError, ValueError):
        return 0.0


def check_policy(policy: Any, creds: Any = None) -> str:
    """ "" when `policy` may be used here, else why not."""
    if creds is None:
        creds = state.read_json("credentials.json")
    if not isinstance(creds, dict):
        return "not logged in: run botrbac login"
    if not isinstance(policy, dict):
        return "no policy yet: run botrbac login"
    keys = pinned_keys(creds)
    if not (keys or policy.get("signature") or _default_server(creds)):
        return ""  # a self-hosted server without a signing key, never seen with one
    tampered = (
        "botrbac's saved role was changed on this computer, so every tool is "
        "blocked: run botrbac sync"
    )
    # A signed policy with no key to check it against means the key was removed.
    if not keys or not all(signing.verify(k, policy) for k in keys):
        return tampered
    terminal = policy.get("terminal")
    tid = creds.get("terminal_id")
    if tid and (not isinstance(terminal, dict) or terminal.get("id") != tid):
        return (
            "botrbac's saved role is for another terminal, so every tool is blocked: "
            "run botrbac sync"
        )
    newest = (state.read_json("state.json", {}) or {}).get(NEWEST)
    try:
        newest = float(newest or 0)
    except (TypeError, ValueError):
        return tampered
    if _issued(policy) < newest:
        return (
            "botrbac's saved role is older than one this computer already had, so every "
            "tool is blocked: run botrbac sync"
        )
    return ""


def save(policy: dict[str, Any]) -> None:
    """Cache a policy from the server. One that does not check out is not cached (the
    one already here stays), and a good signed one moves the newest-seen mark."""
    with state.file_lock(".policy.lock"):
        if check_policy(policy):
            return
        state.write_json("policy.json", {"policy": policy, "fetched_at": time.time()})
        if policy.get("signature"):
            data = state.read_json("state.json", {}) or {}
            issued = _issued(policy)
            if issued > float(data.get(NEWEST) or 0):
                data[NEWEST] = issued
                state.write_json("state.json", data)


def refresh(api: Any) -> dict[str, Any] | None:
    """Fetch and cache the policy; None when the server cannot be reached. A policy
    that does not check out here is returned but not cached (save)."""
    try:
        policy = api.policy()
    except Exception:  # noqa: BLE001 - offline, server down, or logged out
        return None
    if not isinstance(policy, dict):
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
        creds = state.read_json("credentials.json")
        if not isinstance(creds, dict):
            return None, "not logged in: run botrbac login"
        cached = load_cached()
        if cached is None:
            return None, "no policy yet: run botrbac login"
        policy = cached["policy"]
        why = check_policy(policy, creds)
        if why:
            return None, why
        pinned = bool(policy.get("signature"))
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

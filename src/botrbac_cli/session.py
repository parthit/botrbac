"""`botrbac run --role NAME -- command`: start an agent with a narrower role.

The session's tools are the intersection of the terminal's role, every parent
session's role, and the role asked for. A session started inside another one (a
subagent, `codex exec`, a script) inherits BOTRBAC_SESSION from its parent's
environment, so it can only ever narrow. Revoking a session on the website ends it
and everything started under it at the next policy check.
"""

import contextlib
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from . import policy, state
from .queue import AuditQueue


class SessionError(Exception):
    pass


def find_role(pol: dict[str, Any], wanted: str) -> dict[str, Any] | None:
    key = wanted.strip().lower()
    for role in pol.get("roles") or []:
        if str(role.get("id", "")).lower() == key or str(role.get("name", "")).lower() == key:
            return role
    return None


def start(role_name: str, program: str, agent: str | None = None) -> dict[str, Any]:
    cached = policy.load_cached()
    if cached is None:
        raise SessionError("No policy on this computer yet. Run: botrbac login")
    pol = cached["policy"]
    role = find_role(pol, role_name)
    if role is None:
        names = ", ".join(str(r.get("name")) for r in pol.get("roles") or [])
        raise SessionError(f"No role called {role_name!r}. Your roles: {names}")
    parent = policy.load_session(os.environ.get(policy.SESSION_ENV))
    if os.environ.get(policy.SESSION_ENV) and parent is None:
        raise SessionError("This shell is in a session botrbac does not know. Refusing.")
    session_id = uuid.uuid4().hex
    session = {
        "id": session_id,
        "parent": parent["id"] if parent else None,
        "lineage": [*(parent.get("lineage") or [parent["id"]]), session_id]
        if parent
        else [session_id],
        "chain": [*(parent.get("chain") or []), list(role.get("patterns") or [])]
        if parent
        else [list(role.get("patterns") or [])],
        "role_id": role.get("id"),
        "role_name": role.get("name"),
        "program": Path(program).name,
        "created": time.time(),
    }
    state.write_json(f"sessions/{session_id}.json", session, private=True)
    row: dict[str, Any] = {
        "decision": "session",
        "session_id": session_id,
        "role": str(role.get("name")),
        "program": Path(program).name,
        "agent": agent or Path(program).name,
        "reason": "started",
    }
    if parent:
        row["parent_session_id"] = parent["id"]
    AuditQueue().add(**row)
    return session


def run(role_name: str, command: list[str], agent: str | None, api: Any) -> int:
    if not command:
        raise SessionError("Give the command to run after --, e.g. botrbac run --role X -- claude")
    if api is not None:
        policy.refresh(api)  # best effort: a fresh role list, or the cached one offline
    session = start(role_name, command[0], agent)
    terminal_role = (policy.load_cached() or {}).get("policy", {}).get("role", {}).get("name")
    note = f" within this terminal's role {terminal_role!r}" if terminal_role else ""
    print(
        f"botrbac: session {session['id'][:8]} as {session['role_name']!r}{note}.",
        file=sys.stderr,
    )
    env = {
        **os.environ,
        policy.SESSION_ENV: session["id"],
        "BOTRBAC_ROLE": str(session["role_name"]),
    }
    try:
        code = subprocess.call(command, env=env)  # noqa: S603 - the person's own command
    except FileNotFoundError:
        print(f"botrbac: {command[0]} not found", file=sys.stderr)
        code = 127
    if api is not None:
        from .sync import sync

        # Offline: the rows wait for the next sync.
        with contextlib.suppress(Exception):
            sync(api, AuditQueue())
    return code

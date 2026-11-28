"""`botrbac run --role NAME -- command`: start an agent with a narrower role.

The session's tools are the intersection of the terminal's role, every parent
session's role, and the role asked for. A session started inside another one (a
subagent, `codex exec`, a script) inherits BOTRBAC_SESSION from its parent's
environment, so it can only ever narrow. Revoking a session on the website ends it
and everything started under it at the next policy check.
"""

import contextlib
import os
import shlex
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
    """By exact id first, then by name (any case). Two roles with that name is an error,
    never a silent pick."""
    roles = [r for r in pol.get("roles") or [] if isinstance(r, dict)]
    for role in roles:
        if str(role.get("id", "")) == wanted.strip():
            return role
    key = wanted.strip().lower()
    named = [r for r in roles if str(r.get("name", "")).lower() == key]
    if len(named) > 1:
        ids = ", ".join(str(r.get("id")) for r in named)
        raise SessionError(f"More than one role is called {wanted!r}. Use its id: {ids}")
    return named[0] if named else None


def _names(parent: dict[str, Any] | None) -> list[str]:
    """The role names of the sessions this one starts inside, outermost first."""
    if not parent:
        return []
    chain = parent.get("chain") or []
    names = parent.get("role_names")
    if isinstance(names, list) and len(names) == len(chain):
        return [str(n) for n in names]
    return [str(parent.get("role_name"))] * len(chain)  # started by an older botrbac


def start(
    role_name: str,
    program: str,
    agent: str | None = None,
    command: list[str] | None = None,
    task: str | None = None,
) -> dict[str, Any]:
    """`task` (from --task) is what the person says the session is for. Like the
    command line, it is recorded only sealed, with "Record commands" on."""
    cached = policy.load_cached()
    if cached is None:
        raise SessionError("No policy on this computer yet. Run: botrbac login")
    pol = cached["policy"]
    why = policy.check_policy(pol)
    if why:
        # Roles to narrow to come only from a policy this computer trusts.
        raise SessionError(why)
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
        # Each role's name, alongside `chain`, so a refusal can name the role that refused.
        "role_names": [*_names(parent), str(role.get("name"))],
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
    # The whole command line is recorded only sealed, with "Record commands" on.
    AuditQueue().add(
        command=shlex.join(command) if command else None,
        sealed={"task": task.strip() if task and task.strip() else None},
        **row,
    )
    return session


def run(
    role_name: str, command: list[str], agent: str | None, api: Any, task: str | None = None
) -> int:
    if not command:
        raise SessionError("Give the command to run after --, e.g. botrbac run --role X -- claude")
    if api is not None:
        policy.refresh(api)  # best effort: a fresh role list, or the cached one offline
    session = start(role_name, command[0], agent, command, task)
    terminal_role = (policy.load_cached() or {}).get("policy", {}).get("role", {}).get("name")
    note = f" within this terminal's role {terminal_role!r}" if terminal_role else ""
    outer = session["role_names"][:-1]
    if outer:
        # Asking for a wider role inside a session changes nothing: say so up front.
        inside = ", ".join(repr(n) for n in reversed(outer))
        note = f", inside {inside}{note}. A run only narrows: a tool must be in all of them"
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
    if code < 0:
        code = 128 - code  # killed by a signal: report it the way a shell does
    if api is not None:
        from .sync import sync

        # Offline: the rows wait for the next sync.
        with contextlib.suppress(Exception):
            sync(api, AuditQueue())
    return code

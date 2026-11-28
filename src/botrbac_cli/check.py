"""`botrbac check`: the hook adapter for an agent's own tools (shell, file edits, ...).

An agent's pre-tool hook runs `botrbac check --agent NAME` with the tool call as JSON on
stdin. The tool is checked as `<agent>/<tool>` (for example `claude-code/Bash`) against
the same role and session as the gateway. Exit 0 allows the call; exit 2 blocks it and
prints the reason on stderr, which is how Claude Code's PreToolUse hooks block a call.
`--format json` prints {"decision": ..., "reason": ...} for agents that read JSON.

MCP tools that come through `botrbac gateway` (`mcp__botrbac__*`) are allowed here: the
gateway checks and logs them. The prefix is not taken on trust (see `impostor`). Other
MCP tools are checked as `<server>/<tool>`, or blocked outright with `--block-unguarded`,
so an agent cannot go around the gateway.

A shell tool (Claude Code's Bash, Codex's shell, Gemini's run_shell_command; see
shellcmd.SHELL_TOOLS) is checked twice when the role has `cmd/` patterns: the tool
itself, then every program in its command as `cmd/<program>`. The row's reason names
programs only. The command itself (or another tool's input) is recorded only when the
person turned on "Record commands", and then only sealed to the website's key. A tool's
own `description` field (Bash's one-line summary, written by the model) is never kept:
what the model says about its own command is not evidence of why it ran.

The same command handles more hook events, by the payload's `hook_event_name`:
UserPromptSubmit writes a `prompt` row (the prompt sealed, with Record commands on),
PostToolUse and PostToolUseFailure a `result` row (outcome, exit code, sizes; never the
result). Those always exit 0 and print nothing. Any other event is a PreToolUse check.
Rows also carry the agent's own ids, the cwd and its git checkout (provenance.py).
"""

import json
import re
import sys
from pathlib import Path
from typing import Any

from . import agents, policy, provenance, state
from .coverage import GATEWAY_NAME, is_gateway, known_configs, servers_in
from .gateway import safe_tool
from .patterns import COMMAND_SERVER, normalize_server
from .protect import refusal
from .queue import AuditQueue
from .sealing import describe
from .shellcmd import CommandError, command_text, is_shell_tool, programs

GATEWAY_PREFIX = "mcp__botrbac__"
# Hook events that only record. Every other event (PreToolUse, or none) is a check.
PROMPT_EVENTS = frozenset({"UserPromptSubmit"})
# Event -> whether the call failed.
RESULT_EVENTS = {"PostToolUse": False, "PostToolUseFailure": True}
_NAME_KEYS = ("tool_name", "toolName", "tool", "name")


def tool_name(payload: Any) -> str:
    if isinstance(payload, dict):
        for key in _NAME_KEYS:
            value = payload.get(key)
            if isinstance(value, str) and value:
                return value
            if isinstance(value, dict) and isinstance(value.get("name"), str):
                return value["name"]
    return ""


def _server_part(name: str) -> str:
    """A server or agent name as the first half of a tool id. `cmd` is reserved for
    `cmd/<program>` patterns, so an MCP server (or agent) called `cmd` is checked as
    `cmd-upstream/…`, the name the gateway gives it too (coverage._free_name): its tools
    can never match a `cmd/` pattern."""
    server = normalize_server(name)
    return f"{server}-upstream" if server == COMMAND_SERVER else server


def _as_agents_name_it(server: str) -> str:
    """A server's name as it appears inside `mcp__<server>__<tool>`."""
    return re.sub(r"[^A-Za-z0-9_-]", "_", server)


def impostor(name: str, cwd: str | None = None) -> str:
    """Why a tool named `mcp__botrbac__…` is not the gateway's, or "" when it is.

    The name alone proves nothing: a server called `botrbac__x`, or one called `botrbac`
    that runs something else, gets the same prefix. So the name must also fit what is
    on this computer: no configured server other than the gateway may own the prefix,
    and the rest must be a tool the gateway itself offered. Anything else is checked
    like any server that goes around the gateway."""
    servers: list[tuple[str, Any]] = []
    try:
        configs = known_configs(Path(cwd) if cwd else None)
    except OSError:
        # No working folder to look in: nothing here can show the call is the gateway's.
        return "botrbac could not read this folder's MCP servers"
    for config in configs:
        servers.extend(servers_in(config).items())
    for server, spec in servers:
        shown = _as_agents_name_it(server)
        if shown == GATEWAY_NAME:
            if not is_gateway(spec):
                return "a server called botrbac here does not run the botrbac gateway"
        elif shown.startswith(GATEWAY_NAME + "__") and name.startswith(f"mcp__{shown}__"):
            return f"it belongs to the server {server}, not to the botrbac gateway"
    offered = state.routes()
    if offered is not None and name[len(GATEWAY_PREFIX) :] not in offered:
        return "the botrbac gateway does not offer a tool with this name"
    return ""


def classify(agent: str, name: str, cwd: str | None = None) -> tuple[str, bool]:
    """(tool id, is an MCP tool that bypasses the gateway)."""
    if name.startswith(GATEWAY_PREFIX):
        if not impostor(name, cwd):
            return "", False
        rest = name[len(GATEWAY_PREFIX) :]
        return f"{GATEWAY_NAME}-upstream/{safe_tool(rest or 'tool')}", True
    if name.startswith("mcp__"):
        _, server, rest = (name.split("__", 2) + ["", ""])[:3]
        return f"{_server_part(server)}/{safe_tool(rest or 'tool')}", True
    return f"{_server_part(agent)}/{safe_tool(name)}", False


def check(agent: str, raw: str, tool: str | None, block_unguarded: bool) -> tuple[bool, str]:
    payload: Any = None
    if tool is None:
        try:
            payload = json.loads(raw) if raw.strip() else {}
        except ValueError:
            return False, "botrbac could not read the tool call"
    return _check(agent, payload, tool, block_unguarded)


def _check(agent: str, payload: Any, tool: str | None, block_unguarded: bool) -> tuple[bool, str]:
    """PreToolUse: allow or block one call. `payload` is None with `--tool`."""
    if tool is None:
        payload = agents.normalize(agent, payload)  # Cursor's and Gemini's shapes
        tool = tool_name(payload)
    if not tool:
        return False, "botrbac could not tell which tool this is"
    cwd = payload.get("cwd") if isinstance(payload, dict) else None
    tool_id, bypass = classify(agent, tool, cwd if isinstance(cwd, str) else None)
    if not tool_id:
        return True, "checked by the gateway"
    row: dict[str, Any] = {
        "tool": tool_id,
        "agent": normalize_server(agent),
        "via": "hook",
        **policy.session_fields(),
    }
    tool_input = payload.get("tool_input") if isinstance(payload, dict) else None
    row.update(provenance.hook_fields(payload))
    row.update(provenance.git_context(row.get("cwd")))
    row["command"] = _what_ran(agent, tool, payload, tool_input)
    guarded = refusal(tool, tool_input if tool_input is not None else payload)
    if guarded:
        _record(decision="deny", reason="protected file", role="", **row)
        return False, f"Blocked by Bot RBAC: {tool_id}: {guarded}."
    if bypass and block_unguarded:
        reason = "MCP servers must go through botrbac gateway (run: botrbac wrap)"
        if tool.startswith(GATEWAY_PREFIX):
            reason = impostor(tool, cwd if isinstance(cwd, str) else None) or reason
        _record(decision="deny", reason=reason, role="", **row)
        return False, f"Blocked by Bot RBAC: {tool_id}: {reason}"
    enforcer = policy.Enforcer()
    decision = enforcer.decide(tool_id)
    # A role that lists programs limits every one of the agent's own tools that runs a
    # command line, not only the shell tools known by name: a tool this version has not
    # heard of (a background or PowerShell runner) must not be a way around `cmd/`.
    runs_command = is_shell_tool(normalize_server(agent), tool) or (
        not tool.startswith("mcp__")
        and isinstance(tool_input, dict)
        and isinstance(tool_input.get("command"), str | list)
    )
    by_command = decision.allowed and runs_command and enforcer.limits_commands()
    if by_command:
        decision = _decide_command(enforcer, payload, decision.role)
    _record(
        decision="allow" if decision.allowed else "deny",
        reason=decision.reason,
        role=decision.role,
        **row,
    )
    if decision.allowed:
        return True, "ok"
    if by_command:
        return False, (
            f"Blocked by Bot RBAC: {decision.reason}. Run allowed programs one at a time. "
            + policy.fix_hint("cmd/<program>")
        )
    return False, (
        f"Blocked by Bot RBAC: {tool_id} is {decision.reason}. " + policy.fix_hint(tool_id)
    )


def _what_ran(agent: str, tool: str, payload: Any, tool_input: Any) -> str | None:
    """What the call asked for: a shell tool's command line, or another tool's input.
    None when the hook was given no call (`--tool`)."""
    if payload is None:
        return None
    if is_shell_tool(normalize_server(agent), tool):
        command = command_text(payload)
        if command is not None:
            return command
    return describe(tool_input if tool_input is not None else payload)


def observe(agent: str, payload: Any, event: str) -> None:
    """UserPromptSubmit, PostToolUse and PostToolUseFailure: write a `prompt` or
    `result` row. These hooks never block anything and print nothing."""
    name = normalize_server(agent)
    extra = policy.session_fields()
    if event in PROMPT_EVENTS:
        row, text = provenance.prompt_row(name, payload)
        _record(command=text, **row, **extra)
        return
    tool = tool_name(payload)
    tool_id, _bypass = classify(agent, tool) if tool else ("", False)
    if not tool_id:
        return  # the gateway records its own tools' results
    row = provenance.result_row(name, tool_id, payload, RESULT_EVENTS[event])
    _record(**row, **extra)


def _decide_command(enforcer: policy.Enforcer, payload: Any, role: str) -> policy.Decision:
    """The shell tool is allowed; now every program in its command must be. Anything
    that cannot be read is blocked. The reason names programs, never the command."""
    command = command_text(payload)
    if command is None:
        return policy.Decision(False, "botrbac could not find the shell command", role)
    try:
        found = programs(command)
    except CommandError as exc:
        return policy.Decision(False, str(exc), role)
    decision = enforcer.decide_programs(found)
    if decision.allowed:
        decision.reason = "ok: runs " + ", ".join(found[:10])
    return decision


def _record(**row: Any) -> None:
    """Write the audit row. A failure here (a full or read-only disk) is reported, but
    does not change the decision already made."""
    try:
        AuditQueue().add(**row)
    except Exception as exc:  # noqa: BLE001
        print(f"botrbac: could not record this call: {exc}", file=sys.stderr)


_UNREADABLE = object()


def _observe_quietly(agent: str, payload: Any, event: str) -> int:
    """Exit 0 whatever happens: these hooks must never block the agent, and on stdout
    UserPromptSubmit would add text to the conversation."""
    try:
        observe(agent, payload, event)
    except Exception as exc:  # noqa: BLE001
        print(f"botrbac: could not record this {event}: {type(exc).__name__}", file=sys.stderr)
    return 0


def run(agent: str, tool: str | None, block_unguarded: bool, fmt: str) -> int:
    """Any unexpected error blocks the call. Claude Code only blocks on exit code 2: an
    uncaught exception (exit 1) would let the tool run."""
    try:
        # All of it: a large Write or Edit carries the whole file in tool_input.
        raw = "" if tool is not None else sys.stdin.read()
        payload: Any = None
        if tool is None:
            try:
                payload = json.loads(raw) if raw.strip() else {}
            except ValueError:
                payload = _UNREADABLE
            event = provenance.event_name(payload)
            if event in PROMPT_EVENTS or event in RESULT_EVENTS:
                return _observe_quietly(agent, payload, event)
        if payload is _UNREADABLE:
            allowed, reason = False, "botrbac could not read the tool call"
        else:
            allowed, reason = _check(agent, payload, tool, block_unguarded)
    except Exception as exc:  # noqa: BLE001 - fail closed
        allowed, reason = False, f"Blocked by Bot RBAC: the check failed ({type(exc).__name__})"
    if fmt == "json":
        print(json.dumps({"decision": "allow" if allowed else "deny", "reason": reason}))
        return 0
    answer = agents.response(agent, allowed, reason)  # Cursor reads JSON, not the exit code
    if answer is not None:
        print(answer)
        return 0
    if not allowed:
        print(reason, file=sys.stderr)
        return 2
    return 0

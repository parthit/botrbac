"""`botrbac check`: the hook adapter for an agent's own tools (shell, file edits, ...).

An agent's pre-tool hook runs `botrbac check --agent NAME` with the tool call as JSON on
stdin. The tool is checked as `<agent>/<tool>` (for example `claude-code/Bash`) against
the same role and session as the gateway. Exit 0 allows the call; exit 2 blocks it and
prints the reason on stderr, which is how Claude Code's PreToolUse hooks block a call.
`--format json` prints {"decision": ..., "reason": ...} for agents that read JSON.

MCP tools that come through `botrbac gateway` (`mcp__botrbac__*`) are allowed here: the
gateway checks and logs them. Other MCP tools are checked as `<server>/<tool>`, or
blocked outright with `--block-unguarded`, so an agent cannot go around the gateway.

A shell tool (Claude Code's Bash, Codex's shell, Gemini's run_shell_command; see
shellcmd.SHELL_TOOLS) is checked twice when the role has `cmd/` patterns: the tool
itself, then every program in its command as `cmd/<program>`. The row's reason names
programs only. The command itself (or another tool's input) is recorded only when the
person turned on "Record commands", and then only sealed to the website's key.
"""

import json
import sys
from typing import Any

from . import policy
from .gateway import safe_tool
from .patterns import normalize_server
from .protect import refusal
from .queue import AuditQueue
from .sealing import describe
from .shellcmd import CommandError, command_text, is_shell_tool, programs

GATEWAY_PREFIX = "mcp__botrbac__"
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


def classify(agent: str, name: str) -> tuple[str, bool]:
    """(tool id, is an MCP tool that bypasses the gateway)."""
    if name.startswith(GATEWAY_PREFIX):
        return "", False
    if name.startswith("mcp__"):
        _, server, rest = (name.split("__", 2) + ["", ""])[:3]
        return f"{normalize_server(server)}/{safe_tool(rest or 'tool')}", True
    return f"{normalize_server(agent)}/{safe_tool(name)}", False


def check(agent: str, raw: str, tool: str | None, block_unguarded: bool) -> tuple[bool, str]:
    payload: Any = None
    if tool is None:
        try:
            payload = json.loads(raw) if raw.strip() else {}
        except ValueError:
            return False, "botrbac could not read the tool call"
        tool = tool_name(payload)
    if not tool:
        return False, "botrbac could not tell which tool this is"
    tool_id, bypass = classify(agent, tool)
    if not tool_id:
        return True, "checked by the gateway"
    row: dict[str, Any] = {
        "tool": tool_id,
        "agent": normalize_server(agent),
        "via": "hook",
        **policy.session_fields(),
    }
    tool_input = payload.get("tool_input") if isinstance(payload, dict) else None
    row["command"] = _what_ran(agent, tool, payload, tool_input)
    guarded = refusal(tool, tool_input if tool_input is not None else payload)
    if guarded:
        _record(decision="deny", reason="protected file", role="", **row)
        return False, f"Blocked by Bot RBAC: {tool_id}: {guarded}."
    if bypass and block_unguarded:
        reason = "MCP servers must go through botrbac gateway (run: botrbac wrap)"
        _record(decision="deny", reason=reason, role="", **row)
        return False, f"Blocked by Bot RBAC: {tool_id}: {reason}"
    enforcer = policy.Enforcer()
    decision = enforcer.decide(tool_id)
    by_command = (
        decision.allowed
        and is_shell_tool(normalize_server(agent), tool)
        and enforcer.limits_commands()
    )
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
            f"Blocked by Bot RBAC: {decision.reason}. Run allowed programs one at a time, "
            "or ask the person to add cmd/<program> to the role on the Terminal page."
        )
    return False, (
        f"Blocked by Bot RBAC: {tool_id} is {decision.reason}. "
        "Ask the person to change the role on the Terminal page if this tool is needed."
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


def run(agent: str, tool: str | None, block_unguarded: bool, fmt: str) -> int:
    """Any unexpected error blocks the call. Claude Code only blocks on exit code 2: an
    uncaught exception (exit 1) would let the tool run."""
    try:
        # All of it: a large Write or Edit carries the whole file in tool_input.
        raw = "" if tool is not None else sys.stdin.read()
        allowed, reason = check(agent, raw, tool, block_unguarded)
    except Exception as exc:  # noqa: BLE001 - fail closed
        allowed, reason = False, f"Blocked by Bot RBAC: the check failed ({type(exc).__name__})"
    if fmt == "json":
        print(json.dumps({"decision": "allow" if allowed else "deny", "reason": reason}))
        return 0
    if not allowed:
        print(reason, file=sys.stderr)
        return 2
    return 0

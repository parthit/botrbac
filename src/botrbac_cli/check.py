"""`botrbac check`: the hook adapter for an agent's own tools (shell, file edits, ...).

An agent's pre-tool hook runs `botrbac check --agent NAME` with the tool call as JSON on
stdin. The tool is checked as `<agent>/<tool>` (for example `claude-code/Bash`) against
the same role and session as the gateway. Exit 0 allows the call; exit 2 blocks it and
prints the reason on stderr, which is how Claude Code's PreToolUse hooks block a call.
`--format json` prints {"decision": ..., "reason": ...} for agents that read JSON.

MCP tools that come through `botrbac gateway` (`mcp__botrbac__*`) are allowed here: the
gateway checks and logs them. Other MCP tools are checked as `<server>/<tool>`, or
blocked outright with `--block-unguarded`, so an agent cannot go around the gateway.
"""

import json
import sys
from typing import Any

from . import policy
from .gateway import safe_tool
from .patterns import normalize_server
from .queue import AuditQueue

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
    if bypass and block_unguarded:
        reason = "MCP servers must go through botrbac gateway (run: botrbac wrap)"
        AuditQueue().add(decision="deny", reason=reason, role="", **row)
        return False, f"Blocked by Bot RBAC: {tool_id}: {reason}"
    decision = policy.Enforcer().decide(tool_id)
    AuditQueue().add(
        decision="allow" if decision.allowed else "deny",
        reason=decision.reason,
        role=decision.role,
        **row,
    )
    if decision.allowed:
        return True, "ok"
    return False, (
        f"Blocked by Bot RBAC: {tool_id} is {decision.reason}. "
        "Ask the person to change the role on the Terminal page if this tool is needed."
    )


def run(agent: str, tool: str | None, block_unguarded: bool, fmt: str) -> int:
    raw = "" if tool is not None else sys.stdin.read(1_000_000)
    allowed, reason = check(agent, raw, tool, block_unguarded)
    if fmt == "json":
        print(json.dumps({"decision": "allow" if allowed else "deny", "reason": reason}))
        return 0
    if not allowed:
        print(reason, file=sys.stderr)
        return 2
    return 0

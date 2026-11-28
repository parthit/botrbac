"""A terminal's coverage report: which agents are on the computer and which are checked.

The CLI sends it with each sync as `coverage` (botrbac_cli.agents.coverage_summary):
`{"agents_detected": [...], "agents_hooked": [...], "hook_off": [...],
"unguarded_servers": N}`. It is the computer's own say-so, shown on the Terminal page as
a hint, never used to decide anything. Anything unexpected is dropped.
"""

import re
from typing import Any

_AGENT = re.compile(r"[a-z][a-z0-9-]{0,39}")
_LISTS = ("agents_detected", "agents_hooked", "hook_off")
MAX_AGENTS = 10
MAX_SERVERS = 10**6


def _agents(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value[: MAX_AGENTS * 2]:
        if isinstance(item, str) and _AGENT.fullmatch(item) and item not in out:
            out.append(item)
    return out[:MAX_AGENTS]


def clean_coverage(value: Any) -> dict[str, Any] | None:
    """The report as stored, or None when there is none to store."""
    if not isinstance(value, dict):
        return None
    out: dict[str, Any] = {key: _agents(value.get(key)) for key in _LISTS}
    servers = value.get("unguarded_servers")
    if isinstance(servers, int) and not isinstance(servers, bool) and servers >= 0:
        out["unguarded_servers"] = min(servers, MAX_SERVERS)
    else:
        out["unguarded_servers"] = 0
    return out


def unhooked(coverage: dict[str, Any] | None) -> list[str]:
    """Agents found on the computer whose own tools botrbac does not check."""
    if not coverage:
        return []
    hooked = set(coverage.get("agents_hooked") or [])
    return [a for a in coverage.get("agents_detected") or [] if a not in hooked]

"""Tool patterns, shared by the website (roles) and the CLI (enforcement).

A tool is named `server/tool`: `github/create_issue`, `fs/read_file`, `claude-code/Bash`.
A pattern is one of:

- `*`                 every tool
- `server/*`          every tool on one server (`*/tool` is any server)
- `server/tool`       one tool
- `server/prefix*`    tools whose name starts with `prefix`

A role is a list of patterns. A session narrows a role by adding more lists; a tool is
allowed only when every list in the chain allows it. Pure Python, no imports from the
server, so the CLI can use it on its own.
"""

import re

_SERVER = r"[a-z0-9][a-z0-9_.-]{0,63}"
_TOOL = r"[A-Za-z0-9_.:-]{1,128}"
_PATTERN = re.compile(rf"^(\*|{_SERVER})/(\*|{_TOOL}\*?)$")
_TOOL_ID = re.compile(rf"^{_SERVER}/{_TOOL}$")
MAX_PATTERNS = 200


class PatternError(ValueError):
    """A pattern that does not follow the grammar above."""


def normalize_server(name: str) -> str:
    """A server name as it appears in tool ids: lower case, other characters as '-'."""
    cleaned = re.sub(r"[^a-z0-9_.-]+", "-", name.strip().lower()).strip("-._")
    return (cleaned or "server")[:64]


def tool_id(server: str, tool: str) -> str:
    return f"{normalize_server(server)}/{tool}"


def is_tool_id(value: str) -> bool:
    return bool(_TOOL_ID.fullmatch(value))


def validate(pattern: str) -> str:
    value = pattern.strip()
    if value == "*":
        return value
    if not _PATTERN.fullmatch(value):
        raise PatternError(
            f"{value[:80]!r} is not a tool pattern. Use server/tool, server/*, server/prefix* or *."
        )
    return value


def validate_all(patterns: list[str]) -> list[str]:
    """Checked, de-duplicated, order kept."""
    out: list[str] = []
    for raw in patterns:
        if not raw.strip():
            continue
        value = validate(raw)
        if value not in out:
            out.append(value)
    if len(out) > MAX_PATTERNS:
        raise PatternError(f"A role can have at most {MAX_PATTERNS} patterns.")
    return out


def matches(pattern: str, tool: str) -> bool:
    if pattern == "*":
        return True
    p_server, _, p_tool = pattern.partition("/")
    server, sep, name = tool.partition("/")
    if not sep:
        return False
    if p_server not in ("*", server):
        return False
    if p_tool == "*":
        return True
    if p_tool.endswith("*"):
        return name.startswith(p_tool[:-1])
    return name == p_tool


def allows(patterns: list[str], tool: str) -> bool:
    return any(matches(p, tool) for p in patterns)


def chain_allows(chain: list[list[str]], tool: str) -> bool:
    """Every list must allow the tool. An empty chain allows nothing (fail closed)."""
    return bool(chain) and all(allows(patterns, tool) for patterns in chain)

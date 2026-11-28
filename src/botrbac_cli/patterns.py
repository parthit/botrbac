"""Tool patterns, shared by the website (roles) and the CLI (enforcement).

A tool is named `server/tool`: `github/create_issue`, `fs/read_file`, `claude-code/Bash`.
A pattern is one of:

- `*`                 every tool
- `server/*`          every tool on one server (`*/tool` is any server)
- `server/tool`       one tool
- `server/prefix*`    tools whose name starts with `prefix`
- `cmd/program`       a program an agent's shell tool may run (`cmd/gh`, `cmd/git*`,
                      `cmd/*`); see `command_allowed`

A role is a list of patterns. A session narrows a role by adding more lists; a tool is
allowed only when every list in the chain allows it. Pure Python, no imports from the
server, so the CLI can use it on its own.
"""

import re

_SERVER = r"[a-z0-9][a-z0-9_.-]{0,63}"
_TOOL = r"[A-Za-z0-9_.:-]{1,128}"
_PATTERN = re.compile(rf"^(\*|{_SERVER})/(\*|{_TOOL}\*?)$")
_TOOL_ID = re.compile(rf"^{_SERVER}/{_TOOL}$")
_BARE_WORD = re.compile(r"^[A-Za-z0-9_.+-]{1,64}$")
MAX_PATTERNS = 200
# `cmd/<program>` patterns name programs a shell tool may run, not MCP tools.
COMMAND_SERVER = "cmd"


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
        if _BARE_WORD.fullmatch(value):
            raise PatternError(
                f"{value!r} is not a pattern. To allow the {value} command, use "
                f"cmd/{value}. For a tool, use server/tool (for example claude-code/{value})."
            )
        raise PatternError(
            f"{value[:80]!r} is not a tool pattern. Use server/tool, server/*, "
            "server/prefix*, cmd/program or *."
        )
    return value


def validate_all(patterns: list[str]) -> list[str]:
    """Checked, de-duplicated, order kept."""
    out: list[str] = []
    wrong: list[str] = []
    for raw in patterns:
        if not raw.strip():
            continue
        try:
            value = validate(raw)
        except PatternError as exc:
            # Every bad line in one go, so a long list is not fixed one save at a time.
            if len(wrong) < 5 and str(exc) not in wrong:
                wrong.append(str(exc))
            continue
        if value not in out:
            out.append(value)
    if wrong:
        raise PatternError(" ".join(wrong))
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


# ---- programs run by an agent's shell tool -------------------------------------------


def is_command_pattern(pattern: str) -> bool:
    return pattern.startswith(COMMAND_SERVER + "/")


def has_command_rules(patterns: list[str]) -> bool:
    """A list with no `cmd/` patterns does not limit which programs a shell runs."""
    return any(is_command_pattern(p) for p in patterns)


def command_allowed(patterns: list[str], program: str) -> bool:
    """Only `cmd/` patterns count here: `*` or `*/read*` never allow a program."""
    target = f"{COMMAND_SERVER}/{program}"
    return any(matches(p, target) for p in patterns if is_command_pattern(p))


def chain_allows_command(chain: list[list[str]], program: str) -> bool:
    """Every list that has `cmd/` patterns must allow the program; lists without any
    keep the shell all-or-nothing, as before. An empty chain allows nothing."""
    return bool(chain) and all(
        command_allowed(patterns, program) for patterns in chain if has_command_rules(patterns)
    )

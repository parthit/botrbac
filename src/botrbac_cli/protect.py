"""Files an agent must not change, whatever its role.

Bot RBAC's own controls live in files on the computer: Claude Code's settings (which hold
the hook), ~/.claude.json (which lists the MCP servers, including the gateway) and
botrbac's own folder (the cached role, sessions, the login). An agent that could edit
those could switch Bot RBAC off or widen its own role, so tool calls that name them are
refused for every role. Reading is allowed, except for the login (it holds tokens).

This reads the tool call's text. It stops an agent that writes to these files the
ordinary way (Edit/Write, `sed -i`, `echo >`, `rm`, an MCP file tool); it cannot follow
a path the agent builds at run time (variables, base64, a script it writes elsewhere).
It guards against the agent, not the person who owns the computer.
"""

import os
import re
from pathlib import Path
from typing import Any

from . import state

# Tools that only read. They may look at protected files, but not at the login.
READ_TOOLS = frozenset(
    {"Read", "Grep", "Glob", "LS", "NotebookRead", "read_file", "read_many_files",
     "list_directory", "search_file_content", "glob"}
)  # fmt: skip
_READ_PREFIXES = ("read", "get", "list", "search", "find", "view", "glob", "grep", "stat")
# A name that starts like a read but also says it writes (`get_and_write`) is not one.
_WRITE_WORDS = ("write", "edit", "update", "create", "delete", "remove", "move", "rename",
                "set", "put", "save", "patch", "append", "replace")  # fmt: skip


def _variants(path: Path) -> set[str]:
    """How a path may be written in a command: absolute, ~/…, $HOME/…, ${HOME}/…"""
    text = str(path)
    out = {text}
    home = str(Path.home())
    if text.startswith(home + os.sep):
        rest = text[len(home) + 1 :]
        out |= {f"~/{rest}", f"$HOME/{rest}", f"${{HOME}}/{rest}"}
    return {v.lower() for v in out}


def markers() -> tuple[set[str], set[str]]:
    """(text that marks a protected file, text that marks the login). Lower case."""
    home = Path.home()
    protected = {
        # Claude Code settings anywhere (user, project, local), and its MCP server list.
        ".claude/settings.json",
        ".claude/settings.local.json",
        ".claude.json",
        # botrbac's own folder, under its default name and wherever BOTRBAC_HOME puts it.
        ".config/botrbac",
    }
    protected |= _variants(home / ".claude" / "settings.json")
    protected |= _variants(state.home())
    protected |= {
        # Switching hooks off, or taking botrbac's out, by command or by settings text.
        "disableallhooks",
        "hooks remove",
    }
    login = {"botrbac/credentials.json"} | _variants(state.home() / "credentials.json")
    return {m.lower() for m in protected}, {m.lower() for m in login}


def _targets() -> tuple[list[Path], Path]:
    """(protected files and folders, the login file), with symlinks resolved."""
    home, cwd = Path.home(), Path.cwd()
    files = [
        home / ".claude" / "settings.json",
        home / ".claude" / "settings.local.json",
        home / ".claude.json",
        cwd / ".claude" / "settings.json",
        cwd / ".claude" / "settings.local.json",
        state.home(),
    ]
    return [Path(os.path.realpath(f)) for f in files], Path(
        os.path.realpath(state.home() / "credentials.json")
    )


def _paths(texts: list[str]) -> list[Path]:
    """The real files that arguments (and the words of a command) point to, through
    symlinks and `..`, for the ones that exist or could."""
    short = [t for t in texts if len(t) <= 4096]
    # Each whole argument (a path with spaces) and each word of it (a command's paths).
    words = short + [w.strip("'\"<>;|&()") for t in short for w in t.split()]
    return [p for p in (_resolved(w) for w in words[:200]) if p is not None]


def _resolved(text: str) -> Path | None:
    if not text or "\0" in text or "://" in text or text.startswith("-"):
        return None
    try:
        path = Path(os.path.expanduser(text))
        return Path(os.path.realpath(path if path.is_absolute() else Path.cwd() / path))
    except (OSError, ValueError, RuntimeError):
        return None


def _within(path: Path, target: Path) -> bool:
    return path == target or target in path.parents


def _strings(value: Any, depth: int = 0) -> list[str]:
    if depth > 6:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v, depth + 1)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v, depth + 1)]
    return []


def is_read_only(tool: str) -> bool:
    name = tool.rsplit("/", 1)[-1].rsplit("__", 1)[-1]
    if name in READ_TOOLS:
        return True
    lower = name.lower()
    words = re.split(r"[_\-.]+|(?<=[a-z])(?=[A-Z])", name)
    return lower.startswith(_READ_PREFIXES) and not any(
        w.lower().startswith(_WRITE_WORDS) for w in words[1:]
    )


def refusal(tool: str, arguments: Any) -> str | None:
    """Why this call must be refused, or None. `arguments` is the tool's input."""
    raw = _strings(arguments)
    texts = [s.lower() for s in raw]
    if not texts:
        return None
    protected, login = markers()
    targets, login_file = _targets()
    paths = _paths(raw)
    if any(m in t for t in texts for m in login) or any(p == login_file for p in paths):
        return "it names botrbac's login file, which holds its tokens"
    if is_read_only(tool):
        return None
    found = next((m for t in texts for m in sorted(protected) if m in t), None)
    if found is None:
        found = next((str(p) for p in paths for t in targets if _within(p, t)), None)
    if found is not None:
        return (
            f"it mentions {found!r}, which Bot RBAC protects (Claude Code's settings, "
            "~/.claude.json, botrbac's own folder, or switching hooks off). Ask the person "
            "to make that change"
        )
    return None

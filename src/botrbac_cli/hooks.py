"""`botrbac hooks install claude-code`: run `botrbac check` before every tool call.

Writes a PreToolUse hook into Claude Code's settings (the project's
.claude/settings.json, or ~/.claude/settings.json with --user), keeping everything else
in the file and a backup of it. Running it twice changes nothing. UserPromptSubmit,
PostToolUse and PostToolUseFailure hooks run the same command, which records the
prompt and each call's outcome there and never blocks.
"""

import json
import shlex
from pathlib import Path
from typing import Any

from . import state
from .coverage import backup_file, write_atomic
from .shell import botrbac_command

# Claude Code hook event -> its matcher (None: the event takes none). All run the same
# `botrbac check`, which reads the event from the payload: PreToolUse checks the call;
# the others only record (the prompt, the call's outcome) and never block.
EVENTS: dict[str, str | None] = {
    "PreToolUse": "*",
    "UserPromptSubmit": None,
    "PostToolUse": "*",
    "PostToolUseFailure": "*",
}


def hook_command(block_unguarded: bool) -> str:
    parts = [*botrbac_command(), "check", "--agent", "claude-code"]
    if block_unguarded:
        parts.append("--block-unguarded")
    return " ".join(shlex.quote(p) for p in parts)


def _ours(entry: Any) -> bool:
    """A hook entry this command added: it runs botrbac's own `check --agent`."""
    if not isinstance(entry, dict):
        return False
    for hook in entry.get("hooks") or []:
        if not isinstance(hook, dict):
            continue
        try:
            parts = shlex.split(str(hook.get("command", "")))
        except ValueError:
            continue
        runs_botrbac = bool(parts) and (
            Path(parts[0]).name == "botrbac" or parts[1:3] == ["-m", "botrbac_cli"]
        )
        if runs_botrbac and "check" in parts and "--agent" in parts:
            return True
    return False


def remove_claude_code(path: Path) -> dict[str, Any]:
    """Take out the hooks `install_claude_code` added, leaving everything else."""
    if not path.exists():
        return {"file": str(path), "backup": None, "changed": False}
    before = path.read_text()
    try:
        data = json.loads(before or "{}")
    except ValueError as exc:
        raise ValueError(f"{path} is not valid JSON; it was left as it is") from exc
    hooks = data.get("hooks") if isinstance(data, dict) else None
    if not isinstance(hooks, dict):
        return {"file": str(path), "backup": None, "changed": False}
    changed = False
    for event in EVENTS:
        existing = hooks.get(event)
        if not isinstance(existing, list) or not any(_ours(e) for e in existing):
            continue
        changed = True
        kept = [e for e in existing if not _ours(e)]
        if kept:
            hooks[event] = kept
        else:
            del hooks[event]
    if not changed:
        return {"file": str(path), "backup": None, "changed": False}
    if not hooks:
        del data["hooks"]
    backup = backup_file(path)
    write_atomic(path, json.dumps(data, indent=2) + "\n")
    return {"file": str(path), "backup": backup, "changed": True}


def install_claude_code(path: Path, block_unguarded: bool = True) -> dict[str, Any]:
    """Add (or update) the hooks. Writes, and backs up, only when something changes."""
    data: dict[str, Any] = {}
    before = None
    if path.exists():
        before = path.read_text()
        try:
            data = json.loads(before or "{}")
        except ValueError as exc:
            raise ValueError(f"{path} is not valid JSON; it was left as it is") from exc
        if not isinstance(data, dict):
            raise ValueError(f"{path} is not a JSON object; it was left as it is")
    hooks = data.setdefault("hooks", {})
    odd = not isinstance(hooks, dict) or any(
        not isinstance(hooks.get(event) or [], list) for event in EVENTS
    )
    if odd:
        raise ValueError(
            f"{path} has a hooks section botrbac does not understand; it was left as it is"
        )
    command = {"type": "command", "command": hook_command(block_unguarded)}
    for event, matcher in EVENTS.items():
        entries = [e for e in hooks.get(event) or [] if not _ours(e)]
        entry: dict[str, Any] = {"matcher": matcher} if matcher is not None else {}
        entry["hooks"] = [dict(command)]
        entries.append(entry)
        hooks[event] = entries
    text = json.dumps(data, indent=2) + "\n"
    if before is not None and json.loads(before or "{}") == data:
        return {"file": str(path), "backup": None, "changed": False}
    backup = backup_file(path) if before is not None else None
    write_atomic(path, text)
    return {"file": str(path), "backup": backup, "changed": True}


# ---- is the hook still there? -----------------------------------------------------


def claude_code_settings_files(cwd: Path | None = None) -> list[Path]:
    """Every Claude Code settings file that can hold (or switch off) hooks here."""
    here = cwd or Path.cwd()
    home = Path.home() / ".claude"
    return [
        home / "settings.json",
        home / "settings.local.json",
        here / ".claude" / "settings.json",
        here / ".claude" / "settings.local.json",
    ]


def claude_code_hook_status(cwd: Path | None = None) -> str:
    """ "installed", "missing" or "disabled" (hooks switched off with disableAllHooks)."""
    found = False
    for path in claude_code_settings_files(cwd):
        try:
            data = json.loads(path.read_text() or "{}")
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        if data.get("disableAllHooks") is True:
            return "disabled"
        hooks = data.get("hooks")
        entries = hooks.get("PreToolUse") if isinstance(hooks, dict) else None
        if isinstance(entries, list) and any(_ours(e) for e in entries):
            found = True
    return "installed" if found else "missing"


def expect_hook(agent: str, expected: bool) -> None:
    """Remember that this computer should have the hook, so doctor and the website can
    say when it goes missing. Uninstalling with `hooks remove` clears it."""
    data = state.read_json("state.json", {}) or {}
    agents = set(data.get("hooks_expected") or [])
    agents = agents | {agent} if expected else agents - {agent}
    data["hooks_expected"] = sorted(agents)
    state.write_json("state.json", data)


def hook_report(cwd: Path | None = None) -> dict[str, str]:
    """{agent: status} for every agent botrbac installed a hook for."""
    data = state.read_json("state.json", {}) or {}
    report: dict[str, str] = {}
    for agent in data.get("hooks_expected") or []:
        if agent == "claude-code":
            report[agent] = claude_code_hook_status(cwd)
    return report

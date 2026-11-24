"""`botrbac hooks install claude-code`: run `botrbac check` before every tool call.

Writes a PreToolUse hook into Claude Code's settings (the project's
.claude/settings.json, or ~/.claude/settings.json with --user), keeping everything else
in the file and a backup of it. Running it twice changes nothing.
"""

import json
import shlex
from pathlib import Path
from typing import Any

from .coverage import backup_file, write_atomic
from .shell import botrbac_command


def hook_command(block_unguarded: bool) -> str:
    parts = [*botrbac_command(), "check", "--agent", "claude-code"]
    if block_unguarded:
        parts.append("--block-unguarded")
    return " ".join(shlex.quote(p) for p in parts)


def _ours(entry: Any) -> bool:
    """A PreToolUse entry this command added: it runs botrbac's own `check --agent`."""
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


def install_claude_code(path: Path, block_unguarded: bool = True) -> dict[str, Any]:
    """Add (or update) the hook. Writes, and backs up, only when something changes."""
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
    existing = hooks.get("PreToolUse") if isinstance(hooks, dict) else None
    if not isinstance(hooks, dict) or not isinstance(existing or [], list):
        raise ValueError(
            f"{path} has a hooks section botrbac does not understand; it was left as it is"
        )
    entries = [e for e in existing or [] if not _ours(e)]
    entries.append(
        {
            "matcher": "*",
            "hooks": [{"type": "command", "command": hook_command(block_unguarded)}],
        }
    )
    hooks["PreToolUse"] = entries
    text = json.dumps(data, indent=2) + "\n"
    if before is not None and json.loads(before or "{}") == data:
        return {"file": str(path), "backup": None, "changed": False}
    backup = backup_file(path) if before is not None else None
    write_atomic(path, text)
    return {"file": str(path), "backup": backup, "changed": True}

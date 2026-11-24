"""`botrbac hooks install claude-code`: run `botrbac check` before every tool call.

Writes a PreToolUse hook into Claude Code's settings (the project's
.claude/settings.json, or ~/.claude/settings.json with --user), keeping everything else
in the file and a backup of it. Running it twice changes nothing.
"""

import json
import shlex
import shutil
import time
from pathlib import Path
from typing import Any

from .shell import botrbac_command


def hook_command(block_unguarded: bool) -> str:
    parts = [*botrbac_command(), "check", "--agent", "claude-code"]
    if block_unguarded:
        parts.append("--block-unguarded")
    return " ".join(shlex.quote(p) for p in parts)


def _ours(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    return any(
        isinstance(h, dict) and " check --agent " in str(h.get("command", ""))
        and ("botrbac" in str(h.get("command", "")))
        for h in entry.get("hooks") or []
    )  # fmt: skip


def install_claude_code(path: Path, block_unguarded: bool = True) -> dict[str, Any]:
    data: dict[str, Any] = {}
    backup = None
    if path.exists():
        try:
            data = json.loads(path.read_text() or "{}")
        except ValueError as exc:
            raise ValueError(f"{path} is not valid JSON") from exc
        if not isinstance(data, dict):
            raise ValueError(f"{path} is not a JSON object")
        backup = path.with_name(f"{path.name}.botrbac-backup-{int(time.time())}")
        shutil.copy2(path, backup)
    hooks = data.setdefault("hooks", {})
    entries = [e for e in hooks.get("PreToolUse") or [] if not _ours(e)]
    entries.append(
        {
            "matcher": "*",
            "hooks": [{"type": "command", "command": hook_command(block_unguarded)}],
        }
    )
    hooks["PreToolUse"] = entries
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")
    return {"file": str(path), "backup": str(backup) if backup else None}

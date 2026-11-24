"""Files the CLI keeps on this computer, all under one directory.

`$BOTRBAC_HOME`, or `~/.config/botrbac`:

- credentials.json  server URL and this terminal's tokens (mode 0600)
- policy.json       the last policy the server sent, with when it was fetched
- config.json       the MCP servers `botrbac gateway` sits in front of
- audit.db          audit rows waiting to be sent (SQLite)
- sessions/         one file per `botrbac run` session
- state.json        tools seen and unguarded servers, reported at the next sync
"""

import contextlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any


def home() -> Path:
    path = Path(os.environ.get("BOTRBAC_HOME") or Path.home() / ".config" / "botrbac")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def read_json(name: str, default: Any = None) -> Any:
    try:
        return json.loads((home() / name).read_text())
    except (OSError, ValueError):
        return default


def write_json(name: str, data: Any, *, private: bool = False) -> Path:
    """Atomic write; `private` files are readable by this user only."""
    target = home() / name
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
        if private:
            os.chmod(tmp, 0o600)
        os.replace(tmp, target)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
    return target


def remove(name: str) -> None:
    with contextlib.suppress(FileNotFoundError):
        (home() / name).unlink()


def note_seen(tools: list[str] | None = None, unguarded: list[str] | None = None) -> None:
    """Remember what to report at the next sync (tools for the website's role picker)."""
    data = read_json("state.json", {}) or {}
    if tools:
        known = set(data.get("tools") or [])
        data["tools"] = sorted(known | set(tools))[:500]
    if unguarded is not None:
        data["unguarded"] = sorted(set(unguarded))[:50]
    write_json("state.json", data)

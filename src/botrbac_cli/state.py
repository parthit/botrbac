"""Files the CLI keeps on this computer, all under one directory.

`botrbac --home PATH`, else `$BOTRBAC_HOME`, else `~/.config/botrbac`. The commands
botrbac writes into agents' settings (hooks, the gateway) name the folder with --home,
so a BOTRBAC_HOME an agent sets for a child process cannot point them at another one.

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
from collections.abc import Iterator
from pathlib import Path
from typing import Any

_HOME_OVERRIDE: Path | None = None


def set_home(path: str | os.PathLike[str] | None) -> None:
    """Use this folder whatever BOTRBAC_HOME says (`botrbac --home PATH`)."""
    global _HOME_OVERRIDE
    _HOME_OVERRIDE = Path(path).expanduser().absolute() if path else None


def home() -> Path:
    path = _HOME_OVERRIDE or Path(
        os.environ.get("BOTRBAC_HOME") or Path.home() / ".config" / "botrbac"
    )
    if path.is_dir():
        # It holds tokens and the audit record: this user only, even if it was made
        # with a looser umask.
        with contextlib.suppress(OSError):
            if path.stat().st_mode & 0o077:
                os.chmod(path, 0o700)
    else:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def home_path() -> Path:
    """The folder as an absolute path, for commands written into agents' settings."""
    return home().absolute()


@contextlib.contextmanager
def file_lock(name: str) -> Iterator[None]:
    """An exclusive lock across processes on `name` in the folder (POSIX flock); where
    fcntl is missing (Windows), no lock."""
    with open(home() / name, "a") as handle:
        try:
            import fcntl
        except ImportError:  # Windows
            yield
            return
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


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


ROUTES_FILE = "routes.json"
MAX_ROUTES = 5000


def note_routes(exposed: list[str]) -> None:
    """Remember the tool names the gateway offers (`<server>__<tool>`). The hook reads
    them to tell the gateway's own tools from another server's that only look like them."""
    known = read_json(ROUTES_FILE, {}) or {}
    names = set(known.get("routes") or []) if isinstance(known, dict) else set()
    write_json(ROUTES_FILE, {"routes": sorted(names | set(exposed))[:MAX_ROUTES]})


def routes() -> set[str] | None:
    """The names from `note_routes`, or None when no gateway has written them yet (one
    started before botrbac kept this list)."""
    known = read_json(ROUTES_FILE)
    if not isinstance(known, dict) or not isinstance(known.get("routes"), list):
        return None
    return {str(name) for name in known["routes"]}

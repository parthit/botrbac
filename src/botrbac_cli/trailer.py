"""`botrbac trailer`: name the Bot RBAC session in commits made inside one.

`botrbac trailer install [--repo PATH]` writes a git `prepare-commit-msg` hook. When a
commit is made with BOTRBAC_SESSION set (inside `botrbac run`), the hook adds

    Botrbac-Session: <site>/terminal/sessions/<id>

to the message, so a reviewer can open the session that wrote it. Nothing is installed
unless asked. The hook is idempotent (an amend does not add a second trailer), runs an
existing hook first (moved aside to prepare-commit-msg.botrbac-orig, and put back by
`botrbac trailer remove`), keeps that hook's exit status, and its own part never fails
the commit.
"""

import os
import re
import stat
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

from . import state

HOOK = "prepare-commit-msg"
BACKUP = HOOK + ".botrbac-orig"
MARKER = "# botrbac-trailer v1"
TRAILER = "Botrbac-Session"
# Baked into a shell script: scheme, host, optional port and a plain path only.
_SAFE_SITE = re.compile(r"^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$")

SCRIPT = """#!/bin/sh
{marker}
# Adds "{trailer}: <session page>" to commits made inside `botrbac run`.
# Remove with: botrbac trailer remove
status=0
orig="$(dirname "$0")/{backup}"
if [ -x "$orig" ]; then
  "$orig" "$@" || status=$?
fi
if [ "$status" -eq 0 ] && [ -n "$BOTRBAC_SESSION" ] && [ -n "$1" ]; then
  case "$BOTRBAC_SESSION" in
    *[!A-Za-z0-9_-]*) ;;
    *)
      line="{trailer}: {site}/terminal/sessions/$BOTRBAC_SESSION"
      if ! grep -qxF "$line" "$1" 2>/dev/null; then
        git interpret-trailers --in-place --if-exists addIfDifferent \\
          --trailer "$line" "$1" >/dev/null 2>&1 || true
      fi
      ;;
  esac
fi
exit "$status"
"""


class TrailerError(Exception):
    pass


def site() -> str:
    """The site from `botrbac login`, as scheme://host[:port]."""
    creds = state.read_json("credentials.json") or {}
    server = str(creds.get("server") or "") if isinstance(creds, dict) else ""
    parts = urlsplit(server)
    return f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else ""


def hooks_dir(repo: Path) -> Path:
    """Where git looks for this repository's hooks (core.hooksPath included)."""
    try:
        out = subprocess.run(  # noqa: S603 - fixed arguments; the repo is the person's
            ["git", "-C", str(repo), "rev-parse", "--git-path", "hooks"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise TrailerError(f"{repo} is not a git repository") from exc
    path = Path(out)
    return path if path.is_absolute() else (repo / path)


def script(site_url: str) -> str:
    if not _SAFE_SITE.fullmatch(site_url):
        raise TrailerError(f"cannot use {site_url!r} as the site address")
    return SCRIPT.format(marker=MARKER, trailer=TRAILER, backup=BACKUP, site=site_url)


def ours(path: Path) -> bool:
    try:
        return MARKER in path.read_text(errors="replace")
    except OSError:
        return False


def install(repo: Path, site_url: str | None = None) -> dict[str, object]:
    site_url = (site_url or site()).rstrip("/")
    if not site_url:
        raise TrailerError("Not logged in, so the site is unknown. Run: botrbac login")
    text = script(site_url)
    folder = hooks_dir(repo)
    folder.mkdir(parents=True, exist_ok=True)
    hook, backup = folder / HOOK, folder / BACKUP
    moved = False
    if hook.exists() and not ours(hook):
        if backup.exists():
            raise TrailerError(
                f"{backup} already exists and {hook} is not botrbac's. Move one of them first."
            )
        os.replace(hook, backup)
        moved = True
    changed = not hook.exists() or hook.read_text(errors="replace") != text
    if changed:
        hook.write_text(text)
    hook.chmod(hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    kept = backup if moved or backup.exists() else None
    return {"hook": hook, "backup": kept, "changed": changed}


def remove(repo: Path) -> dict[str, object]:
    folder = hooks_dir(repo)
    hook, backup = folder / HOOK, folder / BACKUP
    if not ours(hook):
        return {"hook": hook, "removed": False, "restored": False}
    hook.unlink()
    restored = False
    if backup.exists():
        os.replace(backup, hook)
        restored = True
    return {"hook": hook, "removed": True, "restored": restored}

"""Pre-tool hooks for agents other than Claude Code: Codex CLI, Gemini CLI and Cursor.

Each agent gets three things here: an installer that writes its hook config so it runs
`botrbac check --agent <name>` before a tool call, an adapter that turns its hook payload
into the shape `check.py` reads (`tool_name`, `tool_input`, the command for a shell
tool), and the answer it expects back. Claude Code's own installer is in hooks.py.

What each agent's hook looks like, from its documentation (November 2026):

- **Codex CLI** (https://developers.openai.com/codex/hooks, and the source in
  openai/codex `codex-rs/hooks/src/events/pre_tool_use.rs` and `output_parser.rs`):
  `~/.codex/hooks.json` or `<repo>/.codex/hooks.json`, or `[hooks]` tables in
  `config.toml`, in Claude Code's shape: `{"hooks": {"PreToolUse": [{"matcher": <regex>,
  "hooks": [{"type": "command", "command": ...}]}]}}`. The payload is Claude Code's too:
  `tool_name` (`Bash` for the shell, `apply_patch`, `mcp__<server>__<tool>`) and
  `tool_input` (`{"command": ...}` for the shell). Exit code 2 with the reason on stderr
  blocks. Codex runs a new or changed hook only after the person trusts it in `/hooks`,
  and `[features] hooks = false` in config.toml switches hooks off.
- **Gemini CLI** (https://geminicli.com/docs/hooks/reference/ and
  docs/reference/configuration.md in google-gemini/gemini-cli): a `hooks` object in
  `~/.gemini/settings.json` or `.gemini/settings.json`, with `BeforeTool` entries of
  `{"matcher": <regex>, "hooks": [{"type": "command", "command": ..., "name": ...,
  "timeout": <ms>}]}`. The payload has `tool_name` (`run_shell_command`, `write_file`,
  `mcp_<server>_<tool>`, split at the first underscore after `mcp_`) and `tool_input`.
  Exit code 2 blocks with stderr as the reason; any other non-zero exit is only a
  warning. `hooksConfig.enabled: false` switches hooks off and `hooksConfig.disabled`
  lists hook names that do not run.
- **Cursor** (https://cursor.com/docs/hooks; Cursor is closed source, so this follows
  its docs and third-party write-ups, see docs/terminal.md): `~/.cursor/hooks.json` or
  `.cursor/hooks.json`, `{"version": 1, "hooks": {"beforeShellExecution": [{"command":
  ...}], "beforeMCPExecution": [...], "beforeReadFile": [...]}}`. The shell event sends
  `command` (and `cwd`) at the top level; the MCP event sends `tool_name`, `tool_input`
  (a JSON string) and the server's `url` or `command`; the read event sends `file_path`
  and the file's `content`. The hook answers with JSON on stdout:
  `{"permission": "allow"|"deny", "user_message": ..., "agent_message": ...}`. A hook that
  crashes lets the action go ahead unless the entry has `"failClosed": true`.
"""

import json
import shlex
import shutil
import tomllib
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .coverage import GATEWAY_NAME, backup_file, is_gateway, servers_in, write_atomic
from .patterns import normalize_server

# The agents botrbac knows. Their names are what audit rows carry in `agent`.
AGENTS = ("claude-code", "codex", "gemini", "cursor")
OTHER_AGENTS = ("codex", "gemini", "cursor")
HOOK_NAME = "botrbac"

# Where each agent's hook config lives, relative to the home folder (--user) or the
# project, and the events the hook is added to.
HOOK_FILES: dict[str, Path] = {
    "codex": Path(".codex") / "hooks.json",
    "gemini": Path(".gemini") / "settings.json",
    "cursor": Path(".cursor") / "hooks.json",
}
HOOK_EVENTS: dict[str, tuple[str, ...]] = {
    "codex": ("PreToolUse",),
    "gemini": ("BeforeTool",),
    "cursor": ("beforeShellExecution", "beforeMCPExecution", "beforeReadFile"),
}
# How to tell the agent is on this computer: its folder in the home directory, or a
# program on PATH.
_CONFIG_DIRS = {
    "claude-code": ".claude",
    "codex": ".codex",
    "gemini": ".gemini",
    "cursor": ".cursor",
}
_PROGRAMS = {
    "claude-code": ("claude",),
    "codex": ("codex",),
    "gemini": ("gemini",),
    "cursor": ("cursor-agent", "cursor"),
}
# Cursor's shell, as `check` sees it (shellcmd.SHELL_TOOLS lists it for cmd/ rules).
CURSOR_SHELL = "Shell"
CURSOR_READ = "Read"


# ---- the hook command ----------------------------------------------------------------


def hook_command(agent: str, block_unguarded: bool) -> str:
    # hooks imports this module, so import it here. It bakes in --home, so a BOTRBAC_HOME
    # the agent sets for a child process cannot send the check to a folder it wrote.
    from . import hooks

    return hooks.hook_command(block_unguarded, agent=agent)


def runs_check(command: Any) -> bool:
    """A hook command that runs botrbac's own `check --agent`."""
    try:
        parts = shlex.split(str(command or ""))
    except ValueError:
        return False
    runs_botrbac = bool(parts) and (
        Path(parts[0]).name == "botrbac" or parts[1:3] == ["-m", "botrbac_cli"]
    )
    return runs_botrbac and "check" in parts and "--agent" in parts


def _ours(agent: str, entry: Any) -> bool:
    """An entry under one event that botrbac added."""
    if not isinstance(entry, dict):
        return False
    if agent == "cursor":
        return runs_check(entry.get("command"))
    return any(
        isinstance(h, dict) and runs_check(h.get("command")) for h in entry.get("hooks") or []
    )


def _entry(agent: str, block_unguarded: bool) -> dict[str, Any]:
    command = hook_command(agent, block_unguarded)
    if agent == "cursor":
        # Without failClosed a hook that crashes (botrbac removed, a timeout) lets the
        # action go ahead.
        return {"command": command, "failClosed": True}
    hook: dict[str, Any] = {"type": "command", "command": command}
    if agent == "gemini":
        # Gemini's timeout is in milliseconds; the name is what hooksConfig.disabled lists.
        hook = {"name": HOOK_NAME, **hook, "timeout": 60000}
    # Both read the matcher as a regular expression: ".*" is every tool.
    return {"matcher": ".*", "hooks": [hook]}


# ---- install and remove --------------------------------------------------------------


def _load(path: Path) -> tuple[dict[str, Any], str | None]:
    if not path.exists():
        return {}, None
    before = path.read_text()
    try:
        data = json.loads(before or "{}")
    except ValueError as exc:
        raise ValueError(f"{path} is not valid JSON; it was left as it is") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a JSON object; it was left as it is")
    return data, before


def install(agent: str, path: Path, block_unguarded: bool = True) -> dict[str, Any]:
    """Add (or update) botrbac's hook in this agent's file, keeping everything else.
    Writes, and backs up, only when something changes."""
    data, before = _load(path)
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict) or any(
        not isinstance(hooks.get(e, []), list) for e in HOOK_EVENTS[agent]
    ):
        raise ValueError(
            f"{path} has a hooks section botrbac does not understand; it was left as it is"
        )
    if agent == "cursor":
        if data.get("version", 1) != 1:
            raise ValueError(f"{path} is a hooks.json version botrbac does not know")
        data.setdefault("version", 1)
    for event in HOOK_EVENTS[agent]:
        kept = [e for e in hooks.get(event) or [] if not _ours(agent, e)]
        hooks[event] = [*kept, _entry(agent, block_unguarded)]
    if before is not None and json.loads(before or "{}") == data:
        return {"file": str(path), "backup": None, "changed": False}
    backup = backup_file(path) if before is not None else None
    write_atomic(path, json.dumps(data, indent=2) + "\n")
    return {"file": str(path), "backup": backup, "changed": True}


def remove(agent: str, path: Path) -> dict[str, Any]:
    """Take out the hook `install` added, leaving everything else."""
    unchanged = {"file": str(path), "backup": None, "changed": False}
    data, before = _load(path)
    hooks = data.get("hooks")
    if before is None or not isinstance(hooks, dict):
        return unchanged
    changed = False
    for event in HOOK_EVENTS[agent]:
        entries = hooks.get(event)
        if not isinstance(entries, list) or not any(_ours(agent, e) for e in entries):
            continue
        changed = True
        kept = [e for e in entries if not _ours(agent, e)]
        if kept:
            hooks[event] = kept
        else:
            del hooks[event]
    if not changed:
        return unchanged
    if not hooks:
        del data["hooks"]
    backup = backup_file(path)
    write_atomic(path, json.dumps(data, indent=2) + "\n")
    return {"file": str(path), "backup": backup, "changed": True}


def hook_file(agent: str, user: bool, cwd: Path | None = None) -> Path:
    return (Path.home() if user else (cwd or Path.cwd())) / HOOK_FILES[agent]


def cmd_hooks(args: Any) -> int:
    """`botrbac hooks install|remove codex|gemini|cursor [--user]`."""
    import sys

    from .hooks import expect_hook

    agent = normalize_server(args.agent)
    if agent == "gemini-cli":
        agent = "gemini"
    if agent not in OTHER_AGENTS:
        print(
            "Automatic hook setup is for claude-code, codex, gemini and cursor. For another "
            f"agent, make its pre-tool hook run: botrbac check --agent {args.agent} "
            "(see docs/terminal.md)."
        )
        return 0
    path = hook_file(agent, args.user)
    try:
        if args.action == "remove":
            result = remove(agent, path)
        else:
            result = install(agent, path, not args.allow_unguarded)
    except (OSError, ValueError) as exc:
        print(f"botrbac: {exc}", file=sys.stderr)
        return 1
    expect_hook(agent, args.action == "install")
    if args.action == "remove":
        if result["changed"]:
            print(f"Removed the botrbac hook from {result['file']}")
            print(f"Backup: {result['backup']}")
        else:
            print(f"No botrbac hook in {result['file']}")
        return 0
    if not result["changed"]:
        print(f"Already set up: {result['file']}")
    else:
        print(f"{agent} now asks botrbac before its tool calls: {result['file']}")
        if result["backup"]:
            print(f"Backup: {result['backup']}")
    for line in _after_install(agent):
        print(line)
    return 0


def _after_install(agent: str) -> list[str]:
    tools = {
        "codex": "codex/Bash, codex/apply_patch, codex/*",
        "gemini": "gemini/run_shell_command, gemini/write_file, gemini/*",
        "cursor": "cursor/Shell, cursor/Read, cursor/*",
    }[agent]
    lines = [f"Give the role {tools} patterns as needed."]
    if agent == "codex":
        lines.append("Codex runs a new hook only once you trust it: open Codex, run /hooks.")
    if agent == "cursor":
        lines.append("Restart Cursor so it loads the hook.")
    return lines


# ---- is the hook still there? --------------------------------------------------------


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text() or "{}")
    except (OSError, ValueError):
        return None


def _read_toml(path: Path) -> Any:
    try:
        return tomllib.loads(path.read_text())
    except (OSError, ValueError, tomllib.TOMLDecodeError):
        return None


def hook_status(agent: str, cwd: Path | None = None) -> str:
    """ "installed", "missing" or "disabled", for codex, gemini or cursor."""
    if agent not in OTHER_AGENTS:
        return "missing"
    here = cwd or Path.cwd()
    found = False
    for base in (Path.home(), here):
        data = _read_json(base / HOOK_FILES[agent])
        if not isinstance(data, dict):
            continue
        if agent == "gemini":
            config = data.get("hooksConfig")
            if isinstance(config, dict) and (
                config.get("enabled") is False
                or any(
                    d == HOOK_NAME or runs_check(d)
                    for d in config.get("disabled") or []
                    if isinstance(d, str)
                )
            ):
                return "disabled"
        hooks = data.get("hooks")
        for event in HOOK_EVENTS[agent]:
            entries = hooks.get(event) if isinstance(hooks, dict) else None
            if isinstance(entries, list) and any(_ours(agent, e) for e in entries):
                found = True
    if agent == "codex":
        for base in (Path.home(), here):
            data = _read_toml(base / ".codex" / "config.toml")
            if not isinstance(data, dict):
                continue
            features = data.get("features")
            if isinstance(features, dict) and (
                features.get("hooks") is False or features.get("codex_hooks") is False
            ):
                return "disabled"
            hooks = data.get("hooks")
            entries = hooks.get("PreToolUse") if isinstance(hooks, dict) else None
            if isinstance(entries, list) and any(_ours(agent, e) for e in entries):
                found = True
    return "installed" if found else "missing"


def any_hook_status(agent: str, cwd: Path | None = None) -> str:
    if agent == "claude-code":
        from .hooks import claude_code_hook_status

        return claude_code_hook_status(cwd)
    return hook_status(agent, cwd)


def detected(cwd: Path | None = None) -> list[str]:
    """Agents that look installed here: their folder in the home directory (or the
    project), or their program on PATH."""
    here = cwd or Path.cwd()
    out = []
    for agent in AGENTS:
        folder = _CONFIG_DIRS[agent]
        on_disk = (Path.home() / folder).is_dir() or (here / folder).is_dir()
        if on_disk or any(shutil.which(p) for p in _PROGRAMS[agent]):
            out.append(agent)
    return out


def has_gateway(agent: str, cwd: Path | None = None) -> bool:
    from .coverage import known_configs

    return any(
        is_gateway(spec)
        for config in known_configs(cwd)
        if config.agent == agent
        for spec in servers_in(config).values()
    )


def coverage_summary(cwd: Path | None = None, unguarded: list[str] | None = None) -> dict[str, Any]:
    """What the website shows as this computer's coverage: the agents found here, the ones
    whose hook is in place, the ones whose hook botrbac installed and is now missing or
    switched off, and how many MCP servers bypass the gateway."""
    from . import state

    expected = set((state.read_json("state.json", {}) or {}).get("hooks_expected") or [])
    found = detected(cwd)
    status = {agent: any_hook_status(agent, cwd) for agent in sorted(set(found) | expected)}
    if unguarded is None:
        from .coverage import unguarded as scan

        unguarded = sorted({name for _, name in scan(cwd)})
    return {
        "agents_detected": found,
        "agents_hooked": [a for a in AGENTS if status.get(a) == "installed"],
        # Installed by botrbac and now gone, or switched off however it got there.
        "hook_off": [
            a
            for a in AGENTS
            if status.get(a) == "disabled" or (a in expected and status.get(a) == "missing")
        ],
        "unguarded_servers": len(unguarded),
    }


def doctor_report(say: Callable[[str], None], cwd: Path | None = None) -> None:
    """One line per agent found here: is its hook in place, and its gateway. Agents
    botrbac installed a hook for are reported (and counted) by `hooks.hook_report`."""
    for agent in detected(cwd):
        status = any_hook_status(agent, cwd)
        gateway = has_gateway(agent, cwd)
        hook = {"installed": "hook ✓", "disabled": "hook switched off"}.get(status, "no hook")
        mark = "✓" if status == "installed" and gateway else "!"
        say(f"{mark} {agent} found: {hook}, {'gateway ✓' if gateway else 'no gateway'}")
        if status != "installed":
            say(f"    fix: botrbac hooks install {agent} --user --allow-unguarded")
        if not gateway:
            say(f"    fix: {gateway_fix(agent)}")
    for agent, path in stale_hooks(cwd):
        say(f"! {agent}: the botrbac hook in {path} is from an older botrbac")
        user = " --user" if path.parent.parent == Path.home() else ""
        say(f"    fix: botrbac hooks install {agent}{user} --allow-unguarded")
    from .coverage import stale_gateways

    for config in stale_gateways(cwd):
        say(f"! {config.agent}: the botrbac entry in {config.path} is from an older botrbac")
        say(f"    fix: {gateway_fix(config.agent, update=True)}")


def _commands(data: Any) -> Iterator[str]:
    """Every string under a "command" key, anywhere in a parsed settings file."""
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "command" and isinstance(value, str):
                yield value
            else:
                yield from _commands(value)
    elif isinstance(data, list):
        for value in data:
            yield from _commands(value)


def stale_hooks(cwd: Path | None = None) -> list[tuple[str, Path]]:
    """(agent, file) for each botrbac hook written by a botrbac from before --home: it
    still works, but follows an inherited BOTRBAC_HOME. `hooks install` again fixes it."""
    from .hooks import claude_code_settings_files

    here = cwd or Path.cwd()
    files = [("claude-code", f) for f in claude_code_settings_files(here)]
    for agent, relative in HOOK_FILES.items():
        files += [(agent, Path.home() / relative), (agent, here / relative)]
    out: list[tuple[str, Path]] = []
    seen: set[Path] = set()
    for agent, path in files:
        if path in seen:
            continue
        seen.add(path)
        for command in _commands(_read_json(path)):
            if runs_check(command) and "--home" not in shlex.split(command):
                out.append((agent, path))
                break
    return out


def gateway_fix(agent: str, update: bool = False) -> str:
    """The command that adds (or brings up to date) the gateway entry for one agent."""
    if agent != "claude-code":
        return f"botrbac add-gateway --agent {agent}"
    from .coverage import installed_command

    add = " ".join(shlex.quote(p) for p in installed_command())
    command = f"claude mcp add --scope user botrbac -- {add} gateway"
    return f"claude mcp remove --scope user botrbac && {command}" if update else command


# ---- payload adapters ----------------------------------------------------------------


def normalize(agent: str, payload: Any) -> Any:
    """The agent's hook payload in the shape check.py reads: `tool_name`, `tool_input`
    (with `command` for a shell tool). Payloads it cannot place come back with no tool
    name, which check blocks."""
    if not isinstance(payload, dict):
        return payload
    name = normalize_server(agent)
    if name == "cursor":
        return _cursor(payload)
    if name in ("gemini", "gemini-cli"):
        return _gemini(payload)
    return payload  # Claude Code and Codex already send tool_name and tool_input


def _gemini(payload: dict[str, Any]) -> dict[str, Any]:
    """Gemini names MCP tools `mcp_<server>_<tool>`; check reads `mcp__<server>__<tool>`.

    The server is the one `mcp_context` names. Without it the split is a guess (server
    `botrbac_x` and the gateway look alike in `mcp_botrbac_x_tool`), so a guess is
    checked as an ordinary server, never trusted as the gateway: a guess of `botrbac`
    comes back with no tool name, which check blocks."""
    name = payload.get("tool_name")
    if not isinstance(name, str) or not name.startswith("mcp_") or name.startswith("mcp__"):
        return payload
    context = payload.get("mcp_context")
    server = context.get("server_name") if isinstance(context, dict) else None
    rest = name[len("mcp_") :]
    if isinstance(server, str) and server and rest.startswith(server + "_"):
        tool = rest[len(server) + 1 :]
        if server != GATEWAY_NAME:
            server = _not_gateway(server)  # `botrbac__x` must not read as the gateway
    else:
        server, _, tool = rest.partition("_")
        if server == GATEWAY_NAME:
            return {k: v for k, v in payload.items() if k != "tool_name"}
    return {**payload, "tool_name": f"mcp__{server}__{tool or 'tool'}"}


def _cursor(payload: dict[str, Any]) -> dict[str, Any]:
    event = payload.get("hook_event_name")
    keep = {k: payload[k] for k in ("hook_event_name", "conversation_id") if k in payload}
    has_tool = isinstance(payload.get("tool_name"), str)
    if event == "beforeShellExecution" or (event is None and not has_tool and "command" in payload):
        command = payload.get("command")
        if not isinstance(command, str):
            return keep  # no tool name: blocked
        tool_input: dict[str, Any] = {"command": command}
        if isinstance(payload.get("cwd"), str):
            tool_input["cwd"] = payload["cwd"]
        return {**keep, "tool_name": CURSOR_SHELL, "tool_input": tool_input}
    if event == "beforeReadFile" or (event is None and not has_tool and "file_path" in payload):
        path = payload.get("file_path")
        if not isinstance(path, str):
            return keep
        # Only the path: the file's content (also in the payload) is never checked or kept.
        return {**keep, "tool_name": CURSOR_READ, "tool_input": {"file_path": path}}
    if event == "beforeMCPExecution" or (event is None and has_tool):
        tool = payload.get("tool_name")
        if not isinstance(tool, str) or not tool:
            return keep
        raw = payload.get("tool_input")
        if isinstance(raw, str):
            try:
                raw = json.loads(raw) if raw.strip() else {}
            except ValueError:
                raw = {"input": raw}
        return {
            **keep,
            "tool_name": f"mcp__{_cursor_server(payload)}__{tool}",
            "tool_input": raw if raw is not None else {},
        }
    return keep  # an event botrbac does not know: blocked


_LAUNCHERS = frozenset({"npx", "uvx", "bunx", "pnpx", "node", "python", "python3", "deno", "uv"})


def _cursor_server(payload: dict[str, Any]) -> str:
    """Cursor's MCP event does not say which server by name; it gives the server's url or
    command. Only the gateway's own command (as in coverage.is_gateway) names the gateway."""
    for key in ("server_name", "server", "mcp_server"):
        if isinstance(payload.get(key), str) and payload[key]:
            return _not_gateway(payload[key])
    url = payload.get("url")
    if isinstance(url, str) and url:
        return _not_gateway(urlsplit(url).hostname or "unknown")
    command = payload.get("command")
    if isinstance(command, str) and command.strip():
        try:
            parts = shlex.split(command)
        except ValueError:
            return "unknown"
        if parts and is_gateway({"command": parts[0], "args": parts[1:]}):
            return GATEWAY_NAME
        words = [p for p in parts if not p.startswith("-")]
        name = Path(words[0]).name if words else "unknown"
        if name in _LAUNCHERS and len(words) > 1:
            name = Path(words[1]).name
        return _not_gateway(name.split("@")[0] or "unknown")
    return "unknown"


def _not_gateway(name: str) -> str:
    """Only the gateway's own command makes a call `mcp__botrbac__…`: a server merely
    called botrbac (by its label, host or program) is checked as `botrbac-upstream`, the
    name the gateway would give it (coverage._free_name)."""
    if normalize_server(name) == GATEWAY_NAME or name.startswith(GATEWAY_NAME + "__"):
        return f"{GATEWAY_NAME}-upstream"
    return name


# ---- answers ---------------------------------------------------------------------------


def response(agent: str, allowed: bool, reason: str) -> str | None:
    """The JSON an agent reads on stdout instead of the exit code, or None when the exit
    code (0 allows, 2 blocks with the reason on stderr) is the answer."""
    if normalize_server(agent) != "cursor":
        return None
    if allowed:
        return json.dumps({"permission": "allow"})
    return json.dumps({"permission": "deny", "user_message": reason, "agent_message": reason})

"""Finding MCP servers that do not go through botrbac, and moving them behind it.

`botrbac doctor` lists servers an agent connects to directly: their calls never reach
Bot RBAC, so the website shows them as unguarded. `botrbac wrap <agent>` moves the
servers in that agent's config behind `botrbac gateway` (the original file is kept as a
backup). This guards against the agent. It cannot stop the person who owns the computer
from editing the files back.
"""

import json
import shutil
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import state
from .patterns import normalize_server
from .shell import botrbac_command

GATEWAY_NAME = "botrbac"


@dataclass(frozen=True)
class AgentConfig:
    agent: str
    path: Path
    kind: str  # "json" (an mcpServers object) or "codex" (TOML mcp_servers tables)


def known_configs(cwd: Path | None = None) -> list[AgentConfig]:
    here = cwd or Path.cwd()
    user = Path.home()
    return [
        AgentConfig("claude-code", here / ".mcp.json", "json"),
        AgentConfig("claude-code", user / ".claude.json", "json"),
        AgentConfig("cursor", here / ".cursor" / "mcp.json", "json"),
        AgentConfig("cursor", user / ".cursor" / "mcp.json", "json"),
        AgentConfig("gemini", here / ".gemini" / "settings.json", "json"),
        AgentConfig("gemini", user / ".gemini" / "settings.json", "json"),
        AgentConfig("codex", user / ".codex" / "config.toml", "codex"),
    ]


def is_gateway(spec: Any) -> bool:
    if not isinstance(spec, dict):
        return False
    command = str(spec.get("command") or "")
    args = [str(a) for a in spec.get("args") or []]
    if Path(command).name == "botrbac" and args[:1] == ["gateway"]:
        return True
    return "botrbac_cli" in args and "gateway" in args


def servers_in(config: AgentConfig) -> dict[str, Any]:
    """name -> spec, for every server block in the file (Claude's per-project ones too)."""
    try:
        text = config.path.read_text()
    except OSError:
        return {}
    try:
        data = tomllib.loads(text) if config.kind == "codex" else json.loads(text)
    except (ValueError, tomllib.TOMLDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    key = "mcp_servers" if config.kind == "codex" else "mcpServers"
    found = dict(data.get(key) or {})
    for project in (data.get("projects") or {}).values():
        if isinstance(project, dict):
            found.update(project.get("mcpServers") or {})
    return {str(k): v for k, v in found.items() if isinstance(v, dict)}


def unguarded(cwd: Path | None = None) -> list[tuple[AgentConfig, str]]:
    out = []
    for config in known_configs(cwd):
        for name, spec in servers_in(config).items():
            if not is_gateway(spec):
                out.append((config, name))
    return out


def to_upstream(spec: dict[str, Any]) -> dict[str, Any] | None:
    """An agent's server entry as a gateway upstream, or None if the gateway can't run it."""
    url = spec.get("url") or spec.get("httpUrl")
    if url:
        if spec.get("type") == "sse" or (spec.get("url") and "sse" in str(spec.get("type", ""))):
            return None  # the old SSE transport: leave it where it is
        return {"url": str(url), "headers": dict(spec.get("headers") or {})}
    if spec.get("command"):
        out: dict[str, Any] = {
            "command": str(spec["command"]),
            "args": [str(a) for a in spec.get("args") or []],
        }
        if spec.get("env"):
            out["env"] = {str(k): str(v) for k, v in dict(spec["env"]).items()}
        if spec.get("cwd"):
            out["cwd"] = str(spec["cwd"])
        return out
    return None


def gateway_entry(agent: str) -> dict[str, Any]:
    command = botrbac_command()
    return {"command": command[0], "args": [*command[1:], "gateway", "--agent", agent]}


def wrap(config: AgentConfig, dry_run: bool = False) -> dict[str, Any]:
    """Move the file's top-level servers behind the gateway. Returns what was done."""
    if config.kind == "codex":
        return _wrap_codex(config, dry_run)
    try:
        data = json.loads(config.path.read_text()) if config.path.exists() else {}
    except ValueError as exc:
        raise ValueError(f"{config.path} is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{config.path} is not a JSON object")
    servers = dict(data.get("mcpServers") or {})
    upstreams = dict((state.read_json("config.json", {}) or {}).get("servers") or {})
    moved, kept = [], []
    for name, spec in servers.items():
        if is_gateway(spec):
            continue
        upstream = to_upstream(spec) if isinstance(spec, dict) else None
        if upstream is None:
            kept.append(name)
            continue
        target = _place(name, upstream, upstreams)
        moved.append((name, target))
    remaining = {n: s for n, s in servers.items() if n in kept}
    remaining[GATEWAY_NAME] = gateway_entry(config.agent)
    result = {"file": str(config.path), "moved": moved, "kept": kept, "backup": None}
    if dry_run:
        return result
    if config.path.exists():
        backup = config.path.with_name(f"{config.path.name}.botrbac-backup-{int(time.time())}")
        shutil.copy2(config.path, backup)
        result["backup"] = str(backup)
    data["mcpServers"] = remaining
    config.path.parent.mkdir(parents=True, exist_ok=True)
    config.path.write_text(json.dumps(data, indent=2) + "\n")
    cfg = state.read_json("config.json", {}) or {}
    cfg["servers"] = upstreams
    state.write_json("config.json", cfg, private=True)
    return result


def _wrap_codex(config: AgentConfig, dry_run: bool) -> dict[str, Any]:
    """Codex keeps servers in TOML. Copy them behind the gateway and add the gateway's
    own table; the old tables are listed for the person to delete (we do not rewrite
    their TOML)."""
    servers = servers_in(config)
    upstreams = dict((state.read_json("config.json", {}) or {}).get("servers") or {})
    moved, kept = [], []
    for name, spec in servers.items():
        if is_gateway(spec):
            continue
        upstream = to_upstream(spec)
        if upstream is None:
            kept.append(name)
            continue
        target = _place(name, upstream, upstreams)
        moved.append((name, target))
    result = {"file": str(config.path), "moved": moved, "kept": kept, "backup": None}
    result["delete_tables"] = [f"[mcp_servers.{name}]" for name, _ in moved]
    if dry_run:
        return result
    if GATEWAY_NAME not in servers:
        entry = gateway_entry("codex")
        args = ", ".join(json.dumps(a) for a in entry["args"])
        block = (
            f"\n[mcp_servers.{GATEWAY_NAME}]\ncommand = {json.dumps(entry['command'])}\n"
            f"args = [{args}]\n"
        )
        config.path.parent.mkdir(parents=True, exist_ok=True)
        if config.path.exists():
            backup = config.path.with_name(f"{config.path.name}.botrbac-backup-{int(time.time())}")
            shutil.copy2(config.path, backup)
            result["backup"] = str(backup)
        with config.path.open("a") as handle:
            handle.write(block)
    cfg = state.read_json("config.json", {}) or {}
    cfg["servers"] = upstreams
    state.write_json("config.json", cfg, private=True)
    return result


def _place(name: str, upstream: dict[str, Any], upstreams: dict[str, Any]) -> str:
    """Add `upstream` under a free name, or reuse the name of an identical one (the same
    server configured in two agents)."""
    for existing, spec in upstreams.items():
        if spec == upstream:
            return existing
    target = _free_name(normalize_server(name), upstreams)
    upstreams[target] = upstream
    return target


def _free_name(name: str, taken: dict[str, Any]) -> str:
    if name == GATEWAY_NAME:
        name = f"{name}-upstream"
    candidate, n = name, 2
    while candidate in taken:
        candidate = f"{name}-{n}"
        n += 1
    return candidate

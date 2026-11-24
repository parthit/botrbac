"""botrbac: roles from the Bot RBAC website, enforced for agents on this computer."""

import argparse
import asyncio
import os
import platform
import socket
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from . import __version__, policy, state
from .api import Api, ApiError, NotLoggedIn
from .patterns import COMMAND_SERVER, normalize_server
from .queue import AuditQueue

DEFAULT_SERVER = "https://botrbac.com"


def _api(args: argparse.Namespace) -> Api:
    return Api(getattr(args, "server", None) or os.environ.get("BOTRBAC_SERVER"))


def _say(*lines: str) -> None:
    """Printed and flushed at once: an agent running `botrbac login` reads the link and
    code while the command is still waiting."""
    for line in lines:
        print(line, flush=True)


def cmd_login(args: argparse.Namespace) -> int:
    server = args.server or os.environ.get("BOTRBAC_SERVER") or DEFAULT_SERVER
    api = Api(server)
    started = api.start_login(socket.gethostname(), f"{platform.system()} {platform.release()}")
    _say(
        "To connect this computer, open this link and approve the code:",
        f"Link: {started['verification_uri_complete']}",
        f"Code: {started['user_code']}",
        "Waiting for approval…",
    )
    interval = int(started.get("interval") or 5)
    deadline = time.time() + int(started.get("expires_in") or 600)
    while time.time() < deadline:
        time.sleep(interval)
        result = api.poll_login(started["device_code"])
        if isinstance(result, dict):
            fresh = policy.refresh(api) or {}
            role = fresh.get("role", {}).get("name", "?")
            _say(f"Logged in as {fresh.get('email', '?')}, role {role}")
            return 0
        if result == "slow_down":
            interval += 5
        elif result == "rate_limited":
            time.sleep(60)
        elif result == "access_denied":
            print("Login refused on the website. Run botrbac login again.", file=sys.stderr)
            return 1
        elif result != "authorization_pending":
            print(f"Login did not complete: {result}", file=sys.stderr)
            return 1
    print("The code expired before it was approved. Run botrbac login again.", file=sys.stderr)
    return 1


def cmd_logout(_args: argparse.Namespace) -> int:
    for name in ("credentials.json", "policy.json"):
        state.remove(name)
    print("Logged out on this computer. Disconnect it on the website to end it there too.")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    creds = state.read_json("credentials.json", {}) or {}
    cached = policy.load_cached()
    queue = AuditQueue()
    if not creds:
        print("Not logged in. Run: botrbac login")
        return 1
    online = policy.refresh(_api(args)) is not None
    cached = policy.load_cached() or cached
    pol = (cached or {}).get("policy", {})
    age = time.time() - float((cached or {}).get("fetched_at") or 0)
    print(f"Server:   {creds.get('server')}")
    print(
        f"Account:  {pol.get('email', '?')} · terminal {pol.get('terminal', {}).get('name', '?')}"
    )
    role = pol.get("role", {})
    print(
        f"Role:     {role.get('name', '?')} ({', '.join(role.get('patterns') or []) or 'no tools'})"
    )
    reach = "online" if online else "offline"
    print(f"Policy:   v{pol.get('version', '?')}, {int(age // 60)} min old · {reach}")
    refused = queue.rejected()
    note = f", {refused} refused (botrbac sync --retry-rejected)" if refused else ""
    print(f"Waiting:  {queue.waiting()} audit rows to send{note}")
    session = policy.load_session(os.environ.get(policy.SESSION_ENV))
    if session:
        print(f"Session:  {session.get('id')} as {session.get('role_name')}")
    servers = load_servers()
    print(f"Servers:  {', '.join(servers) or 'none (botrbac servers add …)'}")
    return 0


def cmd_sync(args: argparse.Namespace) -> int:
    from .sync import sync

    queue = AuditQueue()
    if args.retry_rejected:
        print(f"Sending {queue.requeue_rejected()} refused rows again.")
    result = sync(_api(args), queue)
    if result.get("error"):
        print(f"Offline: {result['waiting']} rows waiting ({result['error']})")
        return 1
    print(f"Sent {result['sent']} rows. {result['waiting']} waiting.")
    return 0


def cmd_log(args: argparse.Namespace) -> int:
    for row in AuditQueue().recent(args.limit):
        when = datetime.fromtimestamp(row["ts"]).strftime("%Y-%m-%d %H:%M:%S")
        what = row.get("tool") or f"session {row.get('session_id')} as {row.get('role')}"
        mark = {"sent": "", "rejected": "  (refused by the server)"}.get(
            row.get("status", ""), "  (not sent yet)"
        )
        print(f"{when}  {row['decision']:<7} {what}  {row.get('reason', '')}{mark}")
    return 0


def cmd_gateway(args: argparse.Namespace) -> int:
    from .gateway import serve

    api = _api(args) if state.read_json("credentials.json") else None
    asyncio.run(serve(args.agent, api))
    return 0


# ---- sessions and coverage -------------------------------------------------------


def cmd_run(args: argparse.Namespace) -> int:
    from .session import SessionError, run

    api = _api(args) if state.read_json("credentials.json") else None
    try:
        return run(args.role, args.command_line, args.agent, api)
    except SessionError as exc:
        print(f"botrbac: {exc}", file=sys.stderr)
        return 2


def cmd_shell_init(args: argparse.Namespace) -> int:
    from .shell import DEFAULT_AGENTS, script

    shell = args.shell or os.path.basename(os.environ.get("SHELL", "bash"))
    agents = [a for a in (args.agents or ",".join(DEFAULT_AGENTS)).split(",") if a]
    try:
        print(script("fish" if shell == "fish" else "posix", agents), end="")
    except ValueError as exc:
        print(f"botrbac: {exc}", file=sys.stderr)
        return 2
    return 0


def cmd_wrap(args: argparse.Namespace) -> int:
    from pathlib import Path

    from .coverage import AgentConfig, known_configs, wrap

    kind = "codex" if args.agent == "codex" else "json"
    if args.file:
        targets = [AgentConfig(args.agent, Path(args.file).expanduser(), kind)]
    else:
        targets = [c for c in known_configs() if c.agent == args.agent and c.path.exists()]
        if args.agent == "claude-code":
            # The project's .mcp.json; with --user, ~/.claude.json (user and per-project).
            wanted = ".claude.json" if args.user else ".mcp.json"
            targets = [c for c in targets if c.path.name == wanted] or (
                [] if args.user else [AgentConfig("claude-code", Path.cwd() / ".mcp.json", "json")]
            )
    if not targets:
        print(f"No {args.agent} config found. Give one with --file PATH.", file=sys.stderr)
        return 1
    for target in targets:
        try:
            result = wrap(target, dry_run=args.dry_run)
        except (OSError, ValueError) as exc:
            print(f"botrbac: {exc}", file=sys.stderr)
            return 1
        verb = "Would move" if args.dry_run else "Moved"
        print(f"{result['file']}:")
        for old, new in result["moved"]:
            print(f"  {verb} {old} behind botrbac (as {new})")
        for name in result["kept"]:
            print(f"  Left {name} as it is (botrbac cannot run it): it stays unguarded")
        for name in result.get("assumed_http") or []:
            print(f"  {name} has a url and no type: treated as streamable HTTP. If it is an")
            print("    old SSE server it will fail behind botrbac; restore it from the backup.")
        if result.get("name_taken"):
            print(
                "  [mcp_servers.botrbac] is one of your own servers, so the gateway was not "
                "added. Rename that table, then run this again."
            )
        for table in result.get("delete_tables") or []:
            print(f"  Now delete {table} from that file so Codex only uses botrbac")
        if result["backup"]:
            print(f"  Backup: {result['backup']}")
    return 0


def _wrap_hint(config: Any) -> str:
    if config.agent == "claude-code" and config.path.name == ".claude.json":
        return "botrbac wrap claude-code --user"
    if config.path.parent.resolve() == Path.cwd().resolve() or config.agent == "codex":
        return f"botrbac wrap {config.agent}"
    return f"botrbac wrap {config.agent} --file {config.path}"


def cmd_doctor(args: argparse.Namespace) -> int:
    from .coverage import unguarded

    problems = 0
    creds = state.read_json("credentials.json")
    cached = policy.load_cached()
    print(("✓ logged in to " + creds.get("server", "?")) if creds else "✗ not logged in")
    problems += 0 if creds else 1
    if cached:
        days = int(cached["policy"].get("role", {}).get("offline_days") or 7)
        age = (time.time() - float(cached.get("fetched_at") or 0)) / 86400
        ok = age <= days
        print(f"{'✓' if ok else '✗'} policy is {age:.1f} days old (grace {days} days)")
        problems += 0 if ok else 1
    else:
        print("✗ no policy cached: every tool is blocked")
        problems += 1
    servers = load_servers()
    print(f"✓ {len(servers)} server(s) behind the gateway" if servers else "! no servers yet")
    found = unguarded()
    for config, name in found:
        print(f"✗ {config.agent}: {name} in {config.path} is not behind botrbac")
        print(f"    fix: {_wrap_hint(config)}")
    state.note_seen(unguarded=sorted({name for _, name in found}))
    return 1 if problems or found else 0


def cmd_check(args: argparse.Namespace) -> int:
    from .check import run

    return run(args.agent, args.tool, args.block_unguarded, args.format)


def cmd_hooks(args: argparse.Namespace) -> int:
    from pathlib import Path

    from .hooks import install_claude_code

    if args.agent != "claude-code":
        print(
            "Automatic hook setup is only for Claude Code. For another agent, make its "
            f"pre-tool hook run: botrbac check --agent {args.agent} (see docs/terminal.md)."
        )
        return 0
    base = Path.home() if args.user else Path.cwd()
    result = install_claude_code(base / ".claude" / "settings.json", not args.allow_unguarded)
    if not result["changed"]:
        print(f"Already set up: {result['file']}")
        return 0
    print(f"Claude Code now asks botrbac before every tool call: {result['file']}")
    if result["backup"]:
        print(f"Backup: {result['backup']}")
    print("Give the role claude-code/<Tool> patterns (claude-code/Read, claude-code/*) as needed.")
    return 0


# ---- upstream servers ------------------------------------------------------------


def load_servers() -> dict[str, Any]:
    from .gateway import load_config

    return load_config()["servers"]


def save_servers(servers: dict[str, Any]) -> None:
    data = state.read_json("config.json", {}) or {}
    data["servers"] = servers
    state.write_json("config.json", data, private=True)


def cmd_servers(args: argparse.Namespace) -> int:
    servers = load_servers()
    if args.action == "list":
        for name, spec in sorted(servers.items()):
            target = spec.get("url") or " ".join([spec.get("command", ""), *spec.get("args", [])])
            print(f"{name:<16} {target}")
        return 0
    name = normalize_server(args.name or "")
    if args.action == "add" and name == COMMAND_SERVER:
        print(
            f"{name!r} is reserved for cmd/<program> patterns. Pick another name.", file=sys.stderr
        )
        return 2
    if args.action == "remove":
        servers.pop(name, None)
        save_servers(servers)
        print(f"Removed {name}.")
        return 0
    if args.url:
        servers[name] = {"url": args.url}
    elif args.command_line:
        command = args.command_line
        servers[name] = {"command": command[0], "args": command[1:]}
    else:
        print("Give --url URL or a command after --", file=sys.stderr)
        return 2
    save_servers(servers)
    print(f"Added {name}. Its tools appear as {name}__<tool> in botrbac gateway.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="botrbac", description=__doc__)
    parser.add_argument("--version", action="version", version=f"botrbac {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("login", help="connect this computer to your Bot RBAC account")
    p.add_argument(
        "--server",
        help=f"the website's address (default: BOTRBAC_SERVER, else {DEFAULT_SERVER})",
    )
    p.set_defaults(fn=cmd_login)
    sub.add_parser("logout", help="forget this computer's login").set_defaults(fn=cmd_logout)
    sub.add_parser("status", help="login, role, policy age, rows waiting").set_defaults(
        fn=cmd_status
    )
    p = sub.add_parser("sync", help="send waiting audit rows and fetch the policy")
    p.add_argument(
        "--retry-rejected", action="store_true", help="send rows the server refused again"
    )
    p.set_defaults(fn=cmd_sync)
    p = sub.add_parser("log", help="recent tool calls on this computer")
    p.add_argument("-n", "--limit", type=int, default=20)
    p.set_defaults(fn=cmd_log)
    p = sub.add_parser("gateway", help="run the MCP gateway (what your agent starts)")
    p.add_argument("--agent", help="name to record for the agent (default: from the client)")
    p.set_defaults(fn=cmd_gateway)
    p = sub.add_parser("run", help="run an agent with a narrower role: run --role X -- claude")
    p.add_argument("--role", required=True, help="a role's name or id from the website")
    p.add_argument("--agent", help="name to record (default: the program's name)")
    p.set_defaults(fn=cmd_run)
    p = sub.add_parser("shell-init", help="shell functions for `claude --botrbac --role X`")
    p.add_argument("--shell", choices=["bash", "zsh", "fish"])
    p.add_argument("--agents", help="comma-separated commands to wrap")
    p.set_defaults(fn=cmd_shell_init)
    p = sub.add_parser("wrap", help="move an agent's MCP servers behind botrbac")
    p.add_argument("agent", choices=["claude-code", "cursor", "gemini", "codex", "other"])
    p.add_argument("--file", help="the agent's MCP config file (JSON with mcpServers)")
    p.add_argument(
        "--user", action="store_true", help="claude-code: ~/.claude.json instead of ./.mcp.json"
    )
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(fn=cmd_wrap)
    sub.add_parser("doctor", help="check login, policy and unguarded servers").set_defaults(
        fn=cmd_doctor
    )
    p = sub.add_parser("check", help="for an agent's pre-tool hook: allow or block one call")
    p.add_argument("--agent", required=True, help="the agent's name, e.g. claude-code")
    p.add_argument("--tool", help="the tool's name (default: read the hook's JSON on stdin)")
    p.add_argument(
        "--block-unguarded",
        action="store_true",
        help="block MCP tools that do not come through botrbac gateway",
    )
    p.add_argument("--format", choices=["exit", "json"], default="exit")
    p.set_defaults(fn=cmd_check)
    p = sub.add_parser("hooks", help="install the pre-tool hook for an agent")
    p.add_argument("action", choices=["install"])
    p.add_argument("agent")
    p.add_argument("--user", action="store_true", help="all projects (~/.claude/settings.json)")
    p.add_argument(
        "--allow-unguarded",
        action="store_true",
        help="check MCP tools that bypass the gateway instead of blocking them",
    )
    p.set_defaults(fn=cmd_hooks)
    p = sub.add_parser(
        "servers",
        help="MCP servers the gateway sits in front of",
        epilog="Add a local server with: botrbac servers add NAME -- command args…",
    )
    p.add_argument("action", choices=["list", "add", "remove"])
    p.add_argument("name", nargs="?")
    p.add_argument("--url", help="a streamable HTTP MCP server")
    p.set_defaults(fn=cmd_servers)
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Everything after the first `--` is a command to run, never botrbac's own options.
    tail: list[str] = []
    if "--" in argv:
        cut = argv.index("--")
        argv, tail = argv[:cut], argv[cut + 1 :]
    args = build_parser().parse_args(argv)
    args.command_line = tail
    try:
        return int(args.fn(args) or 0)
    except NotLoggedIn as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except ApiError as exc:
        print(f"The server refused that: {exc}", file=sys.stderr)
        return 1
    except httpx.HTTPError as exc:
        print(f"Could not reach the Bot RBAC website: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

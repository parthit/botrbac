"""botrbac: roles from the Bot RBAC website, enforced for agents on this computer."""

import argparse
import asyncio
import os
import platform
import socket
import sys
import time
from datetime import datetime
from typing import Any

from . import __version__, policy, state
from .api import Api, ApiError, NotLoggedIn
from .patterns import normalize_server
from .queue import AuditQueue


def _api(args: argparse.Namespace) -> Api:
    return Api(getattr(args, "server", None) or os.environ.get("BOTRBAC_SERVER"))


def cmd_login(args: argparse.Namespace) -> int:
    api = _api(args)
    if not api.server:
        print("Give the website's address: botrbac login --server https://…", file=sys.stderr)
        return 2
    started = api.start_login(socket.gethostname(), f"{platform.system()} {platform.release()}")
    print(f"Open {started['verification_uri']} and enter the code {started['user_code']}")
    print(f"  (or open {started['verification_uri_complete']})")
    interval = int(started.get("interval") or 5)
    deadline = time.time() + int(started.get("expires_in") or 600)
    while time.time() < deadline:
        time.sleep(interval)
        result = api.poll_login(started["device_code"])
        if isinstance(result, dict):
            fresh = policy.refresh(api)
            role = (fresh or {}).get("role", {}).get("name", "?")
            print(f"Logged in. This terminal's role: {role}")
            return 0
        if result == "slow_down":
            interval += 5
        elif result != "authorization_pending":
            print(f"Login did not complete: {result}", file=sys.stderr)
            return 1
    print("The code expired. Run botrbac login again.", file=sys.stderr)
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
        print("Not logged in. Run: botrbac login --server <url>")
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
    print(f"Waiting:  {queue.waiting()} audit rows to send")
    session = policy.load_session(os.environ.get(policy.SESSION_ENV))
    if session:
        print(f"Session:  {session.get('id')} as {session.get('role_name')}")
    servers = load_servers()
    print(f"Servers:  {', '.join(servers) or 'none (botrbac servers add …)'}")
    return 0


def cmd_sync(args: argparse.Namespace) -> int:
    from .sync import sync

    result = sync(_api(args), AuditQueue())
    if result.get("error"):
        print(f"Offline: {result['waiting']} rows waiting ({result['error']})")
        return 1
    print(f"Sent {result['sent']} rows. {result['waiting']} waiting.")
    return 0


def cmd_log(args: argparse.Namespace) -> int:
    for row in AuditQueue().recent(args.limit):
        when = datetime.fromtimestamp(row["ts"]).strftime("%Y-%m-%d %H:%M:%S")
        what = row.get("tool") or f"session {row.get('session_id')} as {row.get('role')}"
        mark = "" if row["sent"] else "  (not sent yet)"
        print(f"{when}  {row['decision']:<7} {what}  {row.get('reason', '')}{mark}")
    return 0


def cmd_gateway(args: argparse.Namespace) -> int:
    from .gateway import serve

    api = _api(args) if state.read_json("credentials.json") else None
    asyncio.run(serve(args.agent, api))
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
    p.add_argument("--server", help="the website's address (or BOTRBAC_SERVER)")
    p.set_defaults(fn=cmd_login)
    sub.add_parser("logout", help="forget this computer's login").set_defaults(fn=cmd_logout)
    sub.add_parser("status", help="login, role, policy age, rows waiting").set_defaults(
        fn=cmd_status
    )
    sub.add_parser("sync", help="send waiting audit rows and fetch the policy").set_defaults(
        fn=cmd_sync
    )
    p = sub.add_parser("log", help="recent tool calls on this computer")
    p.add_argument("-n", "--limit", type=int, default=20)
    p.set_defaults(fn=cmd_log)
    p = sub.add_parser("gateway", help="run the MCP gateway (what your agent starts)")
    p.add_argument("--agent", help="name to record for the agent (default: from the client)")
    p.set_defaults(fn=cmd_gateway)
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


if __name__ == "__main__":
    sys.exit(main())

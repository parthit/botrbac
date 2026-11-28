"""botrbac: roles from the Bot RBAC website, enforced for agents on this computer."""

import argparse
import asyncio
import contextlib
import os
import platform
import socket
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from . import __version__, policy, state
from .api import DEFAULT_SERVER, Api, ApiError, NotLoggedIn
from .patterns import COMMAND_SERVER, normalize_server
from .queue import KEEP_SENT, AuditQueue


def _api(args: argparse.Namespace) -> Api:
    return Api(getattr(args, "server", None) or os.environ.get("BOTRBAC_SERVER"))


def _say(*lines: str) -> None:
    """Printed and flushed at once: an agent running `botrbac login` reads the link and
    code while the command is still waiting."""
    for line in lines:
        print(line, flush=True)


def _safe_server(server: str) -> bool:
    """https, or plain http to this computer itself (local development)."""
    parts = urlsplit(server)
    if parts.scheme == "https":
        return bool(parts.hostname)
    return parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1", "::1")


def cmd_login(args: argparse.Namespace) -> int:
    server = args.server or os.environ.get("BOTRBAC_SERVER") or DEFAULT_SERVER
    if not _safe_server(server):
        _say(
            f"Refusing to sign in to {server}: it is not https.",
            "This computer's sign-in would travel unencrypted. Use the https address.",
        )
        return 1
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
    from . import identity

    for name in ("credentials.json", "policy.json"):
        state.remove(name)
    identity.forget()
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


def _role_line(patterns: list[str], limit: int = 6) -> str:
    """A role's patterns on one line: tools first, then the shell's programs."""
    if not patterns:
        return "no tools"
    if "*" in patterns:
        return "every tool"
    tools = [p for p in patterns if not p.startswith("cmd/")]
    programs = [p[4:] for p in patterns if p.startswith("cmd/")]
    shown = ", ".join(tools[:limit]) + (
        f", +{len(tools) - limit} more" if len(tools) > limit else ""
    )
    if programs:
        shown += ("; " if shown else "") + "shell runs only " + ", ".join(programs[:limit])
        if len(programs) > limit:
            shown += f", +{len(programs) - limit} more"
    return shown


def cmd_roles(args: argparse.Namespace) -> int:
    """The roles this computer knows: its own, and the ones `--role` can narrow a run to."""
    if not state.read_json("credentials.json", {}):
        print("Not logged in. Run: botrbac login")
        return 1
    cached = policy.load_cached()
    policy.refresh(_api(args))  # offline: the last list kept here
    cached = policy.load_cached() or cached
    pol = (cached or {}).get("policy") or {}
    roles = [r for r in pol.get("roles") or [] if isinstance(r, dict)]
    mine = pol.get("role") or {}
    if not mine and not roles:
        print("No roles here yet. Run: botrbac sync")
        return 1
    if args.name:
        wanted = args.name.strip().lower()
        found = next(
            (r for r in roles if wanted in (str(r.get("name", "")).lower(), str(r.get("id")))),
            None,
        )
        if found is None:
            names = ", ".join(str(r.get("name")) for r in roles) or "none"
            print(f"No role called {args.name!r}. Roles: {names}", file=sys.stderr)
            return 1
        print(
            f"{found.get('name')}"
            + (" (this computer's role)" if found.get("id") == mine.get("id") else "")
        )
        for pattern in found.get("patterns") or ["(no tools)"]:
            print(f"  {pattern}")
        return 0
    print(f"This computer's role: {mine.get('name', '?')}")
    session = policy.load_session(os.environ.get(policy.SESSION_ENV))
    if session:
        names = [n for n in session.get("role_names") or [session.get("role_name")] if n]
        if names:
            print(f"This run is narrowed to: {', then '.join(str(n) for n in names)}")
    print("Roles (narrow one run with: botrbac run --role NAME -- claude):")
    width = max((len(str(r.get("name", ""))) for r in roles), default=0)
    for role in roles:
        mark = "*" if role.get("id") == mine.get("id") else " "
        name = str(role.get("name", "?"))
        print(f"{mark} {name:<{width}}  {_role_line(list(role.get('patterns') or []))}")
    print("A run gets only what both its role and this computer's role allow.")
    print(f"Make or change roles: {policy._site()}/terminal/roles")
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
        decision = row["decision"]
        if decision == "prompt":
            what = f"prompt {str(row.get('prompt_id') or '')[-8:]}".rstrip()
        elif decision == "result":
            facts = [str(row.get("outcome") or "")]
            if row.get("exit_code") is not None:
                facts.append(f"exit {row['exit_code']}")
            if row.get("duration_ms") is not None:
                facts.append(f"{row['duration_ms']} ms")
            what = f"{row.get('tool')}  {', '.join(f for f in facts if f)}"
        else:
            what = row.get("tool") or f"session {row.get('session_id')} as {row.get('role')}"
        mark = {"sent": "", "rejected": "  (refused by the server)"}.get(
            row.get("status", ""), "  (not sent yet)"
        )
        print(f"{when}  {decision:<7} {what}  {row.get('reason', '')}{mark}".rstrip())
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Walk audit.db's hash chain and check it against the website's signed checkpoint."""
    from . import chain

    queue = AuditQueue()
    rows, pruned, tip = queue.chain_rows()
    unverified = ""
    walked = chain.walk(rows, pruned, tip)
    problems = len(walked["problems"])
    if walked["count"]:
        note = f", rows up to {pruned} pruned after sending" if pruned else ""
        print(f"Local record: rows {walked['first']}-{walked['last']}{note}")
    else:
        print("Local record: no chained rows yet")
    for seq, what in walked["problems"]:
        print(f"✗ row {seq}: {what}")
    creds = state.read_json("credentials.json", {}) or {}
    if creds and not args.offline:
        try:
            chain.remember_checkpoint(_api(args).checkpoint())
        except (ApiError, NotLoggedIn, httpx.HTTPError):
            print("! could not reach the website; checking the last checkpoint kept here")
    checkpoint = (state.read_json("state.json", {}) or {}).get("checkpoint")
    if not checkpoint:
        print("! no checkpoint from the website yet (botrbac sync gets one)")
    elif not chain.verify_checkpoint(creds.get("policy_key"), checkpoint):
        problems += 1
        print("✗ the checkpoint's signature does not match the website's key pinned at login")
    else:
        seq, signed = checkpoint["seq"], checkpoint["row_hash"]
        local = walked["hashes"].get(seq)
        when = datetime.fromtimestamp(float(checkpoint.get("ts") or 0)).strftime("%Y-%m-%d %H:%M")
        if creds.get("terminal_id") and checkpoint.get("terminal_id") != creds["terminal_id"]:
            print(f"! the checkpoint is from an earlier login ({checkpoint.get('terminal_id')})")
        if local == signed:
            print(f"✓ row {seq} matches the website's signed checkpoint ({when})")
        elif local is None and seq <= pruned:
            print(f"! row {seq} (the checkpoint) was already pruned here; nothing to compare")
            unverified = f"row {seq} was pruned here, so the website's checkpoint was not checked"
            if queue.sent_kept() < KEEP_SENT:
                # Pruning keeps the newest KEEP_SENT sent rows: fewer means rows that
                # should still be here are gone (or the prune mark was raised by hand).
                problems += 1
                print("✗ fewer sent rows are kept here than pruning leaves: rows are missing")
        elif local is None:
            problems += 1
            print(
                f"✗ the website signed row {seq} ({when}), and it is not in this computer's record"
            )
        else:
            problems += 1
            print(f"✗ row {seq} here is not the row the website signed ({when})")
    if problems:
        print(f"{problems} problem(s) found.")
    elif unverified:
        print(f"Not verified: {unverified}. Run botrbac sync for a newer checkpoint.")
    else:
        # Intact is not true: code running as you could still have written false rows
        # before they were sent (docs/terminal.md, record integrity).
        print("Record intact: no row missing, reordered or changed since it was written.")
    return 1 if problems else 0


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
        return run(args.role, args.command_line, args.agent, api, args.task)
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


def cmd_add_gateway(args: argparse.Namespace) -> int:
    from .coverage import GATEWAY_FILES, AgentConfig, add_gateway

    relative, kind = GATEWAY_FILES[args.agent]
    path = Path(args.file).expanduser() if args.file else Path.home() / relative
    try:
        result = add_gateway(AgentConfig(args.agent, path, kind), dry_run=args.dry_run)
    except (OSError, ValueError) as exc:
        print(f"botrbac: {exc}", file=sys.stderr)
        return 1
    if result.get("name_taken"):
        print(
            f"botrbac: {path} already has a server called botrbac that is not the gateway. "
            "Rename it, then run this again.",
            file=sys.stderr,
        )
        return 1
    if not result["changed"]:
        print(f"Already set up: {path}")
        return 0
    verb = "Would add" if args.dry_run else "Added"
    print(f"{verb} botrbac gateway to {path}. Other servers were not changed.")
    if result["backup"]:
        print(f"Backup: {result['backup']}")
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
    from .hooks import hook_report

    for agent, status in hook_report().items():
        if status == "installed":
            print(f"✓ {agent} hook is installed")
            continue
        problems += 1
        what = "switched off (disableAllHooks)" if status == "disabled" else "missing"
        print(f"✗ {agent} hook is {what}: its own tools are not checked")
        print(f"    fix: botrbac hooks install {agent} --user --allow-unguarded")
    from .agents import doctor_report

    doctor_report(print)
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

    from .hooks import expect_hook, install_claude_code, remove_claude_code

    if args.agent != "claude-code":
        from .agents import cmd_hooks as other_agent_hooks

        return other_agent_hooks(args)
    base = Path.home() if args.user else Path.cwd()
    settings = base / ".claude" / "settings.json"
    if args.action == "remove":
        removed = remove_claude_code(settings)
        expect_hook("claude-code", False)
        if removed["changed"]:
            print(f"Removed the botrbac hook from {removed['file']}")
            print(f"Backup: {removed['backup']}")
        else:
            print(f"No botrbac hook in {removed['file']}")
        return 0
    result = install_claude_code(settings, not args.allow_unguarded)
    expect_hook("claude-code", True)
    if not result["changed"]:
        print(f"Already set up: {result['file']}")
        return 0
    print(f"Claude Code now asks botrbac before every tool call: {result['file']}")
    if result["backup"]:
        print(f"Backup: {result['backup']}")
    print("Give the role claude-code/<Tool> patterns (claude-code/Read, claude-code/*) as needed.")
    return 0


def cmd_trailer(args: argparse.Namespace) -> int:
    from .trailer import TrailerError, install, remove

    repo = Path(args.repo or ".").expanduser()
    try:
        if args.action == "remove":
            done = remove(repo)
            if not done["removed"]:
                print(f"No botrbac trailer hook in {done['hook']}")
            else:
                print(f"Removed the botrbac trailer hook: {done['hook']}")
                if done["restored"]:
                    print("Put the hook that was there before back in place.")
            return 0
        done = install(repo, args.site)
    except (OSError, TrailerError) as exc:
        print(f"botrbac: {exc}", file=sys.stderr)
        return 1
    print(f"{'Installed' if done['changed'] else 'Already set up'}: {done['hook']}")
    if done["backup"]:
        print(f"The hook that was there runs first: {done['backup']}")
    print("Commits made inside `botrbac run` now name their session (Botrbac-Session: …).")
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
    parser.add_argument(
        "--home",
        metavar="PATH",
        help="botrbac's folder (default: BOTRBAC_HOME, else ~/.config/botrbac); "
        "hooks and the gateway are installed with it",
    )
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
    p = sub.add_parser("roles", help="this computer's role and the roles --role can use")
    p.add_argument("name", nargs="?", help="show every pattern of one role")
    p.set_defaults(fn=cmd_roles)
    p = sub.add_parser("sync", help="send waiting audit rows and fetch the policy")
    p.add_argument(
        "--retry-rejected", action="store_true", help="send rows the server refused again"
    )
    p.set_defaults(fn=cmd_sync)
    p = sub.add_parser("log", help="recent tool calls on this computer")
    p.add_argument("-n", "--limit", type=int, default=20)
    p.set_defaults(fn=cmd_log)
    p = sub.add_parser(
        "verify", help="check this computer's audit record against the website's checkpoint"
    )
    p.add_argument("--offline", action="store_true", help="use the last checkpoint kept here")
    p.set_defaults(fn=cmd_verify)
    p = sub.add_parser("gateway", help="run the MCP gateway (what your agent starts)")
    p.add_argument("--agent", help="name to record for the agent (default: from the client)")
    p.set_defaults(fn=cmd_gateway)
    p = sub.add_parser("run", help="run an agent with a narrower role: run --role X -- claude")
    p.add_argument("--role", required=True, help="a role's name or id from the website")
    p.add_argument("--agent", help="name to record (default: the program's name)")
    p.add_argument(
        "--task", help="what this session is for (recorded sealed, with Record commands on)"
    )
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
    p = sub.add_parser(
        "add-gateway", help="add botrbac gateway to an agent's MCP config (other servers kept)"
    )
    p.add_argument("--agent", required=True, choices=["cursor", "codex", "gemini"])
    p.add_argument("--file", help="the config file (default: the agent's file in your home)")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(fn=cmd_add_gateway)
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
    p = sub.add_parser(
        "hooks", help="add or remove the pre-tool hook: claude-code, codex, gemini, cursor"
    )
    p.add_argument("action", choices=["install", "remove"])
    p.add_argument("agent")
    p.add_argument(
        "--user",
        action="store_true",
        help="every project: the agent's file in your home (~/.claude/settings.json, "
        "~/.codex/hooks.json, ~/.gemini/settings.json, ~/.cursor/hooks.json)",
    )
    p.add_argument(
        "--allow-unguarded",
        action="store_true",
        help="check MCP tools that bypass the gateway instead of blocking them",
    )
    p.set_defaults(fn=cmd_hooks)
    p = sub.add_parser(
        "trailer", help="add a Botrbac-Session trailer to commits made in a session (opt-in)"
    )
    p.add_argument("action", choices=["install", "remove"])
    p.add_argument("--repo", help="the git repository (default: the current directory)")
    p.add_argument("--site", help="the website's address (default: from botrbac login)")
    p.set_defaults(fn=cmd_trailer)
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
    if args.home:
        # Wins over BOTRBAC_HOME; children (an agent under `botrbac run`) get it too.
        state.set_home(args.home)
        os.environ["BOTRBAC_HOME"] = str(state.home_path())
    try:
        return int(args.fn(args) or 0)
    except BrokenPipeError:
        # `botrbac roles | head`: the reader left. Not an error worth a traceback.
        with contextlib.suppress(OSError):
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        # A hook's answer that could not be written must not read as "allow" (exit 2 blocks).
        return 2 if args.cmd == "check" else 1
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

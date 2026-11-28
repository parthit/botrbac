"""Terminal: --role sessions, shell-init, wrap and doctor, the session page."""

import json
import os
import shutil
import subprocess
import sys
import time
import tomllib
from pathlib import Path

import pytest

from botrbac_cli import policy, session, state
from botrbac_cli.coverage import AgentConfig, unguarded, wrap
from botrbac_cli.main import main
from botrbac_cli.queue import AuditQueue
from tests import dash
from tests.conftest import OWNER_EMAIL
from tests.terminal_helpers import bearer, cache_policy, connect_terminal, terminal_app

CLI = [sys.executable, "-m", "botrbac_cli"]
BASH = shutil.which("bash")
ZSH = shutil.which("zsh")
ROLES = [
    {"id": "reviewer", "name": "Reviewer", "patterns": ["github/get_*", "fs/*"]},
    {"id": "reader", "name": "Reader", "patterns": ["github/get_issue"]},
    {"id": "full", "name": "Full access", "patterns": ["*"]},
]


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("BOTRBAC_HOME", str(tmp_path / "botrbac"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    monkeypatch.delenv(policy.SESSION_ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _cache(revoked=()):
    cache_policy(["github/*", "fs/*"], name="Dev", role_id="dev", roles=ROLES, revoked=revoked)


def _allowed(tool: str) -> bool:
    return policy.Enforcer().decide(tool).allowed


def test_sessions_only_narrow(monkeypatch) -> None:
    _cache()
    outer = session.start("reviewer", "/usr/bin/claude")
    monkeypatch.setenv(policy.SESSION_ENV, outer["id"])
    assert _allowed("github/get_issue") and _allowed("fs/read_file")
    assert not _allowed("github/create_issue")

    wider = session.start("Full access", "codex")  # asking for more changes nothing
    monkeypatch.setenv(policy.SESSION_ENV, wider["id"])
    assert wider["parent"] == outer["id"] and wider["lineage"] == [outer["id"], wider["id"]]
    assert not _allowed("github/create_issue") and _allowed("fs/read_file")

    inner = session.start("reader", "codex")
    monkeypatch.setenv(policy.SESSION_ENV, inner["id"])
    assert _allowed("github/get_issue") and not _allowed("fs/read_file")

    rows = [r for r in AuditQueue().pending() if r["decision"] == "session"]
    assert [r["role"] for r in rows] == ["Reviewer", "Full access", "Reader"]
    assert rows[0]["program"] == "claude" and "parent_session_id" not in rows[0]
    assert rows[2]["parent_session_id"] == wider["id"]

    # Revoking the outer session ends everything started under it.
    _cache(revoked=[outer["id"]])
    decision = policy.Enforcer().decide("github/get_issue")
    assert not decision.allowed and "revoked" in decision.reason


def test_session_errors(monkeypatch) -> None:
    with pytest.raises(session.SessionError):
        session.start("reviewer", "claude")  # no policy yet
    _cache()
    with pytest.raises(session.SessionError, match="Your roles"):
        session.start("nope", "claude")
    monkeypatch.setenv(policy.SESSION_ENV, "0" * 32)
    with pytest.raises(session.SessionError, match="does not know"):
        session.start("reviewer", "claude")
    monkeypatch.delenv(policy.SESSION_ENV)
    assert main(["run", "--role", "reviewer"]) == 2  # no command


def test_run_hands_the_session_to_child_processes(home, capfd) -> None:
    _cache()
    child = (
        "import os, subprocess, sys;"
        "print('outer', os.environ['BOTRBAC_SESSION']);"
        "subprocess.call([sys.executable, '-m', 'botrbac_cli', 'run', '--role', 'reader',"
        " '--', sys.executable, '-c', \"import os;print('inner', os.environ['BOTRBAC_SESSION'])\"])"
    )
    code = main(["run", "--role", "reviewer", "--", sys.executable, "-c", child])
    assert code == 0
    out = capfd.readouterr().out.split()
    outer_id, inner_id = out[out.index("outer") + 1], out[out.index("inner") + 1]
    inner = policy.load_session(inner_id)
    assert inner["parent"] == outer_id
    assert inner["chain"] == [["github/get_*", "fs/*"], ["github/get_issue"]]
    assert main(["run", "--role", "reviewer", "--", "/nonexistent/agent"]) == 127


def _shell(home: Path, shell: str):
    """Runs a line in `shell` with `botrbac shell-init` loaded and a fake `claude` that
    prints its arguments and session."""
    bin_dir = home / "bin"
    bin_dir.mkdir()
    agent = bin_dir / "claude"
    agent.write_text('#!/bin/sh\necho "args:$*"\necho "session:${BOTRBAC_SESSION:-none}"\n')
    agent.chmod(0o755)
    init = subprocess.run(  # noqa: S603 - this repo's CLI
        [*CLI, "shell-init", "--shell", Path(shell).name, "--agents", "claude"],
        capture_output=True, text=True, check=True,
    ).stdout  # fmt: skip
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}

    def run(line: str) -> subprocess.CompletedProcess:
        return subprocess.run(  # noqa: S603 - the test's own script
            [shell, "-c", f"{init}\n{line}"], capture_output=True, text=True, env=env
        )

    return run


@pytest.mark.skipif(BASH is None, reason="bash not installed")
def test_shell_init_bash(home) -> None:
    _cache()
    bash = _shell(home, BASH)
    wrapped = bash('claude --botrbac --role reviewer --model x "two words"')
    assert wrapped.returncode == 0, wrapped.stderr
    assert "args:--model x two words" in wrapped.stdout
    assert "session:none" not in wrapped.stdout
    assert "as 'Reviewer'" in wrapped.stderr

    plain = bash("claude --role stays --model x")
    assert "args:--role stays --model x" in plain.stdout and "session:none" in plain.stdout

    assert bash("claude --botrbac").returncode == 2
    assert bash("claude --role=reader --botrbac hi").stdout.startswith("args:hi")

    # `--` ends the wrapper's own options.
    plain = bash("claude -- --botrbac --role x")
    assert "args:-- --botrbac --role x" in plain.stdout and "session:none" in plain.stdout
    wrapped = bash("claude --botrbac --role reviewer -- --role keep")
    assert "args:-- --role keep" in wrapped.stdout and "session:none" not in wrapped.stdout
    missing = bash("claude --botrbac --role")
    assert missing.returncode == 2 and "needs a value" in missing.stderr


@pytest.mark.skipif(ZSH is None, reason="zsh not installed")
def test_shell_init_zsh(home) -> None:
    _cache()
    r = _shell(home, ZSH)("claude --botrbac --role reviewer hi")
    assert "args:hi" in r.stdout and "session:none" not in r.stdout


def test_shell_init_rejects_odd_names(capsys) -> None:
    assert main(["shell-init", "--agents", "claude;rm -rf"]) == 2
    assert main(["shell-init", "--shell", "fish", "--agents", "codex"]) == 0
    assert "function codex --wraps codex" in capsys.readouterr().out


def test_wrap_json_and_doctor(home) -> None:
    mcp = home / ".mcp.json"
    mcp.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "github": {"command": "npx", "args": ["-y", "gh"], "env": {"T": "1"}},
                    "remote": {"type": "http", "url": "https://mcp.example.com/mcp"},
                    "legacy": {"type": "sse", "url": "https://old.example.com/sse"},
                }
            }
        )
    )
    assert {name for _, name in unguarded(home)} == {"github", "remote", "legacy"}
    preview = wrap(AgentConfig("claude-code", mcp, "json"), dry_run=True)
    assert preview["backup"] is None and json.loads(mcp.read_text())["mcpServers"]["github"]

    result = wrap(AgentConfig("claude-code", mcp, "json"))
    assert result["moved"] == [("github", "github"), ("remote", "remote")]
    assert result["kept"] == ["legacy"]
    servers = json.loads(mcp.read_text())["mcpServers"]
    assert set(servers) == {"legacy", "botrbac"}
    assert servers["botrbac"]["args"][-3:] == ["gateway", "--agent", "claude-code"]
    assert Path(result["backup"]).exists()
    upstreams = state.read_json("config.json")["servers"]
    assert upstreams["github"] == {"command": "npx", "args": ["-y", "gh"], "env": {"T": "1"}}
    assert upstreams["remote"]["url"] == "https://mcp.example.com/mcp"

    # The same server in a second agent is not added twice.
    cursor = home / "home" / ".cursor" / "mcp.json"
    cursor.parent.mkdir()
    cursor.write_text(
        json.dumps(
            {"mcpServers": {"gh": {"command": "npx", "args": ["-y", "gh"], "env": {"T": "1"}}}}
        )
    )
    assert wrap(AgentConfig("cursor", cursor, "json"))["moved"] == [("gh", "github")]

    assert [name for _, name in unguarded(home)] == ["legacy"]
    assert main(["doctor"]) == 1
    assert state.read_json("state.json")["unguarded"] == ["legacy"]


def test_wrap_codex(home) -> None:
    config = home / "home" / ".codex" / "config.toml"
    config.parent.mkdir()
    config.write_text('model = "x"\n\n[mcp_servers.gh]\ncommand = "npx"\nargs = ["gh"]\n')
    result = wrap(AgentConfig("codex", config, "codex"))
    assert result["delete_tables"] == ["[mcp_servers.gh]"]
    parsed = tomllib.loads(config.read_text())
    assert parsed["model"] == "x"
    assert parsed["mcp_servers"]["botrbac"]["args"][-3:] == ["gateway", "--agent", "codex"]
    assert state.read_json("config.json")["servers"]["gh"]["command"] == "npx"
    again = wrap(AgentConfig("codex", config, "codex"))
    assert config.read_text().count("[mcp_servers.botrbac]") == 1 and again["moved"]


def test_session_page_and_revoke(world, memstore, oauth) -> None:
    app = terminal_app(world, memstore, oauth)
    c = dash.client(app)
    dash.login(c)
    issued = connect_terminal(c)
    root, child = "a" * 32, "b" * 32
    rows = [
        {"event_id": "e" * 16, "ts": time.time(), "decision": "session", "session_id": root,
         "role": "Reviewer", "program": "claude", "agent": "claude"},
        {"event_id": "f" * 16, "ts": time.time(), "decision": "session", "session_id": child,
         "parent_session_id": root, "role": "Reader", "program": "codex", "agent": "codex"},
        {"event_id": "g" * 16, "ts": time.time(), "decision": "deny", "session_id": child,
         "tool": "github/create_issue", "reason": "not in role Reader", "agent": "codex"},
    ]  # fmt: skip
    headers = bearer(issued)
    c.post("/api/terminal/audit", json={"rows": rows}, headers=headers)
    page = c.get(f"/terminal/sessions/{root}")
    assert page.status_code == 200
    assert (
        "Reviewer" in page.text
        and "Reader" in page.text
        and "Tried to use create issue on github" in page.text
    )
    # A malformed id has no page; a well-formed one with no rows left has a minimal one.
    assert c.get("/terminal/sessions/short").status_code == 404
    assert c.get(f"/terminal/sessions/{'c' * 32}").status_code == 200
    assert f"/terminal/sessions/{root}" in c.get("/terminal/activity").text

    token = dash.csrf(c, f"/terminal/sessions/{root}")
    c.post(f"/terminal/sessions/{root}/revoke", data={"csrf": token})
    assert 'id="revoke-session"' not in c.get(f"/terminal/sessions/{root}").text
    policy_body = c.get("/api/terminal/policy", headers=headers).json()
    assert policy_body["revoked_sessions"] == [root]
    assert app.state.terminal.activity.revoked_sessions(OWNER_EMAIL) == [root]


def test_ambiguous_role_name_is_an_error() -> None:
    roles = [
        {"id": "r_1", "name": "Reviewer", "patterns": ["a/*"]},
        {"id": "r_2", "name": "reviewer", "patterns": ["b/*"]},
    ]
    cache_policy(["*"], name="Dev", role_id="dev", roles=roles)
    with pytest.raises(session.SessionError, match="r_1, r_2"):
        session.start("Reviewer", "claude")
    assert session.start("r_2", "claude")["role_id"] == "r_2"


def test_signal_exit_code(home) -> None:
    _cache()
    code = main(["run", "--role", "reviewer", "--", sys.executable, "-c",
                 "import os, signal; os.kill(os.getpid(), signal.SIGTERM)"])  # fmt: skip
    assert code == 128 + 15


def test_wrap_claude_user_file_with_projects(home) -> None:
    user = home / "home" / ".claude.json"
    user.write_text(
        json.dumps(
            {
                "numStartups": 3,
                "mcpServers": {"notes": {"type": "http", "url": "https://n.example.com/mcp"}},
                "projects": {
                    "/work/app": {"mcpServers": {"db": {"command": "db-mcp"}}, "x": 1},
                },
            }
        )
    )
    user.chmod(0o640)
    assert main(["wrap", "claude-code", "--user"]) == 0
    data = json.loads(user.read_text())
    assert data["numStartups"] == 3
    assert set(data["mcpServers"]) == {"botrbac"}
    assert data["projects"]["/work/app"] == {"mcpServers": {}, "x": 1}
    assert oct(user.stat().st_mode & 0o777) == "0o640"  # permissions kept
    backups = list(user.parent.glob(".claude.json.botrbac-backup-*"))
    assert backups and oct(backups[0].stat().st_mode & 0o777) == "0o600"
    assert set(state.read_json("config.json")["servers"]) == {"notes", "db"}
    assert unguarded(home) == []


def test_wrap_codex_file_and_bad_json(home, capsys) -> None:
    toml_file = home / "codex.toml"
    toml_file.write_text('[mcp_servers.gh]\ncommand = "npx"\n')
    assert main(["wrap", "codex", "--file", str(toml_file)]) == 0
    assert "[mcp_servers.botrbac]" in toml_file.read_text()
    broken = home / "broken.json"
    broken.write_text("{not json")
    assert main(["wrap", "cursor", "--file", str(broken)]) == 1
    assert "not valid JSON" in capsys.readouterr().err


def test_wrap_warns_about_untyped_urls(home, capsys) -> None:
    cfg = home / "c.json"
    cfg.write_text(json.dumps({"mcpServers": {"maybe": {"url": "https://m.example.com/sse"}}}))
    main(["wrap", "cursor", "--file", str(cfg)])
    assert "treated as streamable HTTP" in capsys.readouterr().out


def test_session_page_escapes_terminal_text(world, memstore, oauth) -> None:
    app = terminal_app(world, memstore, oauth)
    c = dash.client(app)
    dash.login(c)
    root = "d" * 32
    app.state.terminal.activity.add(
        OWNER_EMAIL,
        "t_x",
        "<b>box</b>",
        [{"event_id": "h" * 16, "ts": time.time(), "decision": "session", "session_id": root,
          "role": "<i>r</i>", "program": "claude"}],
    )  # fmt: skip
    page = c.get(f"/terminal/sessions/{root}").text
    assert "<b>box</b>" not in page and "&lt;b&gt;box&lt;/b&gt;" in page


def test_wrap_codex_reports_a_taken_name(home, capsys) -> None:
    config = home / "codex2.toml"
    config.write_text('[mcp_servers.botrbac]\ncommand = "my-own-thing"\n')
    assert main(["wrap", "codex", "--file", str(config)]) == 0
    assert "was not added" in capsys.readouterr().out


def test_wrap_keeps_a_symlinked_config_a_symlink(home) -> None:
    real = home / "dotfiles" / "mcp.json"
    real.parent.mkdir()
    real.write_text(json.dumps({"mcpServers": {"gh": {"command": "npx"}}}))
    link = home / "linked.json"
    link.symlink_to(real)
    assert main(["wrap", "cursor", "--file", str(link)]) == 0
    assert link.is_symlink()
    assert "botrbac" in json.loads(real.read_text())["mcpServers"]

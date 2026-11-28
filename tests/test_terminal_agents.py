"""Terminal: hooks for Codex CLI, Gemini CLI and Cursor, their payloads, and coverage."""

import io
import json
import sys
import time
from pathlib import Path

import pytest

from botrbac_cli import agents, policy, state
from botrbac_cli.check import check
from botrbac_cli.hooks import expect_hook, hook_report, install_claude_code
from botrbac_cli.main import main
from botrbac_cli.queue import AuditQueue
from tests import dash
from tests.conftest import OWNER_EMAIL
from tests.terminal_helpers import FakeApi, bearer, connect_terminal, terminal_app

# ---- sample payloads, shaped like each agent's documented hook input ----------------

CODEX_BASH = {
    "session_id": "019a1b2c-3d4e-7f00-8a9b-0c1d2e3f4a5b",
    "transcript_path": None,
    "cwd": "/work/app",
    "hook_event_name": "PreToolUse",
    "model": "gpt-5-codex",
    "permission_mode": "default",
    "turn_id": "turn-3",
    "tool_name": "Bash",
    "tool_use_id": "call_abc123",
    "tool_input": {"command": "git status && gh pr list"},
}
CODEX_MCP = {
    **CODEX_BASH,
    "tool_name": "mcp__github__create_issue",
    "tool_input": {"title": "x"},
}
GEMINI_SHELL = {
    "session_id": "a1b2c3",
    "transcript_path": "/home/me/.gemini/tmp/chat.json",
    "cwd": "/work/app",
    "hook_event_name": "BeforeTool",
    "timestamp": "2026-11-28T10:00:00Z",
    "tool_name": "run_shell_command",
    "tool_input": {"command": "gh pr list", "description": "List PRs"},
}
GEMINI_MCP = {
    **GEMINI_SHELL,
    "tool_name": "mcp_github_create_issue",
    "tool_input": {"title": "x"},
    "mcp_context": {"server_name": "github", "tool_name": "create_issue"},
}
GEMINI_GATEWAY = {**GEMINI_SHELL, "tool_name": "mcp_botrbac_github__get_issue", "tool_input": {}}
_CURSOR_BASE = {
    "conversation_id": "c0nv-1",
    "generation_id": "gen-1",
    "workspace_roots": ["/work/app"],
}
CURSOR_SHELL = {
    **_CURSOR_BASE,
    "hook_event_name": "beforeShellExecution",
    "command": "gh pr list",
    "cwd": "/work/app",
}
CURSOR_MCP = {
    **_CURSOR_BASE,
    "hook_event_name": "beforeMCPExecution",
    "tool_name": "create_issue",
    "tool_input": json.dumps({"title": "x"}),
    "command": "npx -y @modelcontextprotocol/server-github",
}
CURSOR_MCP_URL = {**CURSOR_MCP, "url": "https://mcp.notion.com/mcp"}
del CURSOR_MCP_URL["command"]
CURSOR_GATEWAY = {**CURSOR_MCP, "tool_name": "github__get_issue", "command": "botrbac gateway"}
CURSOR_READ = {
    **_CURSOR_BASE,
    "hook_event_name": "beforeReadFile",
    "file_path": "/work/app/README.md",
    "content": "SECRET FILE TEXT",
    "attachments": [],
}


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    (tmp_path / "proj").mkdir()
    monkeypatch.chdir(tmp_path / "proj")
    monkeypatch.setenv("BOTRBAC_HOME", str(tmp_path / "botrbac"))
    monkeypatch.delenv(policy.SESSION_ENV, raising=False)
    monkeypatch.setattr(agents.shutil, "which", lambda _name: None)
    _role(
        [
            "codex/Bash",
            "gemini/run_shell_command",
            "cursor/Shell",
            "cursor/Read",
            "github/get_*",
        ]
    )
    return tmp_path / "home"


def _role(patterns: list[str]) -> None:
    state.write_json(
        "policy.json",
        {
            "policy": {
                "role": {"id": "r", "name": "Coder", "patterns": patterns},
                "roles": [],
                "revoked_sessions": [],
            },
            "fetched_at": time.time(),
        },
    )


# ---- install and remove -------------------------------------------------------------

OTHERS = {
    "codex": {"model": "o3", "hooks": {"PreToolUse": [{"matcher": "^Bash$", "hooks": [
        {"type": "command", "command": "mine.sh"}]}], "Stop": [{"hooks": []}]}},
    "gemini": {"theme": "dark", "mcpServers": {"x": {"command": "x"}}, "hooks": {
        "BeforeTool": [{"matcher": "write_file", "hooks": [
            {"type": "command", "command": "mine.sh"}]}]}},
    "cursor": {"version": 1, "hooks": {"beforeShellExecution": [{"command": "./mine.sh"}],
                                       "afterFileEdit": [{"command": "./fmt.sh"}]}},
}  # fmt: skip


@pytest.mark.parametrize("agent", ["codex", "gemini", "cursor"])
def test_install_remove_round_trip_keeps_the_rest(home, agent) -> None:
    path = home / agents.HOOK_FILES[agent]
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(OTHERS[agent], indent=2))

    first = agents.install(agent, path)
    assert first["changed"] and first["backup"]
    assert json.loads(Path(first["backup"]).read_text()) == OTHERS[agent]
    data = json.loads(path.read_text())
    for key, value in OTHERS[agent].items():
        if key != "hooks":
            assert data[key] == value
    for event in agents.HOOK_EVENTS[agent]:
        ours = [e for e in data["hooks"][event] if agents._ours(agent, e)]
        assert len(ours) == 1
    for event, entries in OTHERS[agent]["hooks"].items():
        for entry in entries:
            assert entry in data["hooks"][event]  # the person's own hooks stay
    assert agents.hook_status(agent) == "installed"

    # Idempotent: nothing written, no new backup.
    again = agents.install(agent, path)
    assert not again["changed"] and again["backup"] is None
    # Switching --allow-unguarded replaces our entry instead of adding a second one.
    agents.install(agent, path, block_unguarded=False)
    data = json.loads(path.read_text())
    for event in agents.HOOK_EVENTS[agent]:
        assert len([e for e in data["hooks"][event] if agents._ours(agent, e)]) == 1

    removed = agents.remove(agent, path)
    assert removed["changed"] and removed["backup"]
    assert json.loads(path.read_text()) == OTHERS[agent]
    assert agents.hook_status(agent) == "missing"
    assert not agents.remove(agent, path)["changed"]


def test_entry_shapes(home) -> None:
    for agent in ("codex", "gemini", "cursor"):
        agents.install(agent, home / agents.HOOK_FILES[agent])
    codex = json.loads((home / ".codex/hooks.json").read_text())["hooks"]["PreToolUse"][0]
    assert codex["matcher"] == ".*" and codex["hooks"][0]["type"] == "command"
    assert codex["hooks"][0]["command"].endswith("check --agent codex --block-unguarded")
    gemini = json.loads((home / ".gemini/settings.json").read_text())["hooks"]["BeforeTool"][0]
    assert gemini["hooks"][0]["name"] == "botrbac" and gemini["hooks"][0]["timeout"] == 60000
    cursor = json.loads((home / ".cursor/hooks.json").read_text())
    assert cursor["version"] == 1
    assert set(cursor["hooks"]) == {"beforeShellExecution", "beforeMCPExecution", "beforeReadFile"}
    assert all(e[0]["failClosed"] is True for e in cursor["hooks"].values())
    assert "--agent cursor" in cursor["hooks"]["beforeReadFile"][0]["command"]


@pytest.mark.parametrize("agent", ["codex", "gemini", "cursor"])
@pytest.mark.parametrize(
    "text", ["{oops", "[]", json.dumps({"hooks": []}), json.dumps({"hooks": {"PreToolUse": 1,
             "BeforeTool": 1, "beforeShellExecution": 1}})],
)  # fmt: skip
def test_invalid_files_are_left_alone(home, agent, text) -> None:
    path = home / agents.HOOK_FILES[agent]
    path.parent.mkdir(parents=True)
    path.write_text(text)
    with pytest.raises(ValueError):
        agents.install(agent, path)
    assert path.read_text() == text
    assert not list(path.parent.glob("*.botrbac-backup-*"))


def test_cursor_unknown_version_is_left_alone(home) -> None:
    path = home / ".cursor" / "hooks.json"
    path.parent.mkdir()
    path.write_text(json.dumps({"version": 2, "hooks": {}}))
    with pytest.raises(ValueError):
        agents.install("cursor", path)


def test_hooks_command_for_each_agent(home, capsys) -> None:
    proj = home.parent / "proj"
    assert main(["hooks", "install", "gemini"]) == 0
    assert (proj / ".gemini" / "settings.json").exists()  # the project's, without --user
    assert main(["hooks", "install", "cursor", "--user", "--allow-unguarded"]) == 0
    cursor = json.loads((home / ".cursor" / "hooks.json").read_text())
    assert "--block-unguarded" not in cursor["hooks"]["beforeShellExecution"][0]["command"]
    assert main(["hooks", "install", "codex", "--user"]) == 0
    out = capsys.readouterr().out
    assert "/hooks" in out and "cursor/Shell" in out
    assert hook_report() == {"codex": "installed", "cursor": "installed", "gemini": "installed"}

    assert main(["hooks", "remove", "cursor", "--user"]) == 0
    assert "Removed the botrbac hook" in capsys.readouterr().out
    assert "cursor" not in hook_report()

    bad = home / ".codex" / "hooks.json"
    bad.write_text("{oops")
    assert main(["hooks", "install", "codex", "--user"]) == 1
    assert "not valid JSON" in capsys.readouterr().err


def test_hook_switched_off(home) -> None:
    agents.install("gemini", home / ".gemini" / "settings.json")
    settings = home / ".gemini" / "settings.json"
    data = json.loads(settings.read_text())
    data["hooksConfig"] = {"enabled": False}
    settings.write_text(json.dumps(data))
    assert agents.hook_status("gemini") == "disabled"
    data["hooksConfig"] = {"disabled": ["botrbac"]}
    settings.write_text(json.dumps(data))
    assert agents.hook_status("gemini") == "disabled"

    agents.install("codex", home / ".codex" / "hooks.json")
    (home / ".codex" / "config.toml").write_text("[features]\nhooks = false\n")
    assert agents.hook_status("codex") == "disabled"
    (home / ".codex" / "config.toml").write_text('model = "o3"\n')
    assert agents.hook_status("codex") == "installed"


def test_codex_inline_toml_hook_counts(home) -> None:
    (home / ".codex").mkdir()
    (home / ".codex" / "config.toml").write_text(
        '[[hooks.PreToolUse]]\nmatcher = ".*"\n[[hooks.PreToolUse.hooks]]\n'
        'type = "command"\ncommand = "/usr/bin/botrbac check --agent codex"\n'
    )
    assert agents.hook_status("codex") == "installed"


# ---- payload adapters ---------------------------------------------------------------


def test_codex_payload_needs_no_change() -> None:
    assert agents.normalize("codex", CODEX_BASH) is CODEX_BASH


def test_gemini_mcp_names() -> None:
    assert agents.normalize("gemini", GEMINI_MCP)["tool_name"] == "mcp__github__create_issue"
    assert agents.normalize("gemini", GEMINI_SHELL) is GEMINI_SHELL
    no_context = {**GEMINI_MCP, "mcp_context": None, "tool_name": "mcp_my-server_do_thing"}
    assert agents.normalize("gemini", no_context)["tool_name"] == "mcp__my-server__do_thing"
    gateway = agents.normalize("gemini", GEMINI_GATEWAY)["tool_name"]
    assert gateway == "mcp__botrbac__github__get_issue"


def test_cursor_payloads() -> None:
    shell = agents.normalize("cursor", CURSOR_SHELL)
    assert shell["tool_name"] == "Shell"
    assert shell["tool_input"] == {"command": "gh pr list", "cwd": "/work/app"}
    read = agents.normalize("cursor", CURSOR_READ)
    assert read["tool_name"] == "Read" and read["tool_input"] == {
        "file_path": CURSOR_READ["file_path"]
    }
    assert "SECRET" not in json.dumps(read)  # the file's content is dropped
    mcp = agents.normalize("cursor", CURSOR_MCP)
    assert mcp["tool_name"] == "mcp__server-github__create_issue"
    assert mcp["tool_input"] == {"title": "x"}
    assert (
        agents.normalize("cursor", CURSOR_MCP_URL)["tool_name"]
        == "mcp__mcp.notion.com__create_issue"
    )
    assert (
        agents.normalize("cursor", CURSOR_GATEWAY)["tool_name"] == "mcp__botrbac__github__get_issue"
    )
    # Without hook_event_name, the keys still say which event it is.
    bare = {"command": "ls"}
    assert agents.normalize("cursor", bare)["tool_name"] == "Shell"
    assert agents.normalize("cursor", {"file_path": "/x"})["tool_name"] == "Read"
    # An event botrbac does not know, or a shell event without a command: no tool name.
    assert "tool_name" not in agents.normalize("cursor", {"hook_event_name": "stop"})
    odd = {"hook_event_name": "beforeShellExecution", "command": ["ls"]}
    assert "tool_name" not in agents.normalize("cursor", odd)  # fmt: skip


def test_check_with_each_agent_payload() -> None:
    assert check("codex", json.dumps(CODEX_BASH), None, False)[0]
    blocked, why = check("codex", json.dumps(CODEX_MCP), None, True)
    assert not blocked and "gateway" in why
    assert check("gemini", json.dumps(GEMINI_SHELL), None, False)[0]
    assert check("gemini", json.dumps(GEMINI_GATEWAY), None, True)[0]
    assert not check("gemini", json.dumps(GEMINI_MCP), None, True)[0]
    assert check("cursor", json.dumps(CURSOR_SHELL), None, True)[0]
    assert check("cursor", json.dumps(CURSOR_READ), None, True)[0]
    assert check("cursor", json.dumps(CURSOR_GATEWAY), None, True)[0]
    assert not check("cursor", json.dumps(CURSOR_MCP), None, True)[0]
    rows = AuditQueue().pending()
    assert {r["agent"] for r in rows} == {"codex", "gemini", "cursor"}
    tools = {r["tool"] for r in rows}
    assert {"codex/Bash", "gemini/run_shell_command", "cursor/Shell", "cursor/Read"} <= tools


def test_cmd_rules_apply_to_each_shell() -> None:
    _role(["codex/Bash", "gemini/run_shell_command", "cursor/Shell", "cmd/gh"])
    for agent, payload, key in (
        ("codex", CODEX_BASH, None),
        ("gemini", GEMINI_SHELL, None),
        ("cursor", CURSOR_SHELL, "command"),
    ):
        ok = json.loads(json.dumps(payload))
        if key:
            ok[key] = "gh pr list"
        else:
            ok["tool_input"]["command"] = "gh pr list"
        assert check(agent, json.dumps(ok), None, False)[0], agent
        bad = json.loads(json.dumps(ok))
        if key:
            bad[key] = "gh pr list; rm -rf /"
        else:
            bad["tool_input"]["command"] = "gh pr list; rm -rf /"
        allowed, why = check(agent, json.dumps(bad), None, False)
        assert not allowed and "cmd/rm" in why, agent


def test_protected_files_for_other_agents(home) -> None:
    _role(["*"])
    edit = {**CURSOR_SHELL, "command": "rm ~/.cursor/hooks.json"}
    allowed, why = check("cursor", json.dumps(edit), None, False)
    assert not allowed and "protects" in why
    gemini = {**GEMINI_SHELL, "tool_name": "write_file",
              "tool_input": {"file_path": str(home / ".gemini" / "settings.json")}}  # fmt: skip
    assert not check("gemini", json.dumps(gemini), None, False)[0]
    assert check("cursor", json.dumps({**CURSOR_READ, "file_path": "~/.cursor/hooks.json"}),
                 None, False)[0]  # fmt: skip  # reading is fine


# ---- answers ------------------------------------------------------------------------


def _run(monkeypatch, agent: str, stdin: str) -> int:
    monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
    return main(["check", "--agent", agent])


def test_cursor_json_allow_and_deny(monkeypatch, capsys) -> None:
    assert _run(monkeypatch, "cursor", json.dumps(CURSOR_SHELL)) == 0
    assert json.loads(capsys.readouterr().out) == {"permission": "allow"}
    denied = {**CURSOR_SHELL, "hook_event_name": "beforeMCPExecution", "tool_name": "delete"}
    assert _run(monkeypatch, "cursor", json.dumps(denied)) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["permission"] == "deny"
    assert "Blocked by Bot RBAC" in out["user_message"] and out["agent_message"]


@pytest.mark.parametrize("garbage", ["not json", "[1, 2]", "{}", '{"hook_event_name": "x"}', ""])
def test_garbage_fails_closed(monkeypatch, capsys, garbage) -> None:
    assert _run(monkeypatch, "cursor", garbage) == 0
    assert json.loads(capsys.readouterr().out)["permission"] == "deny"
    for agent in ("codex", "gemini"):
        assert _run(monkeypatch, agent, garbage) == 2
        assert "botrbac" in capsys.readouterr().err.lower()


def test_adapter_crash_fails_closed(monkeypatch, capsys) -> None:
    def boom(*_a):
        raise RuntimeError("bug")

    monkeypatch.setattr(agents, "_cursor", boom)
    assert _run(monkeypatch, "cursor", json.dumps(CURSOR_SHELL)) == 0
    assert json.loads(capsys.readouterr().out)["permission"] == "deny"
    monkeypatch.setattr(agents, "_gemini", boom)
    assert _run(monkeypatch, "gemini", json.dumps(GEMINI_SHELL)) == 2
    assert "check failed" in capsys.readouterr().err


def test_codex_and_gemini_block_with_exit_2(monkeypatch, capsys) -> None:
    write = {**CODEX_BASH, "tool_name": "apply_patch", "tool_input": {"input": "*** x"}}
    assert _run(monkeypatch, "codex", json.dumps(write)) == 2
    assert "codex/apply_patch" in capsys.readouterr().err
    assert _run(monkeypatch, "gemini", json.dumps(GEMINI_SHELL)) == 0
    assert capsys.readouterr().out == ""


# ---- doctor and coverage ------------------------------------------------------------


def test_coverage_summary(home) -> None:
    assert agents.coverage_summary() == {
        "agents_detected": [],
        "agents_hooked": [],
        "hook_off": [],
        "unguarded_servers": 0,
    }
    (home / ".claude").mkdir()
    (home / ".cursor").mkdir()
    (home / ".gemini").mkdir()
    install_claude_code(home / ".claude" / "settings.json")
    agents.install("cursor", home / ".cursor" / "hooks.json")
    expect_hook("cursor", True)
    expect_hook("codex", True)  # installed once, and the file has gone since
    (home / ".gemini" / "settings.json").write_text(
        json.dumps({"mcpServers": {"notion": {"command": "notion-mcp"}}})
    )
    summary = agents.coverage_summary()
    assert summary == {
        "agents_detected": ["claude-code", "gemini", "cursor"],
        "agents_hooked": ["claude-code", "cursor"],
        "hook_off": ["codex"],
        "unguarded_servers": 1,
    }


def test_doctor_lists_each_agent(home, capsys) -> None:
    (home / ".codex").mkdir()
    (home / ".cursor").mkdir()
    agents.install("cursor", home / ".cursor" / "hooks.json")
    (home / ".cursor" / "mcp.json").write_text(
        json.dumps({"mcpServers": {"botrbac": {"command": "botrbac", "args": ["gateway"]}}})
    )
    main(["doctor"])
    out = capsys.readouterr().out
    assert "✓ cursor found: hook ✓, gateway ✓" in out
    assert "! codex found: no hook, no gateway" in out
    assert "botrbac hooks install codex --user --allow-unguarded" in out
    assert "botrbac add-gateway --agent codex" in out


def test_sync_sends_coverage(home) -> None:
    from botrbac_cli.sync import sync

    (home / ".cursor").mkdir()
    agents.install("cursor", home / ".cursor" / "hooks.json")
    state.note_seen(unguarded=["notion", "slack"])
    api = FakeApi()
    sync(api, AuditQueue())
    assert api.bodies[0]["coverage"] == {
        "agents_detected": ["cursor"],
        "agents_hooked": ["cursor"],
        "hook_off": [],
        "unguarded_servers": 2,
    }


def test_sync_survives_a_broken_coverage_scan(monkeypatch) -> None:
    from botrbac_cli.sync import sync

    def boom(**_kw):
        raise OSError("unreadable home")

    monkeypatch.setattr(agents, "coverage_summary", boom)
    api = FakeApi()
    sync(api, AuditQueue())
    assert api.bodies[0]["coverage"] == {}


def test_coverage_shows_on_the_terminals_page(world, memstore, oauth) -> None:
    app = terminal_app(world, memstore, oauth)
    c = dash.client(app)
    dash.login(c)
    issued = connect_terminal(c)
    report = {
        "agents_detected": ["claude-code", "codex", "cursor", "<script>", 7],
        "agents_hooked": ["claude-code", "cursor"],
        "hook_off": [],
        "unguarded_servers": 0,
        "extra": "dropped",
    }
    r = c.post("/api/terminal/audit", json={"rows": [], "coverage": report}, headers=bearer(issued))
    assert r.status_code == 200
    (terminal,) = app.state.terminal.terminals.for_person(OWNER_EMAIL)
    stored = app.state.terminal.terminals.get(terminal.id).coverage
    assert stored == {
        "agents_detected": ["claude-code", "codex", "cursor"],
        "agents_hooked": ["claude-code", "cursor"],
        "hook_off": [],
        "unguarded_servers": 0,
    }
    page = c.get("/terminal").text
    assert (
        "<b>Codex isn&#39;t being checked.</b>" in page
        or "<b>Codex isn't being checked.</b>" in page
    )
    assert "botrbac hooks install codex --user --allow-unguarded" in page

    full = {**report, "agents_detected": ["cursor"], "agents_hooked": ["cursor"],
            "unguarded_servers": 1}  # fmt: skip
    c.post("/api/terminal/audit", json={"rows": [], "coverage": full}, headers=bearer(issued))
    page = c.get("/terminal").text
    assert "1 tool server goes around Bot RBAC" in page
    assert "being checked" not in page

    # An old CLI sends no coverage: the last report stays, and junk is ignored.
    for junk in (None, "x", {"unguarded_servers": -3}):
        r = c.post("/api/terminal/audit", json={"rows": [], "coverage": junk},
                   headers=bearer(issued))  # fmt: skip
        assert r.status_code == 200
    assert app.state.terminal.terminals.get(terminal.id).coverage["unguarded_servers"] == 0

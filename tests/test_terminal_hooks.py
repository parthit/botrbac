"""Terminal, phase 7: `botrbac check` for agents' own tools, and hook installation."""

import io
import json
import sys
import time

import pytest

from botrbac_cli import policy, state
from botrbac_cli.check import check, classify, tool_name
from botrbac_cli.hooks import install_claude_code
from botrbac_cli.main import main
from botrbac_cli.queue import AuditQueue


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("BOTRBAC_HOME", str(tmp_path / "botrbac"))
    monkeypatch.delenv(policy.SESSION_ENV, raising=False)
    state.write_json(
        "policy.json",
        {
            "policy": {
                "role": {
                    "id": "r",
                    "name": "Coder",
                    "patterns": ["claude-code/Read", "claude-code/Bash", "github/get_*"],
                },
                "roles": [],
                "revoked_sessions": [],
            },
            "fetched_at": time.time(),
        },
    )
    return tmp_path


def _hook(name: str) -> str:
    return json.dumps({"hook_event_name": "PreToolUse", "tool_name": name, "tool_input": {}})


def test_tool_name_shapes() -> None:
    assert tool_name({"tool_name": "Bash"}) == "Bash"
    assert tool_name({"toolName": "shell"}) == "shell"
    assert tool_name({"tool": {"name": "edit"}}) == "edit"
    assert tool_name(["x"]) == ""


def test_classify() -> None:
    assert classify("claude-code", "Bash") == ("claude-code/Bash", False)
    assert classify("claude-code", "mcp__botrbac__github__get_issue") == ("", False)
    assert classify("claude-code", "mcp__github__get_issue") == ("github/get_issue", True)
    assert classify("Gemini CLI", "run_shell_command") == ("gemini-cli/run_shell_command", False)


def test_check_decisions() -> None:
    assert check("claude-code", _hook("Bash"), None, False)[0]
    allowed, reason = check("claude-code", _hook("Write"), None, False)
    assert not allowed and "claude-code/Write" in reason and "Coder" in reason
    assert check("claude-code", _hook("mcp__botrbac__github__delete_repo"), None, True)[0]
    assert check("claude-code", _hook("mcp__github__get_issue"), None, False)[0]
    blocked, why = check("claude-code", _hook("mcp__github__get_issue"), None, True)
    assert not blocked and "gateway" in why
    assert not check("claude-code", "not json", None, False)[0]
    assert not check("claude-code", "{}", None, False)[0]
    assert check("codex", "", "Read", False)[0] is False  # codex/Read is not in the role

    rows = AuditQueue().pending()
    assert {r["via"] for r in rows} == {"hook"}
    assert [r["decision"] for r in rows] == ["allow", "deny", "allow", "deny", "deny"]


def test_check_command_exit_codes(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(_hook("Read")))
    assert main(["check", "--agent", "claude-code"]) == 0
    monkeypatch.setattr(sys, "stdin", io.StringIO(_hook("Edit")))
    assert main(["check", "--agent", "claude-code"]) == 2
    assert "Blocked by Bot RBAC" in capsys.readouterr().err
    assert main(["check", "--agent", "codex", "--tool", "Edit", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "deny"


def test_check_without_policy_blocks(home) -> None:
    state.remove("policy.json")
    assert not check("claude-code", _hook("Read"), None, False)[0]


def test_install_claude_code_hook(home) -> None:
    settings = home / "proj" / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(
        json.dumps(
            {
                "permissions": {"allow": ["Bash(ls)"]},
                "hooks": {
                    "PreToolUse": [
                        {"matcher": "Bash", "hooks": [{"type": "command", "command": "mine"}]}
                    ]
                },
            }
        )
    )
    first = install_claude_code(settings)
    assert first["backup"]
    install_claude_code(settings)  # again: still one botrbac entry
    data = json.loads(settings.read_text())
    assert data["permissions"] == {"allow": ["Bash(ls)"]}
    entries = data["hooks"]["PreToolUse"]
    assert entries[0]["hooks"][0]["command"] == "mine"
    ours = [e for e in entries if "check --agent claude-code" in e["hooks"][0]["command"]]
    assert len(ours) == 1 and ours[0]["matcher"] == "*"
    assert ours[0]["hooks"][0]["command"].endswith("--block-unguarded")


def test_hooks_command(home, monkeypatch, capsys) -> None:
    monkeypatch.chdir(home)
    assert main(["hooks", "install", "claude-code", "--allow-unguarded"]) == 0
    command = json.loads((home / ".claude" / "settings.json").read_text())["hooks"]["PreToolUse"][0]
    assert "--block-unguarded" not in command["hooks"][0]["command"]
    assert main(["hooks", "install", "codex"]) == 0
    assert "botrbac check --agent codex" in capsys.readouterr().out


def test_unexpected_error_blocks(monkeypatch, capsys) -> None:
    def boom(*_args, **_kwargs):
        raise OSError("disk")

    monkeypatch.setattr(policy.Enforcer, "decide", boom)
    monkeypatch.setattr(sys, "stdin", io.StringIO(_hook("Read")))
    assert main(["check", "--agent", "claude-code"]) == 2
    assert "check failed" in capsys.readouterr().err


def test_audit_write_failure_keeps_the_decision(monkeypatch, capsys) -> None:
    def broken(self, **_row):
        raise OSError("read-only disk")

    monkeypatch.setattr(AuditQueue, "add", broken)
    assert check("claude-code", _hook("Read"), None, False)[0]
    assert not check("claude-code", _hook("Edit"), None, False)[0]
    assert "could not record" in capsys.readouterr().err


def test_large_payload_is_read_whole(monkeypatch) -> None:
    payload = json.dumps({"tool_name": "Read", "tool_input": {"content": "x" * 3_000_000}})
    monkeypatch.setattr(sys, "stdin", io.StringIO(payload))
    assert main(["check", "--agent", "claude-code"]) == 0


def test_tool_names_are_case_sensitive() -> None:
    assert check("claude-code", "", "Read", False)[0]
    assert not check("claude-code", "", "read", False)[0]


def test_hook_install_user_scope_and_bad_file(home, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(home / "h"))
    (home / "h").mkdir()
    assert main(["hooks", "install", "claude-code", "--user"]) == 0
    settings = home / "h" / ".claude" / "settings.json"
    assert "check" in settings.read_text()

    bad = home / "bad" / ".claude" / "settings.json"
    bad.parent.mkdir(parents=True)
    bad.write_text("{oops")
    with pytest.raises(ValueError, match="left as it is"):
        install_claude_code(bad)
    assert bad.read_text() == "{oops"


def test_hook_install_twice_makes_no_new_backup(home) -> None:
    settings = home / "p" / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text("{}")
    assert install_claude_code(settings)["changed"]
    second = install_claude_code(settings)
    assert not second["changed"] and second["backup"] is None
    assert len(list(settings.parent.glob("settings.json.botrbac-backup-*"))) == 1


def test_unrelated_hook_that_mentions_botrbac_is_kept(home) -> None:
    settings = home / "q" / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True)
    mine = {"type": "command", "command": "echo botrbac check --agent is great"}
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [mine]}]}}))
    install_claude_code(settings)
    entries = json.loads(settings.read_text())["hooks"]["PreToolUse"]
    assert entries[0]["hooks"][0] == mine and len(entries) == 2

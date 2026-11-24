"""`cmd/<program>` patterns: which programs an agent's shell tool may run."""

import json
import time

import pytest

from botrbac_cli import policy, state
from botrbac_cli.check import check
from botrbac_cli.patterns import (
    PatternError,
    chain_allows,
    chain_allows_command,
    command_allowed,
    validate,
)
from botrbac_cli.queue import AuditQueue
from botrbac_cli.shellcmd import CommandError, command_text, is_shell_tool, programs


def _role(patterns, chain=None):
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


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("BOTRBAC_HOME", str(tmp_path / "botrbac"))
    monkeypatch.delenv(policy.SESSION_ENV, raising=False)
    _role(["claude-code/Bash", "claude-code/Read", "cmd/gh", "cmd/git"])
    return tmp_path


def _bash(command, tool="Bash"):
    return json.dumps({"tool_name": tool, "tool_input": {"command": command}})


# ---- the grammar -------------------------------------------------------------------


def test_cmd_patterns_validate_and_match() -> None:
    assert validate("cmd/gh") == "cmd/gh"
    assert validate("cmd/*") == "cmd/*"
    assert validate("cmd/git*") == "cmd/git*"
    assert command_allowed(["cmd/gh"], "gh")
    assert not command_allowed(["cmd/gh"], "ghx")
    assert command_allowed(["cmd/git*"], "git-lfs")
    assert command_allowed(["cmd/*"], "rm")
    # Only cmd/ patterns name programs: * and */read* never allow one.
    assert not command_allowed(["*", "*/read*"], "readlink")
    # A list without cmd/ patterns does not limit programs; one with them does.
    assert chain_allows_command([["*"], ["cmd/gh"]], "gh")
    assert not chain_allows_command([["*"], ["cmd/gh"]], "rm")
    assert chain_allows_command([["claude-code/Bash"]], "rm")
    assert not chain_allows_command([], "gh")
    assert chain_allows([["*"]], "github/get_issue")


def test_bare_word_says_use_cmd() -> None:
    with pytest.raises(PatternError, match="To allow the gh command, use cmd/gh."):
        validate("gh")
    with pytest.raises(PatternError, match="not a tool pattern"):
        validate("gh pr list")


# ---- reading commands ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "found"),
    [
        ("gh pr list", ["gh"]),
        ("git status && gh pr view 3", ["git", "gh"]),
        ("FOO=1 gh pr list", ["gh"]),
        ("sudo rm -rf /", ["rm"]),
        ("/usr/bin/gh api x", ["gh"]),
        ("ls | grep x; cat a > out.txt", ["ls", "grep", "cat"]),
        ("env -i A=1 xargs -n1 gh", ["gh"]),
        ("git log || echo none & wait", ["git", "echo", "wait"]),
        ("git status\ngh pr list", ["git", "gh"]),
        ('echo "a; b" 2>&1', ["echo"]),
        ("echo a#b; rm x", ["echo", "rm"]),  # # is not taken as a comment
    ],
)
def test_programs(command, found) -> None:
    assert programs(command) == found


@pytest.mark.parametrize(
    ("command", "why"),
    [
        ("echo $(gh pr list)", "substitution"),
        ("echo `gh pr list`", "backticks"),
        ("diff <(ls a) b", "process substitution"),
        ("tee >(gh x)", "process substitution"),
        ("bash -c 'gh pr list'", "bash -c"),
        ("sh -c gh", "sh -c"),
        ("bash -lc 'rm x'", "bash -c"),
        ("eval gh pr list", "eval"),
        ("git status; eval x", "eval"),
        ("(gh pr list)", "subshell"),
        ("$CMD x", "which program"),
        ('echo "unclosed', "quotes"),
        ("", "no program"),
        ("sudo", "no program"),
    ],
)
def test_unreadable_commands_are_refused(command, why) -> None:
    with pytest.raises(CommandError, match=why):
        programs(command)


def test_command_text_shapes() -> None:
    assert command_text({"tool_input": {"command": "gh pr list"}}) == "gh pr list"
    assert command_text({"args": {"command": "ls"}}) == "ls"
    # Codex's argv: its own `bash -lc` wrapper is unwrapped, other argv joined.
    assert command_text({"tool_input": {"command": ["bash", "-lc", "gh pr list"]}}) == (
        "gh pr list"
    )
    assert command_text({"tool_input": {"command": ["gh", "pr", "list"]}}) == "gh pr list"
    assert command_text({"tool_input": {}}) is None
    assert command_text("x") is None
    assert is_shell_tool("claude-code", "Bash")
    assert is_shell_tool("codex", "shell")
    assert is_shell_tool("gemini-cli", "run_shell_command")
    assert not is_shell_tool("claude-code", "Read")


# ---- the hook ------------------------------------------------------------------------


def test_hook_allows_listed_programs() -> None:
    assert check("claude-code", _bash("gh pr list"), None, False)[0]
    assert check("claude-code", _bash("git status && gh pr view"), None, False)[0]
    assert check("claude-code", _bash("FOO=1 gh"), None, False)[0]


@pytest.mark.parametrize(
    "command",
    ["sudo rm -rf /", "echo $(gh pr list)", "bash -c 'gh'", "gh pr list; rm -rf x", ""],
)
def test_hook_blocks_other_programs(command) -> None:
    allowed, reason = check("claude-code", _bash(command), None, False)
    assert not allowed and reason.startswith("Blocked by Bot RBAC")


def test_hook_logs_program_names_never_the_command() -> None:
    secret = "ghp_" + "x" * 20
    check("claude-code", _bash(f"GH_TOKEN={secret} gh pr list"), None, False)
    check("claude-code", _bash(f"curl -H {secret} example.com"), None, False)
    rows = AuditQueue().pending()
    assert [r["decision"] for r in rows] == ["allow", "deny"]
    assert "gh" in rows[0]["reason"] and "cmd/curl" in rows[1]["reason"]
    assert all(secret not in json.dumps(r) for r in rows)
    assert all(r["tool"] == "claude-code/Bash" for r in rows)


def test_shell_tool_itself_must_be_allowed() -> None:
    _role(["cmd/*"])
    assert not check("claude-code", _bash("gh pr list"), None, False)[0]


def test_role_without_cmd_patterns_is_unchanged() -> None:
    _role(["claude-code/Bash"])
    assert check("claude-code", _bash("sudo rm -rf /"), None, False)[0]
    assert check("claude-code", _bash("echo $(whoami)"), None, False)[0]
    assert check("claude-code", "", "Bash", False)[0]
    _role(["claude-code/Read"])
    assert not check("claude-code", _bash("ls"), None, False)[0]


def test_other_agents_shell_tools() -> None:
    _role(["codex/shell", "gemini-cli/run_shell_command", "cmd/git"])
    codex = json.dumps(
        {"tool_name": "shell", "tool_input": {"command": ["bash", "-lc", "git status"]}}
    )
    assert check("codex", codex, None, False)[0]
    bad = json.dumps({"tool_name": "shell", "tool_input": {"command": ["rm", "-rf", "x"]}})
    assert not check("codex", bad, None, False)[0]
    assert not check("Gemini CLI", _bash("gh x", tool="run_shell_command"), None, False)[0]


def test_shell_call_without_a_command_is_blocked_when_programs_are_limited() -> None:
    assert not check("claude-code", "", "Bash", False)[0]

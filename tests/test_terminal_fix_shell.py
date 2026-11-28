"""Regressions: shell commands that hid a program, and MCP names that passed as cmd/ or
as the gateway."""

import json

import pytest

from botrbac_cli import agents, policy
from botrbac_cli.check import check, classify
from botrbac_cli.shellcmd import CommandError, programs
from tests.terminal_helpers import cache_policy


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("BOTRBAC_HOME", str(tmp_path / "botrbac"))
    monkeypatch.delenv(policy.SESSION_ENV, raising=False)
    cache_policy(["claude-code/Bash", "cmd/git", "cmd/gh"], name="Coder")
    return tmp_path


def _bash(command: str) -> str:
    return json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})


# ---- comments, quoting, heredocs -------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "found"),
    [
        # A quote inside a comment opens nothing: the next lines are still read.
        ("git status #'\nrm -rf x\n#'", ["git", "rm"]),
        ("gh pr list # it's fine\ngit status", ["gh", "git"]),
        ("git status;#'\nrm x", ["git", "rm"]),
        ('git log #"\nrm x\n#"', ["git", "rm"]),
        ("git status &&#x\nrm y", ["git", "rm"]),
        # A comment's trailing backslash does not join the next line.
        ("git status # \\\nrm x", ["git", "rm"]),
        # `#` inside a word is not a comment.
        ("echo a#b; rm x", ["echo", "rm"]),
        ("echo ''#x; rm y", ["echo", "rm"]),
        # Ordinary quoting still reads as before.
        ("echo 'a; rm x' \"b; rm y\" c\\;d", ["echo"]),
        ("gh \\\n pr list", ["gh"]),
        ("cat <<< 'x'; rm y", ["cat", "rm"]),
        ("echo ${HOME}; rm x", ["echo", "rm"]),
    ],
)
def test_comments_never_hide_later_lines(command, found) -> None:
    assert programs(command) == found


@pytest.mark.parametrize(
    ("command", "why"),
    [
        ("git log $'\\'' ; rm -rf x #'", r"\$'"),
        ("git log $'a'", r"\$'"),
        ('git log $"a"', r"\$'"),
        ("cat <<EOF\ncat '\nEOF\nrm -rf x\n#'", "heredoc|quotes"),
        ("cat <<EOF\nhello\nEOF\nrm -rf x", "heredoc"),
        ("cat <<-EOF\n\thello\n\tEOF", "heredoc"),
        ('echo "${x:-"a"}"', "inside"),
        ("echo ${x:-'}'}; rm y", "inside"),
        ("git status \\", "backslash"),
    ],
)
def test_unfollowable_quoting_is_refused(command, why) -> None:
    with pytest.raises(CommandError, match=why):
        programs(command)


@pytest.mark.parametrize(
    "command",
    [
        "git status #'\nrm -rf x\n#'",
        "git log $'\\'' ; rm -rf x #'",
        "cat <<EOF\ncat '\nEOF\nrm -rf x\n#'",
        "PATH=./d:$PATH 2 >/dev/null; git --version",
    ],
)
def test_hook_blocks_the_bypasses(command) -> None:
    allowed, reason = check("claude-code", _bash(command), None, False)
    assert not allowed and reason.startswith("Blocked by Bot RBAC")


# ---- file descriptors --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "found"),
    [
        # Spaced from the redirect, the number is the program, as in bash.
        ("PATH=./d:$PATH 2 >/dev/null; git --version", ["2", "git"]),
        ("2 >f rm x", ["2"]),
        ('"2">f rm', ["2"]),
        # Touching it, it is a file descriptor.
        ("2>f rm x", ["rm"]),
        ("git status 2>&1; gh pr list", ["git", "gh"]),
        ("gh; 2>>f rm x", ["gh", "rm"]),
    ],
)
def test_only_an_adjacent_number_is_a_file_descriptor(command, found) -> None:
    assert programs(command) == found


def test_an_escaped_redirect_is_part_of_the_word() -> None:
    with pytest.raises(CommandError, match="which program"):
        programs("2\\>f")  # one word, `2>f`: not a program name botrbac reads


# ---- the cmd/ namespace ------------------------------------------------------------------


def test_a_server_called_cmd_never_maps_into_cmd() -> None:
    assert classify("claude-code", "mcp__cmd__git") == ("cmd-upstream/git", True)
    assert classify("claude-code", "mcp__CMD__rm") == ("cmd-upstream/rm", True)
    assert classify("cmd", "git") == ("cmd-upstream/git", False)
    assert classify("claude-code", "mcp__cmdx__git") == ("cmdx/git", True)
    assert not check("claude-code", json.dumps({"tool_name": "mcp__cmd__git"}), None, False)[0]


# ---- the gateway, by name ------------------------------------------------------------


def _gemini(name: str, context: dict | None = None) -> dict:
    payload = {"hook_event_name": "BeforeTool", "tool_name": name, "tool_input": {}}
    if context is not None:
        payload["mcp_context"] = context
    return payload


def test_gemini_trusts_the_gateway_only_from_mcp_context() -> None:
    named = agents.normalize("gemini", _gemini("mcp_botrbac_github__get_issue",
                                               {"server_name": "botrbac"}))  # fmt: skip
    assert named["tool_name"] == "mcp__botrbac__github__get_issue"
    # A server called botrbac_x, named in mcp_context: an ordinary server.
    other = agents.normalize("gemini", _gemini("mcp_botrbac_x_tool", {"server_name": "botrbac_x"}))
    assert other["tool_name"] == "mcp__botrbac_x__tool"
    assert classify("gemini", other["tool_name"])[1]
    # botrbac__x would read as the gateway's prefix: checked as botrbac-upstream.
    odd = agents.normalize("gemini", _gemini("mcp_botrbac__x_t", {"server_name": "botrbac__x"}))
    assert not odd["tool_name"].startswith("mcp__botrbac__")
    # No mcp_context: a guess of `botrbac` is never trusted; the call is blocked.
    guess = agents.normalize("gemini", _gemini("mcp_botrbac_x_tool"))
    assert "tool_name" not in guess
    assert not check("gemini", json.dumps(_gemini("mcp_botrbac_x_tool")), None, False)[0]
    # Other guesses are checked as ordinary servers, as before.
    assert agents.normalize("gemini", _gemini("mcp_github_x"))["tool_name"] == "mcp__github__x"


def _cursor(**fields) -> dict:
    return {"hook_event_name": "beforeMCPExecution", "tool_name": "github__get_issue",
            "tool_input": "{}", **fields}  # fmt: skip


@pytest.mark.parametrize(
    "fields",
    [
        {"command": "botrbac gateway"},
        {"command": "/usr/local/bin/botrbac gateway --agent cursor"},
        {"command": "python -m botrbac_cli gateway"},
    ],
)
def test_cursor_gateway_by_its_command(fields) -> None:
    name = agents.normalize("cursor", _cursor(**fields))["tool_name"]
    assert name == "mcp__botrbac__github__get_issue"


@pytest.mark.parametrize(
    "fields",
    [
        {"command": "botrbac serve"},
        {"command": "npx botrbac"},
        {"command": "/opt/botrbac"},
        {"url": "https://botrbac/mcp"},
        {"server_name": "botrbac"},
        {"server_name": "BotRBAC"},
        {"server_name": "botrbac__x"},
    ],
)
def test_cursor_server_merely_named_botrbac_is_not_the_gateway(fields) -> None:
    name = agents.normalize("cursor", _cursor(**fields))["tool_name"]
    assert name.startswith("mcp__botrbac-upstream__")
    tool_id, bypass = classify("cursor", name)
    assert tool_id == "botrbac-upstream/github__get_issue" and bypass

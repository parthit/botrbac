"""What a blocked agent is told: each kind of block names the fix that would work."""

import json

import pytest

from botrbac_cli import policy, session
from botrbac_cli.check import check
from botrbac_cli.main import main
from botrbac_cli.queue import AuditQueue
from scoped_drive_mcp.terminal import present
from tests.terminal_helpers import cache_policy

ROLES = [
    {"id": "dev", "name": "Dev", "patterns": ["claude-code/*", "cmd/git", "cmd/ls"]},
    {"id": "reviewer", "name": "Reviewer", "patterns": ["claude-code/Read", "claude-code/Bash"]},
    {"id": "gitonly", "name": "Git only", "patterns": ["claude-code/*", "cmd/git"]},
    {"id": "full", "name": "Full access", "patterns": ["*"]},
]


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("BOTRBAC_HOME", str(tmp_path / "botrbac"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    monkeypatch.delenv(policy.SESSION_ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    cache_policy(ROLES[0]["patterns"], name="Dev", role_id="dev", roles=ROLES)
    return tmp_path


def _call(tool: str, command: str | None = None, block_unguarded: bool = False) -> str:
    payload = {"tool_name": tool, "tool_input": {"command": command} if command else {}}
    allowed, text = check("claude-code", json.dumps(payload), None, block_unguarded)
    assert not allowed and text.startswith("Blocked by Bot RBAC: ")
    return text


def _enter(monkeypatch, role: str) -> None:
    monkeypatch.setenv(policy.SESSION_ENV, session.start(role, "claude")["id"])


def test_the_computers_role_names_the_pattern_and_the_page() -> None:
    text = _call("mcp__slack__post")
    assert "slack/post is not in role 'Dev'" in text
    assert "add slack/post to this computer's role at https://rbac.self-hosted.test/" in text
    assert "--role" not in text


def test_a_refused_program_is_named_with_what_the_shell_may_run() -> None:
    text = _call("Bash", "git log | head -5")
    assert "running cmd/head is not in role 'Dev'" in text
    assert "The shell here runs only: git, ls." in text
    # The pattern to ask for is the real one, not a placeholder.
    assert "add cmd/head to this computer's role" in text and "<program>" not in text


@pytest.mark.parametrize(
    "command", ["for f in a b; do ls $f; done", "ls $(git rev-parse HEAD)", "git commit <<EOF"]
)
def test_an_unreadable_command_is_not_sent_to_the_person(command) -> None:
    text = _call("Bash", command)
    assert "no role change is needed" in text and "The shell here runs only: git, ls." in text
    assert "ask them" not in text and "terminal/roles" not in text


def test_a_narrowed_run_blames_the_role_that_refused(monkeypatch) -> None:
    _enter(monkeypatch, "Reviewer")
    text = _call("Edit")
    assert "claude-code/Edit is not in role 'Reviewer', a role this run was narrowed to" in text
    assert "wider --role" in text and "add claude-code/Edit to 'Reviewer'" in text
    assert "this computer's role" not in text  # the computer's role already allows it

    # Asking for a wider role inside changes nothing, and the message still names Reviewer.
    _enter(monkeypatch, "Full access")
    assert "is not in role 'Reviewer', a role this run was narrowed to" in _call("Edit")
    row = AuditQueue().pending()[-1]
    assert row["reason"] == "not in role 'Reviewer'" and row["role"] == "Full access"
    # What the computer's role refuses is still the computer's role's to fix.
    text = _call("mcp__slack__post")
    assert "slack/post is not in role 'Dev'" in text and "this computer's role" in text


def test_a_narrowed_runs_programs_blame_the_role_that_refused(monkeypatch) -> None:
    _enter(monkeypatch, "Git only")
    assert check(
        "claude-code",
        json.dumps({"tool_name": "Bash", "tool_input": {"command": "git status"}}),
        None,
        False,
    )[0]
    text = _call("Bash", "ls")
    assert "running cmd/ls is not in role 'Git only', a role this run was narrowed to" in text
    assert "The shell here runs only: git." in text
    text = _call("Bash", "curl x")  # refused by both: the outermost one is named
    assert "running cmd/curl is not in role 'Dev'" in text and "this computer's role" in text


def test_reasons_still_read_by_the_website(monkeypatch) -> None:
    """Activity builds its "To allow it" link from the row's reason: same shape as before."""
    _call("Bash", "git log | head -5")
    _enter(monkeypatch, "Reviewer")
    _call("Edit")
    reasons = [r["reason"] for r in AuditQueue().pending() if r["decision"] == "deny"]
    assert reasons == ["running cmd/head is not in role 'Dev'", "not in role 'Reviewer'"]
    assert all(present.blocked_because(reason) for reason in reasons)


def test_a_session_from_an_older_botrbac_still_decides(monkeypatch) -> None:
    from botrbac_cli import state

    started = session.start("Reviewer", "claude")
    old = {k: v for k, v in started.items() if k != "role_names"}
    state.write_json(f"sessions/{old['id']}.json", old, private=True)
    monkeypatch.setenv(policy.SESSION_ENV, old["id"])
    assert "is not in role 'Reviewer', a role this run" in _call("Edit")
    assert policy.Enforcer().decide("claude-code/Read").allowed
    assert session.start("Full access", "claude")["role_names"] == ["Reviewer", "Full access"]


def test_no_login_or_a_revoked_session_does_not_ask_for_a_wider_role(monkeypatch) -> None:
    started = session.start("Reviewer", "claude")
    monkeypatch.setenv(policy.SESSION_ENV, started["id"])
    cache_policy(ROLES[0]["patterns"], name="Dev", roles=ROLES, revoked=[started["id"]])
    text = _call("Read")
    assert "this session was revoked on the website. Every tool is blocked" in text
    assert "do not ask for a wider one" in text and "add " not in text

    monkeypatch.setenv("BOTRBAC_HOME", str(policy.state.home() / "nobody"))
    text = _call("Bash", "ls")
    assert text.startswith("Blocked by Bot RBAC: not logged in: run botrbac login. Every tool")
    assert "is not logged in" not in text and "terminal/roles" not in text


def test_an_unguarded_server_is_the_persons_to_wrap() -> None:
    text = _call("mcp__slack__post", block_unguarded=True)
    assert "does not go through the botrbac gateway" in text
    assert "ask the person to run botrbac wrap" in text and "(run: botrbac wrap)" not in text
    assert AuditQueue().pending()[-1]["reason"].endswith("(run: botrbac wrap)")  # as before


def test_run_says_a_nested_session_only_narrows(capfd) -> None:
    assert main(["run", "--role", "Reviewer", "--", "true"]) == 0
    assert "A run only narrows" not in capfd.readouterr().err


def test_nested_run_and_roles_show_the_narrowing(monkeypatch, capsys) -> None:
    _enter(monkeypatch, "Reviewer")
    session.run("Full access", ["true"], None, None)
    err = capsys.readouterr().err
    assert "as 'Full access', inside 'Reviewer' within this terminal's role 'Dev'" in err
    assert "A run only narrows: a tool must be in all of them." in err

    monkeypatch.setattr(policy, "refresh", lambda api: None)
    assert main(["roles"]) == 0
    assert "This run is narrowed to: Reviewer\n" in capsys.readouterr().out

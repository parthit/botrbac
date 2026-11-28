"""Terminal: hook provenance and intent (ids, prompts, results, description, git)."""

import hashlib
import io
import json
import subprocess
import sys
import uuid

import pytest

from botrbac_cli import policy, provenance, sealing, state
from botrbac_cli.check import check
from botrbac_cli.hooks import EVENTS, install_claude_code, remove_claude_code
from botrbac_cli.main import main
from botrbac_cli.queue import AuditQueue
from scoped_drive_mcp.store import MemoryStore
from scoped_drive_mcp.terminal.feature import TerminalFeature
from scoped_drive_mcp.terminal.ingest import TerminalActivity, clean_row
from tests import dash
from tests.terminal_helpers import bearer, cache_policy, connect_terminal, terminal_app

NOW = 1_800_000_000.0
KEY = sealing.key_from_secret("test secret")
PUBLIC = sealing.public_key_text(KEY)
SECRET = "ghp_" + "p" * 30


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("BOTRBAC_HOME", str(tmp_path / "botrbac"))
    monkeypatch.delenv(policy.SESSION_ENV, raising=False)
    cache_policy(["claude-code/*"], name="Full")
    return tmp_path


def _userinfo(user: str, secret: str) -> str:
    """`user:secret@`, built at run time so secret scanners do not read a test value
    as a leaked credential."""
    return user + ":" + secret + "@"


def _recording(key: str = PUBLIC) -> None:
    data = state.read_json("policy.json")
    data["policy"]["command_key"] = key
    state.write_json("policy.json", data)


def _hook(event: str, **payload) -> str:
    return json.dumps({"hook_event_name": event, **payload})


def _run_hook(monkeypatch, capsys, text: str) -> tuple[int, str, str]:
    monkeypatch.setattr(sys, "stdin", io.StringIO(text))
    code = main(["check", "--agent", "claude-code"])
    out = capsys.readouterr()
    return code, out.out, out.err


CLAUDE = {
    "session_id": "abc-123",
    "prompt_id": "p-1",
    "tool_use_id": "toolu_01",
    "agent_id": "agent-7",
    "agent_type": "Explore",
    "parent_agent_id": "agent-1",
    "permission_mode": "acceptEdits",
    "cwd": "/home/me/proj",
}


# ---- field extraction ---------------------------------------------------------------


def test_fields_from_claude_codex_and_cursor_payloads() -> None:
    assert provenance.hook_fields(CLAUDE) == {
        "agent_session_id": "abc-123",
        "prompt_id": "p-1",
        "tool_use_id": "toolu_01",
        "agent_id": "agent-7",
        "agent_type": "Explore",
        "parent_agent_id": "agent-1",
        "permission_mode": "acceptEdits",
        "cwd": "/home/me/proj",
    }
    codex = {"session_id": "s-9", "turn_id": "turn-4", "cwd": "/w"}
    assert provenance.hook_fields(codex) == {
        "agent_session_id": "s-9",
        "prompt_id": "turn-4",
        "cwd": "/w",
    }
    cursor = {
        "conversation_id": "conv-1",
        "generation_id": "gen-2",
        "workspace_roots": ["/Users/me/app"],
    }
    assert provenance.hook_fields(cursor) == {
        "agent_session_id": "conv-1",
        "prompt_id": "gen-2",
        "cwd": "/Users/me/app",
    }


def test_fields_are_parsed_defensively() -> None:
    junk = {
        "session_id": "has spaces",
        "prompt_id": "x" * 129,
        "tool_use_id": ["toolu"],
        "agent_id": True,
        "permission_mode": "a" * 33,
        "cwd": "relative/path",
    }
    assert provenance.hook_fields(junk) == {}
    assert provenance.hook_fields("not a dict") == {}
    assert provenance.hook_fields({"cwd": "/a\x00b\nc"})["cwd"] == "/abc"
    assert provenance.hook_fields({"cwd": "C:\\Users\\me"})["cwd"] == "C:\\Users\\me"


# ---- PreToolUse rows ----------------------------------------------------------------


def test_pre_tool_row_keeps_ids_and_seals_the_description() -> None:
    _recording()
    command = f"GH_TOKEN={SECRET} " + "echo hi; " * 1200  # longer than the 8,000 cut
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command, "description": f"List PRs using {SECRET}"},
        **CLAUDE,
    }
    assert check("claude-code", json.dumps(payload), None, False)[0]
    (row,) = AuditQueue().pending()
    assert row["agent_session_id"] == "abc-123" and row["tool_use_id"] == "toolu_01"
    assert row["cwd"] == "/home/me/proj" and row["permission_mode"] == "acceptEdits"
    assert SECRET not in json.dumps(row)
    assert sealing.open_sealed(KEY, f"{row['event_id']}:description", row["description"]) == (
        f"List PRs using {SECRET}"
    )
    with pytest.raises(sealing.SealError):  # bound to its field
        sealing.open_sealed(KEY, row["event_id"], row["description"])
    # The digest covers the whole command, not the cut one that was sealed.
    data = command.encode()
    assert row["input_digest"] == "sha256:" + hashlib.sha256(data).hexdigest()
    assert row["input_size"] == len(data) > sealing.MAX_CHARS


def test_without_recording_no_description_or_digest() -> None:
    payload = {"tool_name": "Bash", "tool_input": {"command": "ls", "description": "List"}}
    assert check("claude-code", json.dumps(payload), None, False)[0]
    (row,) = AuditQueue().pending()
    for name in ("command", "description", "input_digest", "input_size"):
        assert name not in row


def test_queue_add_seals_extra_fields() -> None:
    _recording()
    row = AuditQueue().add(sealed={"task": "fix the build", "description": None}, decision="x")
    assert "description" not in row
    assert sealing.open_sealed(KEY, f"{row['event_id']}:task", row["task"]) == "fix the build"


# ---- prompt and result rows ---------------------------------------------------------


def test_prompt_row(monkeypatch, capsys) -> None:
    _recording()
    text = _hook("UserPromptSubmit", prompt=f"deploy with {SECRET}", **CLAUDE)
    code, out, _err = _run_hook(monkeypatch, capsys, text)
    assert code == 0 and out == ""
    (row,) = AuditQueue().pending()
    assert row["decision"] == "prompt" and row["tool"] == "" and row["prompt_id"] == "p-1"
    assert row["agent_session_id"] == "abc-123" and SECRET not in json.dumps(row)
    assert sealing.open_sealed(KEY, row["event_id"], row["command"]) == f"deploy with {SECRET}"
    clean = clean_row(row, NOW, KEY)
    assert clean["decision"] == "prompt" and clean["tool"] == "" and clean["prompt_id"] == "p-1"
    assert clean["command"] == row["command"]


def test_prompt_and_result_hooks_never_block(monkeypatch, capsys) -> None:
    def boom(*_a, **_k):
        raise OSError("disk")

    monkeypatch.setattr(AuditQueue, "add", boom)
    for event in ("UserPromptSubmit", "PostToolUse", "PostToolUseFailure"):
        code, out, _err = _run_hook(monkeypatch, capsys, _hook(event, tool_name="Bash"))
        assert code == 0 and out == ""
    # PreToolUse still fails closed.
    code, _out, err = _run_hook(monkeypatch, capsys, "not json")
    assert code == 2 and "could not read" in err


def test_result_rows(monkeypatch, capsys) -> None:
    ok = _hook(
        "PostToolUse",
        tool_name="Bash",
        tool_input={"command": "ls"},
        tool_response={"stdout": f"secret {SECRET}", "stderr": "", "exit_code": 0},
        duration_ms=42,
        **CLAUDE,
    )
    failed = _hook(
        "PostToolUseFailure", tool_name="Read", error="file not found", tool_use_id="toolu_02"
    )
    nonzero = _hook("PostToolUse", tool_name="Bash", tool_response={"exitCode": 3})
    gateway = _hook("PostToolUse", tool_name="mcp__botrbac__github__get_issue")
    for text in (ok, failed, nonzero, gateway):
        code, out, _err = _run_hook(monkeypatch, capsys, text)
        assert code == 0 and out == ""
    rows = AuditQueue().pending()
    assert len(rows) == 3  # the gateway records its own tools
    first, second, third = rows
    assert first["decision"] == "result" and first["tool"] == "claude-code/Bash"
    assert first["outcome"] == "ok" and first["exit_code"] == 0 and first["duration_ms"] == 42
    assert first["tool_use_id"] == "toolu_01" and first["result_size"] > 0
    assert SECRET not in json.dumps(rows) and "file not found" not in json.dumps(rows)
    assert second["outcome"] == "error" and second["tool"] == "claude-code/Read"
    assert second["result_size"] == len("file not found")
    assert third["outcome"] == "error" and third["exit_code"] == 3
    clean = clean_row(first, NOW)
    assert clean["outcome"] == "ok" and clean["exit_code"] == 0 and clean["tool_use_id"]


def test_server_validates_prompt_and_result_rows() -> None:
    base = {"event_id": uuid.uuid4().hex, "ts": NOW, "agent": "claude-code"}
    assert clean_row({**base, "decision": "prompt", "tool": "x/y"}, NOW)["tool"] == ""
    assert clean_row({**base, "decision": "result", "tool": ""}, NOW) is None
    row = clean_row(
        {
            **base,
            "decision": "result",
            "tool": "claude-code/Bash",
            "outcome": "maybe",
            "exit_code": True,
            "duration_ms": -5,
            "result_size": "12",
        },
        NOW,
    )
    for name in ("outcome", "exit_code", "duration_ms", "result_size"):
        assert name not in row
    # An old CLI's row is accepted as it was.
    old = {**base, "decision": "allow", "tool": "claude-code/Bash", "reason": "ok"}
    assert set(clean_row(old, NOW)) == {
        "event_id", "ts", "decision", "tool", "agent", "reason", "role", "via",
    }  # fmt: skip


# ---- the server and sealed fields ---------------------------------------------------


def _row(**over):
    row = {
        "event_id": uuid.uuid4().hex,
        "ts": NOW,
        "agent": "claude-code",
        "tool": "claude-code/Bash",
        "decision": "allow",
        "reason": "ok",
        "role": "full",
    }
    row.update(over)
    return row


def test_sealed_description_round_trip_through_clean_row() -> None:
    row = _row()
    row["description"] = sealing.seal(PUBLIC, f"{row['event_id']}:description", "List files")
    row["input_digest"] = "sha256:" + "a" * 64
    row["input_size"] = 12
    kept = clean_row(row, NOW, KEY)
    assert kept["description"] == row["description"]
    assert kept["input_digest"] == row["input_digest"] and kept["input_size"] == 12
    (opened,) = TerminalFeature(MemoryStore(), signing_secret="test secret").open_commands([kept])
    assert opened["description"] == "List files" and not opened["description_unreadable"]
    off = clean_row(row, NOW)  # recording off: none of it
    assert "description" not in off and "input_digest" not in off and "input_size" not in off


def test_server_drops_a_description_sealed_with_the_wrong_aad() -> None:
    row = _row()
    eid = row["event_id"]
    for wrong in (eid, f"{eid}:task", f"{uuid.uuid4().hex}:description"):
        row["description"] = sealing.seal(PUBLIC, wrong, "moved")
        assert "description" not in clean_row(row, NOW, KEY)
    row["description"] = "plain text"
    assert "description" not in clean_row(row, NOW, KEY)


def test_server_validates_context_fields() -> None:
    good = _row(
        cwd="/home/me/proj",
        repo="github.com/o/r",
        branch="feature/x",
        head="0123abc",
        agent_session_id="abc-123",
        permission_mode="plan",
    )
    kept = clean_row(good, NOW)
    for name in ("cwd", "repo", "branch", "head", "agent_session_id", "permission_mode"):
        assert kept[name] == good[name]
    bad = _row(
        cwd="relative",
        repo="https://" + _userinfo("user", "tok") + "github.com/o/r",
        branch="a b;c",
        head="xyz",
        agent_session_id="no spaces allowed",
        permission_mode="x" * 40,
    )
    kept = clean_row(bad, NOW)
    for name in ("cwd", "repo", "branch", "head", "agent_session_id", "permission_mode"):
        assert name not in kept
    assert clean_row(_row(cwd="/a\x1b[31m" + "b" * 600), NOW)["cwd"] == "/a[31m" + "b" * 506


# ---- digest -------------------------------------------------------------------------


def test_input_digest() -> None:
    got = provenance.input_digest("héllo")
    data = "héllo".encode()
    assert got == {"input_digest": "sha256:" + hashlib.sha256(data).hexdigest(), "input_size": 6}


# ---- git ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://" + _userinfo("user", "tok") + "github.com/o/r.git", "github.com/o/r"),
        ("https://" + _userinfo("x-access-token", "ghs_abc") + "github.com/o/r", "github.com/o/r"),
        ("git@github.com:o/r.git", "github.com/o/r"),
        ("ssh://git@gitlab.example.com:2222/group/sub/r.git", "gitlab.example.com/group/sub/r"),
        ("https://GitHub.com/o/r.git?token=abc#frag", "github.com/o/r"),
        ("/srv/git/r.git", ""),
        ("file:///srv/git/r.git", ""),
        ("", ""),
        (None, ""),
        ("https://github.com/o/r with space", ""),
    ],
)
def test_sanitize_remote(url, expected) -> None:
    assert provenance.sanitize_remote(url) == expected


def _git(cwd, *args):
    subprocess.run(  # noqa: S603
        ["git", "-C", str(cwd), *args],  # noqa: S607
        check=True,
        capture_output=True,
    )


def test_git_context(tmp_path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    try:
        _git(repo, "init", "-q", "-b", "main")
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("git not available")
    _git(
        repo,
        "-c",
        "user.email=a@b",
        "-c",
        "user.name=a",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "x",
    )
    _git(
        repo,
        "remote",
        "add",
        "origin",
        "https://" + _userinfo("me", "hunter2") + "github.com/o/r.git",
    )
    found = provenance.git_context(str(repo))
    assert found["repo"] == "github.com/o/r" and found["branch"] == "main"
    assert len(found["head"]) == 40
    assert "hunter2" not in (state.home() / provenance.GIT_CACHE).read_text()
    assert provenance.git_context(str(tmp_path)) == {}  # not a checkout
    assert provenance.git_context(str(tmp_path / "missing")) == {}
    assert provenance.git_context(None) == {}


def test_git_failure_never_fails_the_check(monkeypatch) -> None:
    def boom(*_a, **_k):
        raise RuntimeError("git exploded")

    monkeypatch.setattr(provenance, "_read_git", boom)
    payload = {"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": "/"}
    assert check("claude-code", json.dumps(payload), None, False)[0]
    (row,) = AuditQueue().pending()
    assert row["cwd"] == "/" and "repo" not in row


# ---- hooks install / remove ---------------------------------------------------------


def test_hooks_install_and_remove_all_four_events(home) -> None:
    settings = home / "proj" / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True)
    mine = {"matcher": "Bash", "hooks": [{"type": "command", "command": "mine"}]}
    settings.write_text(json.dumps({"hooks": {"PostToolUse": [mine]}}))
    first = install_claude_code(settings)
    assert first["changed"] and first["backup"]
    assert not install_claude_code(settings)["changed"]  # idempotent
    hooks = json.loads(settings.read_text())["hooks"]
    assert set(hooks) == set(EVENTS) == {
        "PreToolUse", "UserPromptSubmit", "PostToolUse", "PostToolUseFailure",
    }  # fmt: skip
    for event in EVENTS:
        ours = [e for e in hooks[event] if "check --agent claude-code" in json.dumps(e)]
        assert len(ours) == 1
    assert "matcher" not in hooks["UserPromptSubmit"][0]
    assert hooks["PostToolUse"][0] == mine
    removed = remove_claude_code(settings)
    assert removed["changed"] and removed["backup"]
    assert json.loads(settings.read_text()) == {"hooks": {"PostToolUse": [mine]}}
    assert not remove_claude_code(settings)["changed"]


# ---- the website --------------------------------------------------------------------


def test_activity_page_filters_and_export(world, memstore, oauth) -> None:
    app = terminal_app(world, memstore, oauth)
    c = dash.client(app)
    dash.login(c)
    issued = connect_terminal(c, role_id="full")
    token = dash.csrf(c, "/terminal/activity")
    c.post("/terminal/activity/record", data={"csrf": token, "record": "1"})
    public = c.get("/api/terminal/policy", headers=bearer(issued)).json()["command_key"]

    prompt = _row(decision="prompt", tool="", prompt_id="p-1", agent_session_id="as-1")
    prompt["command"] = sealing.seal(public, prompt["event_id"], "please list the files")
    call = _row(
        prompt_id="p-1",
        agent_session_id="as-1",
        tool_use_id="toolu_1",
        cwd="/home/me/proj",
        repo="github.com/o/r",
        branch="main",
        head="0123456789abcdef",
    )
    call["description"] = sealing.seal(public, f"{call['event_id']}:description", "List files")
    result = _row(
        decision="result", tool_use_id="toolu_1", outcome="error", exit_code=2, duration_ms=7
    )
    other = _row(prompt_id="p-2", agent_session_id="as-2")
    # A finished call with no exit code (Claude Code's PostToolUse) shows none.
    quiet = _row(decision="result", tool_use_id="toolu_2", outcome="ok", duration_ms=85)
    rows = [prompt, call, result, other, quiet]
    sent = c.post("/api/terminal/audit", json={"rows": rows}, headers=bearer(issued))
    assert sent.json()["accepted"] == 5

    page = c.get("/terminal/activity").text
    assert "please list the files" in page and "List files" in page
    assert "agent&#39;s claim, not checked" in page or "agent's claim, not checked" in page
    assert "github.com/o/r@0123456789" in page and "/home/me/proj" in page
    assert "exit 2" in page and "failed" in page
    assert "85 ms" in page and "exit ·" not in page and "exit  ·" not in page

    only = c.get("/terminal/activity", params={"prompt_id": "p-1"}).text
    assert "please list the files" in only and 'id="activity-scope"' in only
    assert only.count('data-label="When"') == 2
    by_session = c.get("/terminal/activity", params={"agent_session_id": "as-2"}).text
    assert by_session.count('data-label="When"') == 1

    csv_text = c.get("/terminal/activity/export?format=csv").text
    header = csv_text.splitlines()[0].split(",")
    for name in (
        "agent_session_id", "prompt_id", "tool_use_id", "agent_id", "agent_type",
        "parent_agent_id", "permission_mode", "cwd", "repo", "branch", "head",
        "description", "task", "input_digest", "input_size", "outcome", "exit_code",
        "duration_ms", "result_size",
    ):  # fmt: skip
        assert name in header
    assert "List files" in csv_text
    lines = c.get("/terminal/activity/export?format=jsonl&prompt_id=p-1").text.splitlines()
    assert len(lines) == 2 and {json.loads(x)["prompt_id"] for x in lines} == {"p-1"}


def test_session_task_is_sealed_and_shown(world, memstore, oauth) -> None:
    from botrbac_cli import session

    _recording()
    cache_policy(
        ["claude-code/*"], name="Full", roles=[{"id": "r", "name": "Full", "patterns": []}]
    )
    _recording()
    started = session.start("Full", "claude", None, ["claude"], task=f"fix CI with {SECRET}")
    (row,) = AuditQueue().pending()
    assert row["session_id"] == started["id"] and SECRET not in json.dumps(row)
    assert SECRET not in json.dumps(state.read_json(f"sessions/{started['id']}.json"))
    opened = sealing.open_sealed(KEY, f"{row['event_id']}:task", row["task"])
    assert opened == f"fix CI with {SECRET}"
    kept = clean_row(row, NOW, KEY)
    assert kept["task"] == row["task"]

    log = TerminalActivity(MemoryStore(), clock=lambda: NOW)
    log.add("a@x.com", "t_1", "laptop", [row], KEY)
    feature = TerminalFeature(MemoryStore(), signing_secret="test secret")
    tree = feature.open_tree(log.session("a@x.com", started["id"]))
    assert tree["start"]["task"] == f"fix CI with {SECRET}"


def test_exit_code_from_claude_failure_text() -> None:
    from botrbac_cli import provenance

    out = provenance.result_fields(
        {"error": "Exit code 2\nls: cannot access '/nope': No such file or directory"}, True
    )
    assert out["exit_code"] == 2 and out["outcome"] == "error"
    assert "nope" not in str(out)
    assert "exit_code" not in provenance.result_fields({"error": "Timed out"}, True)


def test_log_shows_prompt_and_result_rows(tmp_path, monkeypatch, capsys) -> None:
    from botrbac_cli.main import main
    from botrbac_cli.queue import AuditQueue

    monkeypatch.setenv("BOTRBAC_HOME", str(tmp_path))
    q = AuditQueue()
    q.add(decision="prompt", tool="", prompt_id="prompt-1234abcd", agent="claude-code")
    q.add(
        decision="result",
        tool="claude-code/Bash",
        outcome="error",
        exit_code=2,
        duration_ms=11,
        agent="claude-code",
    )
    assert main(["log"]) == 0
    out = capsys.readouterr().out
    assert "prompt 1234abcd" in out and "as None" not in out
    assert "claude-code/Bash  error, exit 2, 11 ms" in out


def test_http_status_is_not_an_exit_code() -> None:
    from botrbac_cli import provenance

    out = provenance.result_fields({"tool_response": {"status_code": 200, "body": "x"}}, False)
    assert out["outcome"] == "ok" and "exit_code" not in out

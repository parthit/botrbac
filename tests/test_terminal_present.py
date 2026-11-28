"""The Activity page in plain words (terminal/present.py)."""

from scoped_drive_mcp.terminal import present


def test_actions_read_as_sentences() -> None:
    assert present.action({"tool": "claude-code/Bash", "command": "ls"})["sentence"] == (
        "Ran a command"
    )
    wrote = present.action(
        {"tool": "claude-code/Write", "command": '{"file_path": "/p/greet.py", "content": "x"}'}
    )
    assert wrote["sentence"] == "Wrote the file greet.py" and wrote["shown"] == "/p/greet.py"
    assert present.action({"tool": "claude-code/Write"})["sentence"] == "Wrote a file"
    assert present.action({"tool": "github/create_issue"})["sentence"] == (
        "Used create issue on github"
    )
    assert present.action({"tool": "claude-code/Agent"})["sentence"] == "Started a helper agent"
    assert present.agent_name("claude-code") == "Claude Code"


def test_blocked_reasons_say_what_to_do() -> None:
    why = present.blocked_because("running cmd/curl is not in role Coding limited shell")
    assert why["text"] == "The role “Coding limited shell” doesn't allow the program curl."
    assert why["role_fix"] and "cmd/curl" in why["fix"]
    assert present.blocked_because("not in role Reader")["text"].startswith("The role “Reader”")
    assert not present.blocked_because("protected file")["role_fix"]
    weird = present.blocked_because("botrbac does not run commands that use $(…)")
    assert "couldn't safely read" in weird["text"]


def test_stories_group_by_prompt_and_fold_results() -> None:
    rows = [  # newest first, as stored
        {"decision": "result", "tool": "claude-code/Bash", "tool_use_id": "t2",
         "prompt_id": "p1", "outcome": "error", "exit_code": 2, "duration_ms": 7, "ts": 5},
        {"decision": "allow", "tool": "claude-code/Bash", "tool_use_id": "t2", "prompt_id": "p1",
         "command": "ls /nope", "agent": "claude-code", "terminal": "laptop", "ts": 4},
        {"decision": "deny", "tool": "claude-code/Bash", "tool_use_id": "t1", "prompt_id": "p1",
         "reason": "running cmd/curl is not in role R", "command": "curl x", "ts": 3},
        {"decision": "prompt", "tool": "", "prompt_id": "p1", "command": "do it", "ts": 2},
        {"decision": "allow", "tool": "github/get_issue", "ts": 1},
    ]  # fmt: skip
    first, second = present.stories(rows)
    assert first["kind"] == "prompt" and first["head"]["command"] == "do it"
    assert first["agent"] == "Claude Code" and first["terminal"] == "laptop"
    assert [s["tool_use_id"] for s in first["steps"]] == ["t1", "t2"]  # in the order it happened
    assert first["blocked"] == 1 and first["failed"] == 1
    assert first["steps"][1]["outcome"] == "Failed (exit code 2, 7 ms)"
    assert first["steps"][0]["blocked"]["role_fix"]
    assert first["steps"][0]["action"]["sentence"] == "Tried to run a command"
    assert second["kind"] == "single" and second["steps"][0]["action"]["sentence"] == (
        "Used get issue on github"
    )


def test_outcome_words() -> None:
    assert present.outcome({"outcome": "ok", "duration_ms": 89}) == "Finished in 89 ms"
    assert present.outcome({"outcome": "ok", "duration_ms": 5600}) == "Finished in 5.6 s"
    assert present.outcome({"outcome": "error"}) == "Failed"
    assert present.outcome(None) == ""


def test_multi_program_block_and_quoted_role() -> None:
    why = present.blocked_because("running cmd/curl, cmd/wget is not in role 'Coding, limited'")
    assert why["text"] == "The role “Coding, limited” doesn't allow the programs curl, wget."
    assert why["add"] == ["cmd/curl", "cmd/wget"] and why["role"] == "Coding, limited"


def test_fix_link_goes_straight_to_the_role_with_the_pattern() -> None:
    from types import SimpleNamespace

    mine = SimpleNamespace(id="r_1", builtin=False)
    builtin = SimpleNamespace(id="read-only", builtin=True)
    roles = {"Mine": mine, "Read-only": builtin}
    why = present.blocked_because("running cmd/curl is not in role Mine")
    assert present.fix_link(why, "claude-code/Bash", roles) == "/terminal/roles/r_1?add=cmd/curl"
    tool = present.blocked_because("not in role 'Read-only'")
    assert present.fix_link(tool, "claude-code/Write", roles) == (
        "/terminal/roles/new?from=read-only&add=claude-code/Write"
    )
    gone = present.blocked_because("not in role Deleted")
    assert present.fix_link(gone, "x/y", roles) == "/terminal/roles"


def test_role_summary_in_words() -> None:
    lines = present.role_summary(
        ["claude-code/*", "claude-code/Read", "claude-code/Grep", "github/get_*",
         "*/read*", "cmd/git", "cmd/ls", "notion/search"]
    )  # fmt: skip
    assert lines == [
        "All of Claude Code's tools",
        "Claude Code: Read, Grep",
        "github tools starting with “get_”",
        "Any server's tools starting with “read”",
        "notion: search",
        "Shell programs: git, ls",
    ]


def test_tools_in_rows_include_refused_programs() -> None:
    rows = [
        {"decision": "allow", "tool": "claude-code/Bash"},
        {"decision": "deny", "tool": "claude-code/Bash",
         "reason": "running cmd/curl, cmd/wget is not in role R"},
        {"decision": "prompt", "tool": ""},
    ]  # fmt: skip
    assert present.tools_in(rows) == ["claude-code/Bash", "cmd/curl", "cmd/wget"]

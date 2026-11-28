"""Terminal: files an agent may not change whatever its role, and spotting a missing hook."""

import json
import time

import pytest

from botrbac_cli import policy, state
from botrbac_cli.check import check
from botrbac_cli.hooks import claude_code_hook_status, hook_report, install_claude_code
from botrbac_cli.main import main
from botrbac_cli.protect import refusal
from botrbac_cli.queue import AuditQueue
from tests import dash
from tests.conftest import OWNER_EMAIL
from tests.terminal_helpers import FakeApi, bearer, connect_terminal, stub_upstream, terminal_app


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    monkeypatch.setenv("BOTRBAC_HOME", str(tmp_path / "home" / ".config" / "botrbac"))
    monkeypatch.delenv(policy.SESSION_ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    # Full access, so only the protection can refuse.
    state.write_json(
        "policy.json",
        {
            "policy": {
                "role": {"id": "full", "name": "Full access", "patterns": ["*"]},
                "roles": [],
                "revoked_sessions": [],
            },
            "fetched_at": time.time(),
        },
    )
    return tmp_path


def _call(tool: str, **tool_input) -> str:
    return json.dumps({"tool_name": tool, "tool_input": tool_input})


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("Edit", {"file_path": "~/.claude/settings.json", "old_string": "a", "new_string": "b"}),
        ("Write", {"file_path": ".claude/settings.local.json", "content": "{}"}),
        ("Write", {"file_path": "/x/proj/.claude/settings.json", "content": "{}"}),
        ("Edit", {"file_path": "$HOME/.claude.json", "old_string": "a", "new_string": "b"}),
        ("Bash", {"command": "sed -i 's/botrbac//' ~/.claude/settings.json"}),
        ("Bash", {"command": "jq 'del(.hooks)' $HOME/.claude/settings.json > /tmp/x"}),
        ("Bash", {"command": "rm -rf ~/.config/botrbac"}),
        ("Bash", {"command": "echo '{}' > ~/.config/botrbac/policy.json"}),
        ("Bash", {"command": "cat ~/.config/botrbac/credentials.json"}),
        ("Read", {"file_path": "~/.config/botrbac/credentials.json"}),
        ("mcp__fs__write_file", {"path": "~/.claude/settings.json", "content": "{}"}),
        # Switching the hook off another way.
        ("Bash", {"command": "botrbac hooks remove claude-code --user"}),
        ("Bash", {"command": "echo '{\"disableAllHooks\": true}' > x.json"}),
    ],
)
def test_protected_files_are_refused_even_with_full_access(tool, tool_input) -> None:
    allowed, reason = check("claude-code", _call(tool, **tool_input), None, False)
    assert not allowed and "Blocked by Bot RBAC" in reason
    assert AuditQueue().pending()[-1]["reason"] == "protected file"


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("Read", {"file_path": "~/.claude/settings.json"}),
        ("Read", {"file_path": "~/.config/botrbac/policy.json"}),
        ("Grep", {"pattern": "botrbac", "path": "~/.claude"}),
        ("Edit", {"file_path": "src/app.py", "old_string": "a", "new_string": "b"}),
        ("Bash", {"command": "git status && gh pr list"}),
        ("Read", {"file_path": "app/credentials.json"}),  # only botrbac's own is protected
    ],
)
def test_ordinary_calls_still_pass(tool, tool_input) -> None:
    assert check("claude-code", _call(tool, **tool_input), None, False)[0]


def test_custom_botrbac_home_is_protected(home, monkeypatch) -> None:
    custom = home / "elsewhere"
    monkeypatch.setenv("BOTRBAC_HOME", str(custom))
    assert refusal("Bash", {"command": f"rm {custom}/policy.json"})
    assert refusal("Write", {"file_path": f"{custom}/sessions/x.json"})


def test_gateway_refuses_protected_paths() -> None:
    import anyio

    from botrbac_cli.gateway import Gateway

    gateway = Gateway(policy.Enforcer(), AuditQueue(), agent="t")
    upstream = stub_upstream("fs", "write_file")
    gateway.add(upstream)
    result = anyio.run(gateway.call, "fs__write_file", {"path": "~/.claude/settings.json"})
    assert result.isError and "Blocked by Bot RBAC" in result.content[0].text
    assert upstream.session.calls == []
    anyio.run(gateway.call, "fs__write_file", {"path": "notes.txt"})
    assert upstream.session.calls == [("write_file", {"path": "notes.txt"})]


# ---- is the hook still there? ------------------------------------------------------


def test_hook_status_and_doctor(home, capsys) -> None:
    settings = home / "home" / ".claude" / "settings.json"
    assert hook_report() == {}  # never installed: nothing expected
    assert main(["hooks", "install", "claude-code", "--user"]) == 0
    assert hook_report() == {"claude-code": "installed"}

    settings.write_text("{}")  # someone (or something) took it out
    assert claude_code_hook_status() == "missing"
    capsys.readouterr()
    main(["doctor"])
    assert "claude-code hook is missing" in capsys.readouterr().out

    install_claude_code(settings)
    data = json.loads(settings.read_text())
    data["disableAllHooks"] = True
    settings.write_text(json.dumps(data))
    assert hook_report() == {"claude-code": "disabled"}

    assert main(["hooks", "remove", "claude-code", "--user"]) == 0
    assert hook_report() == {}  # removed on purpose: no longer expected


def test_missing_hook_shows_on_the_website(world, memstore, oauth) -> None:
    app = terminal_app(world, memstore, oauth)
    c = dash.client(app)
    dash.login(c)
    issued = connect_terminal(c)
    headers = bearer(issued)
    c.post("/api/terminal/audit", json={"rows": [], "hooks": {"claude-code": "missing"}},
           headers=headers)  # fmt: skip
    (terminal,) = app.state.terminal.terminals.for_person(OWNER_EMAIL)
    assert app.state.terminal.terminals.get(terminal.id).hook_missing == ["claude-code"]
    page = c.get("/terminal").text
    assert "Claude Code isn" in page and "being checked" in page
    c.post("/api/terminal/audit", json={"rows": [], "hooks": {"claude-code": "installed"}},
           headers=headers)  # fmt: skip
    assert "being checked" not in c.get("/terminal").text


def test_sync_reports_hook_status() -> None:
    from botrbac_cli.hooks import expect_hook
    from botrbac_cli.sync import sync

    expect_hook("claude-code", True)
    api = FakeApi()
    sync(api, AuditQueue())
    assert api.bodies[0]["hooks"] == {"claude-code": "missing"}


# ---- the signed role file ----------------------------------------------------------


def _pin_signed_policy(issued_at: float | None = None, **role) -> dict:
    from botrbac_cli import signing

    key = signing.key_from_secret("test secret")
    body = {
        "role": {"id": "r", "name": "Coder", "patterns": ["claude-code/Read"], **role},
        "roles": [],
        "revoked_sessions": [],
        "issued_at": time.time() if issued_at is None else issued_at,
    }
    body["signature"] = signing.sign(key, body)
    state.write_json("policy.json", {"policy": body, "fetched_at": time.time()})
    state.write_json("credentials.json", {"policy_key": signing.public_key_text(key)})
    return body


def test_server_signs_policies_and_hands_out_the_key(world, memstore, oauth) -> None:
    from botrbac_cli import signing

    c = dash.client(terminal_app(world, memstore, oauth))
    dash.login(c)
    issued = connect_terminal(c)
    assert issued["policy_key"]
    body = c.get("/api/terminal/policy", headers=bearer(issued)).json()
    assert signing.verify(issued["policy_key"], body)
    body["role"]["patterns"] = ["*"]
    assert not signing.verify(issued["policy_key"], body)


def test_signed_policy_is_used() -> None:
    _pin_signed_policy()
    assert check("claude-code", _call("Read", file_path="notes.txt"), None, False)[0]
    assert not check("claude-code", _call("Edit", file_path="notes.txt"), None, False)[0]


def _widen(body: dict) -> None:
    body["role"]["patterns"] = ["*"]  # an agent widening its own role


def _strip_signature(body: dict) -> None:
    body.pop("signature")


def _widen_and_unpin(body: dict) -> None:
    _widen(body)
    state.write_json("credentials.json", {})  # removing the key does not switch signing off


@pytest.mark.parametrize("tamper", [_widen, _strip_signature, _widen_and_unpin])
def test_a_policy_changed_on_this_computer_blocks_everything(tamper) -> None:
    body = _pin_signed_policy()
    tamper(body)
    state.write_json("policy.json", {"policy": body, "fetched_at": time.time()})
    allowed, reason = check("claude-code", _call("Read", file_path="notes.txt"), None, False)
    assert not allowed and "changed on this computer" in reason


def test_fetch_time_cannot_stretch_the_offline_grace() -> None:
    # Issued 30 days ago; the unsigned fetch time claims "just now".
    _pin_signed_policy(issued_at=time.time() - 30 * 86400, offline_days=7)
    allowed, reason = check("claude-code", _call("Read", file_path="notes.txt"), None, False)
    assert not allowed and "offline" in reason


def test_login_pins_the_key_and_refresh_keeps_it() -> None:
    from botrbac_cli.api import Api

    api = Api("https://example.test")
    base = {"access_token": "a", "refresh_token": "r", "expires_in": 3600}
    api._save({**base, "policy_key": "KEY"})
    api._save(base)  # an answer without a key keeps the pinned one
    assert state.read_json("credentials.json", {})["policy_key"] == "KEY"
    api._save({**base, "policy_key": "NEW"})  # a new server key replaces it
    assert state.read_json("credentials.json", {})["policy_key"] == "NEW"


# ---- paths through symlinks and `..` ---------------------------------------------------


def test_symlink_to_protected_file_is_refused(home) -> None:
    settings = home / "home" / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text("{}")
    (home / "innocent.json").symlink_to(settings)
    assert not check("claude-code", _call("Write", file_path="innocent.json"), None, False)[0]
    sneaky = str(home / "sub" / ".." / "home" / ".claude" / "settings.json").replace(
        ".claude", "./.claude"
    )
    assert not check("claude-code", _call("Edit", file_path=sneaky), None, False)[0]


def test_read_looking_names_that_write_are_not_read_only() -> None:
    from botrbac_cli.protect import is_read_only

    assert not is_read_only("fs/get_and_write")
    assert not is_read_only("fs/getAndWrite")
    assert is_read_only("fs/read_file") and is_read_only("fs/list_directory")


def test_refusal_says_what_matched_and_follows_paths_with_spaces(home) -> None:
    settings = home / "home" / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text("{}")
    odd = home / "my files"
    odd.mkdir()
    (odd / "x.json").symlink_to(settings)
    why = refusal("claude-code/Write", {"file_path": str(odd / "x.json")})
    assert why and "settings.json" in why
    assert "disableallhooks" in refusal("claude-code/Bash", {"command": "echo disableAllHooks"})

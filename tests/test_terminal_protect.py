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
from tests.terminal_helpers import connect_terminal, terminal_app


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
    from mcp import types

    from botrbac_cli.gateway import Gateway, Upstream

    class Session:
        called = False

        async def call_tool(self, name, arguments):
            Session.called = True
            return types.CallToolResult(content=[])

    gateway = Gateway(policy.Enforcer(), AuditQueue(), agent="t")
    tool = types.Tool(name="write_file", inputSchema={"type": "object"})
    gateway.add(Upstream("fs", session=Session(), tools=[tool]))  # type: ignore[arg-type]
    result = anyio.run(gateway.call, "fs__write_file", {"path": "~/.claude/settings.json"})
    assert result.isError and "Blocked by Bot RBAC" in result.content[0].text
    assert not Session.called
    anyio.run(gateway.call, "fs__write_file", {"path": "notes.txt"})
    assert Session.called


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
    headers = {"Authorization": f"Bearer {issued['access_token']}"}
    c.post("/api/terminal/audit", json={"rows": [], "hooks": {"claude-code": "missing"}},
           headers=headers)  # fmt: skip
    (terminal,) = app.state.terminal.terminals.for_person(OWNER_EMAIL)
    assert app.state.terminal.terminals.get(terminal.id).hook_missing == ["claude-code"]
    assert "claude-code hook off" in c.get("/terminal").text
    c.post("/api/terminal/audit", json={"rows": [], "hooks": {"claude-code": "installed"}},
           headers=headers)  # fmt: skip
    assert "hook off" not in c.get("/terminal").text


def test_sync_reports_hook_status() -> None:
    from botrbac_cli.hooks import expect_hook
    from botrbac_cli.sync import sync

    expect_hook("claude-code", True)
    sent = []

    class Api:
        def send_audit(self, body):
            sent.append(body)
            return {}

        def policy(self):
            return {"role": {"id": "r", "patterns": ["*"]}, "roles": []}

    sync(Api(), AuditQueue())
    assert sent[0]["hooks"] == {"claude-code": "missing"}


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
    body = c.get(
        "/api/terminal/policy", headers={"Authorization": f"Bearer {issued['access_token']}"}
    ).json()
    assert signing.verify(issued["policy_key"], body)
    body["role"]["patterns"] = ["*"]
    assert not signing.verify(issued["policy_key"], body)


def test_signed_policy_is_used() -> None:
    _pin_signed_policy()
    assert check("claude-code", _call("Read", file_path="notes.txt"), None, False)[0]
    assert not check("claude-code", _call("Edit", file_path="notes.txt"), None, False)[0]


def test_edited_policy_blocks_everything() -> None:
    body = _pin_signed_policy()
    body["role"]["patterns"] = ["*"]  # an agent widening its own role
    state.write_json("policy.json", {"policy": body, "fetched_at": time.time()})
    allowed, reason = check("claude-code", _call("Read", file_path="notes.txt"), None, False)
    assert not allowed and "changed on this computer" in reason


def test_unsigned_policy_is_refused_once_a_key_is_pinned() -> None:
    body = _pin_signed_policy()
    body.pop("signature")
    state.write_json("policy.json", {"policy": body, "fetched_at": time.time()})
    assert not check("claude-code", _call("Read", file_path="notes.txt"), None, False)[0]


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


# ---- paths through symlinks and `..`, and switching hooks off -------------------------


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


@pytest.mark.parametrize(
    "command",
    ["botrbac hooks remove claude-code --user", "echo '{\"disableAllHooks\": true}' > x.json"],
)
def test_switching_hooks_off_is_refused(command) -> None:
    assert not check("claude-code", _call("Bash", command=command), None, False)[0]


def test_other_credentials_files_can_be_read() -> None:
    assert check("claude-code", _call("Read", file_path="app/credentials.json"), None, False)[0]

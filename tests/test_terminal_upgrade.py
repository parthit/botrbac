"""Computers set up by a botrbac from before --home: doctor names the hook and gateway
entries to bring up to date, and running the usual commands again fixes them."""

import json
import tomllib

import pytest

from botrbac_cli import agents, coverage
from botrbac_cli.main import main

OLD_HOOK = "/usr/bin/botrbac check --agent claude-code --block-unguarded"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BOTRBAC_HOME", str(tmp_path / ".config" / "botrbac"))
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    return tmp_path


def _write(path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data if isinstance(data, str) else json.dumps(data))


def test_doctor_names_an_old_hook_and_the_fix(home) -> None:
    hook = {"type": "command", "command": OLD_HOOK}
    _write(
        home / ".claude" / "settings.json",
        {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [hook]}]}},
    )
    lines: list[str] = []
    agents.doctor_report(lines.append)
    text = "\n".join(lines)
    assert "hook in" in text and "older botrbac" in text
    assert "fix: botrbac hooks install claude-code --user --allow-unguarded" in text
    assert main(["hooks", "install", "claude-code", "--user", "--allow-unguarded"]) == 0
    assert agents.stale_hooks() == []


def test_add_gateway_brings_an_old_json_entry_up_to_date(home) -> None:
    path = home / ".cursor" / "mcp.json"
    _write(
        path,
        {
            "mcpServers": {
                "botrbac": {"command": "botrbac", "args": ["gateway", "--agent", "cursor"]},
                "github": {"command": "npx", "args": ["x"]},
            }
        },
    )
    assert [c.path for c in coverage.stale_gateways()] == [path]
    lines: list[str] = []
    agents.doctor_report(lines.append)
    assert any("fix: botrbac add-gateway --agent cursor" in line for line in lines)
    assert main(["add-gateway", "--agent", "cursor"]) == 0
    data = json.loads(path.read_text())
    assert data["mcpServers"]["botrbac"]["args"][0] == "--home"
    assert data["mcpServers"]["github"] == {"command": "npx", "args": ["x"]}
    assert coverage.stale_gateways() == []
    before = path.read_text()
    assert main(["add-gateway", "--agent", "cursor"]) == 0  # nothing left to change
    assert path.read_text() == before


def test_add_gateway_brings_an_old_codex_table_up_to_date(home) -> None:
    path = home / ".codex" / "config.toml"
    _write(
        path,
        'model = "x"\n\n[mcp_servers.botrbac]\ncommand = "botrbac"\n'
        'args = ["gateway", "--agent", "codex"]\n\n[mcp_servers.github]\ncommand = "npx"\n',
    )
    assert main(["add-gateway", "--agent", "codex"]) == 0
    data = tomllib.loads(path.read_text())
    assert data["model"] == "x"
    assert data["mcp_servers"]["github"] == {"command": "npx"}
    assert data["mcp_servers"]["botrbac"]["args"][:1] == ["--home"]
    assert coverage.stale_gateways() == []


def test_claude_code_fix_names_the_folder(home) -> None:
    _write(
        home / ".claude.json",
        {"mcpServers": {"botrbac": {"command": "botrbac", "args": ["gateway"]}}},
    )
    lines: list[str] = []
    agents.doctor_report(lines.append)
    fix = next(line for line in lines if "claude mcp remove" in line)
    assert "--home" in fix and str(home / ".config" / "botrbac") in fix

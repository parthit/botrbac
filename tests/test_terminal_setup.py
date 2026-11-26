"""Terminal setup: the install script, agent instructions, add-gateway, login and the page."""

import json
import stat
import subprocess
import tomllib
from pathlib import Path

import pytest

from botrbac_cli import state
from botrbac_cli.main import main
from scoped_drive_mcp.terminal.feature import (
    install_command,
    install_script,
    login_command,
    safe_site,
    setup_markdown,
)
from tests import dash
from tests.conftest import BASE_URL
from tests.terminal_helpers import terminal_app

ROOT = Path(__file__).resolve().parent.parent


# ---- public documents ------------------------------------------------------------------


def test_setup_md_is_public_markdown(world, memstore, oauth) -> None:
    c = dash.client(terminal_app(world, memstore, oauth))
    r = c.get("/terminal/setup.md")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/markdown")
    text = r.text
    assert BASE_URL in text and "{{" not in text
    assert f"botrbac login --server {BASE_URL}" in text
    assert "claude mcp add botrbac -- botrbac gateway" in text
    assert "~/.cursor/mcp.json" in text and '"--agent", "cursor"' in text
    assert "[mcp_servers.botrbac]" in text and '"--agent", "codex"' in text
    assert "~/.gemini/settings.json" in text and '"--agent", "gemini"' in text
    assert "Never print, log or paste tokens" in text


def test_docs_copy_matches_the_served_instructions() -> None:
    """docs/terminal-agent-setup.md is generated from the template, for botrbac.com."""
    docs = (ROOT / "docs" / "terminal-agent-setup.md").read_text()
    assert docs == setup_markdown("https://botrbac.com"), (
        "regenerate: uv run python scripts/terminal_agent_setup.py"
    )


def test_install_sh_is_public(world, memstore, oauth) -> None:
    c = dash.client(terminal_app(world, memstore, oauth))
    r = c.get("/terminal/install.sh")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/x-shellscript")
    assert f"SERVER='{BASE_URL}'" in r.text and "{{" not in r.text
    assert "sudo" not in r.text.replace("never uses sudo", "").replace("Never uses sudo", "")


def test_site_addresses() -> None:
    assert login_command("https://botrbac.com/") == "botrbac login"
    assert login_command("https://rbac.example.org") == (
        "botrbac login --server https://rbac.example.org"
    )
    assert install_command("https://botrbac.com", "cursor") == (
        "curl -fsSL https://botrbac.com/terminal/install.sh | sh -s -- --agent cursor"
    )
    # Never bakes something odd (a hostile Host header) into a script.
    assert safe_site("https://evil.example'; rm -rf ~;'") == "https://botrbac.com"
    assert safe_site("http://127.0.0.1:8000") == "http://127.0.0.1:8000"


def test_install_sh_parses() -> None:
    result = subprocess.run(  # noqa: S603 - the script this repo serves
        ["/bin/sh", "-n"], input=install_script(BASE_URL), text=True, capture_output=True
    )
    assert result.returncode == 0, result.stderr


# ---- running the script with stand-in programs ------------------------------------------

_STUB = """#!/bin/sh
echo "{name} $*" >> "$STUB_LOG"
{body}
exit 0
"""
_BODIES = {
    "uv": "",
    "botrbac": (
        'case "$1" in\n'
        '  status) [ -f "$HOME/.logged-in" ] || exit 1 ;;\n'
        '  login) echo "Link: x"; echo "Code: ABCD-EFGH"; touch "$HOME/.logged-in" ;;\n'
        "esac"
    ),
    "claude": (
        'if [ "$1 $2" = "mcp get" ]; then [ -f "$HOME/.claude-has-it" ] || exit 1; fi\n'
        'if [ "$1 $2" = "mcp add" ]; then touch "$HOME/.claude-has-it"; fi'
    ),
}


def _stubs(tmp_path: Path, names) -> tuple[dict[str, str], Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in names:
        path = bin_dir / name
        path.write_text(_STUB.format(name=name, body=_BODIES[name]))
        path.chmod(path.stat().st_mode | stat.S_IEXEC)
    log = tmp_path / "calls.log"
    home = tmp_path / "home"
    home.mkdir()
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(home), "STUB_LOG": str(log)}
    return env, log


def _run(env, *args):
    return subprocess.run(  # noqa: S603 - the script this repo serves
        ["/bin/sh", "-s", "--", *args],
        input=install_script(BASE_URL),
        text=True,
        capture_output=True,
        env=env,
        timeout=30,
    )


def test_install_sh_runs_install_login_and_mcp_add_in_order(tmp_path) -> None:
    env, log = _stubs(tmp_path, ["uv", "botrbac", "claude"])
    first = _run(env, "--agent", "claude-code")
    assert first.returncode == 0, first.stderr + first.stdout
    calls = log.read_text().splitlines()
    names = [c.split()[0] + " " + c.split()[1] for c in calls]
    assert names.index("uv tool") < names.index("botrbac login") < names.index("claude mcp")
    assert f"botrbac login --server {BASE_URL}" in calls
    assert any(c.startswith("claude mcp add --scope user botrbac -- ") for c in calls)
    assert "botrbac hooks install claude-code --user --allow-unguarded" in calls
    assert names.index("claude mcp") < names.index("botrbac hooks")
    assert "starts as Read-only" in first.stdout
    assert "Done. Restart Claude Code to load Bot RBAC." in first.stdout
    assert "Code: ABCD-EFGH" in first.stdout

    second = _run(env)
    assert second.returncode == 0, second.stderr + second.stdout
    again = log.read_text().splitlines()[len(calls) :]
    assert not any(c.startswith("botrbac login") for c in again)
    assert not any(c.startswith("claude mcp add") for c in again)
    assert any(c.startswith("uv tool install --upgrade") for c in again)


def test_install_sh_no_hook(tmp_path) -> None:
    env, log = _stubs(tmp_path, ["uv", "botrbac", "claude"])
    r = _run(env, "--no-hook")
    assert r.returncode == 0, r.stderr + r.stdout
    assert "hooks install" not in log.read_text()


def test_install_sh_other_agents_use_add_gateway(tmp_path) -> None:
    env, log = _stubs(tmp_path, ["uv", "botrbac"])
    r = _run(env, "--agent", "cursor")
    assert r.returncode == 0, r.stderr
    assert "botrbac add-gateway --agent cursor" in log.read_text()
    assert "hooks install" not in log.read_text()
    assert "Restart Cursor" in r.stdout


def test_install_sh_skips_claude_when_missing_and_refuses_bad_agents(tmp_path) -> None:
    env, log = _stubs(tmp_path, ["uv", "botrbac"])
    r = _run(env)
    assert r.returncode == 0 and "not installed here" in r.stdout
    bad = _run(env, "--agent", "vim")
    assert bad.returncode != 0 and "unknown agent" in bad.stderr


# ---- botrbac add-gateway ---------------------------------------------------------------


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("BOTRBAC_HOME", str(tmp_path / "botrbac"))
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def test_add_gateway_merges_json_and_is_idempotent(home, capsys) -> None:
    path = home / ".cursor" / "mcp.json"
    path.parent.mkdir()
    path.write_text(json.dumps({"mcpServers": {"github": {"command": "gh-mcp"}}, "theme": 1}))
    assert main(["add-gateway", "--agent", "cursor"]) == 0
    data = json.loads(path.read_text())
    assert data["theme"] == 1 and data["mcpServers"]["github"] == {"command": "gh-mcp"}
    assert data["mcpServers"]["botrbac"]["args"][-3:] == ["gateway", "--agent", "cursor"]
    assert "Backup:" in capsys.readouterr().out
    assert len(list(path.parent.glob("mcp.json.botrbac-backup-*"))) == 1

    before = path.read_text()
    assert main(["add-gateway", "--agent", "cursor"]) == 0
    assert path.read_text() == before
    assert "Already set up" in capsys.readouterr().out


def test_add_gateway_creates_gemini_file(home) -> None:
    assert main(["add-gateway", "--agent", "gemini"]) == 0
    data = json.loads((home / ".gemini" / "settings.json").read_text())
    assert list(data["mcpServers"]) == ["botrbac"]


def test_add_gateway_appends_toml_once(home) -> None:
    path = home / ".codex" / "config.toml"
    path.parent.mkdir()
    path.write_text('model = "o4"\n\n[mcp_servers.github]\ncommand = "gh-mcp"\n')
    assert main(["add-gateway", "--agent", "codex"]) == 0
    data = tomllib.loads(path.read_text())
    assert data["model"] == "o4" and data["mcp_servers"]["github"] == {"command": "gh-mcp"}
    assert data["mcp_servers"]["botrbac"]["args"][-3:] == ["gateway", "--agent", "codex"]
    text = path.read_text()
    assert main(["add-gateway", "--agent", "codex"]) == 0
    assert path.read_text() == text


def test_add_gateway_leaves_broken_or_clashing_files(home, capsys) -> None:
    path = home / ".cursor" / "mcp.json"
    path.parent.mkdir()
    path.write_text("{not json")
    assert main(["add-gateway", "--agent", "cursor"]) == 1
    assert path.read_text() == "{not json"
    path.write_text(json.dumps({"mcpServers": {"botrbac": {"command": "something-else"}}}))
    assert main(["add-gateway", "--agent", "cursor"]) == 1
    assert "not the gateway" in capsys.readouterr().err
    assert json.loads(path.read_text())["mcpServers"]["botrbac"] == {"command": "something-else"}


# ---- the CLI's login output and default server -------------------------------------------


class _LoginApi:
    """botrbac_cli.api.Api for `botrbac login`: answers each poll from `polls`."""

    seen: dict = {}
    polls: list = []

    def __init__(self, server=None, client=None):
        _LoginApi.seen["server"] = server
        self.server = server

    def start_login(self, hostname, os_name):
        return {
            "device_code": "d",
            "user_code": "ABCD-EFGH",
            "verification_uri": f"{self.server}/device",
            "verification_uri_complete": f"{self.server}/device?code=ABCD-EFGH",
            "interval": 1,
            "expires_in": 60,
        }

    def poll_login(self, device_code):
        return _LoginApi.polls.pop(0) if _LoginApi.polls else {"access_token": "x"}

    def policy(self):
        return {"email": "me@example.com", "role": {"name": "Read-only"}}


@pytest.fixture
def login_api(home, monkeypatch):
    from botrbac_cli import main as cli

    sleeps: list = []
    monkeypatch.delenv("BOTRBAC_SERVER", raising=False)
    monkeypatch.setattr(cli, "Api", _LoginApi)
    monkeypatch.setattr(cli.time, "sleep", sleeps.append)
    _LoginApi.polls = []
    return sleeps


def test_login_defaults_to_botrbac_com_and_prints_plain_lines(login_api, monkeypatch, capsys):
    assert main(["login"]) == 0
    assert _LoginApi.seen["server"] == "https://botrbac.com"
    out = capsys.readouterr().out.splitlines()
    assert "Link: https://botrbac.com/device?code=ABCD-EFGH" in out
    assert "Code: ABCD-EFGH" in out
    assert out[-1] == "Logged in as me@example.com, role Read-only"
    monkeypatch.setenv("BOTRBAC_SERVER", "https://rbac.example.org")
    assert main(["login"]) == 0 and _LoginApi.seen["server"] == "https://rbac.example.org"
    assert main(["login", "--server", "http://localhost:8000"]) == 0
    assert _LoginApi.seen["server"] == "http://localhost:8000"
    assert state.read_json("policy.json")


def test_login_waits_politely(login_api) -> None:
    """RFC 8628: slow_down adds five seconds to every later wait; rate_limited waits a
    minute once."""
    _LoginApi.polls = ["authorization_pending", "slow_down", "rate_limited", "slow_down"]
    assert main(["login"]) == 0
    assert login_api == [1, 1, 6, 60, 6, 11]


@pytest.mark.parametrize(
    ("polls", "message"),
    [
        (["authorization_pending", "access_denied"], "Login refused on the website"),
        (["invalid_grant"], "Login did not complete: invalid_grant"),
    ],
)
def test_login_that_does_not_finish_exits_1(login_api, capsys, polls, message) -> None:
    _LoginApi.polls = polls
    assert main(["login"]) == 1
    assert message in capsys.readouterr().err
    assert state.read_json("policy.json") is None


def test_login_code_expiring_exits_1(login_api, monkeypatch, capsys) -> None:
    monkeypatch.setattr(_LoginApi, "start_login", lambda self, h, o: {
        "device_code": "d", "user_code": "ABCD-EFGH", "verification_uri_complete": "x",
        "expires_in": -1})  # fmt: skip
    assert main(["login"]) == 1
    assert "code expired" in capsys.readouterr().err


def test_unreachable_server_is_one_line_and_exit_1(home, monkeypatch, capsys) -> None:
    monkeypatch.setenv("BOTRBAC_SERVER", "http://127.0.0.1:9")
    assert main(["login"]) == 1
    err = capsys.readouterr().err.strip().splitlines()
    assert len(err) == 1 and "Could not reach" in err[0]


# ---- the Terminal page ---------------------------------------------------------------------


def test_terminal_page_leads_with_setup(world, memstore, oauth) -> None:
    c = dash.client(terminal_app(world, memstore, oauth))
    assert c.get("/terminal").headers["location"].startswith("/login")  # signed out
    dash.login(c)
    assert 'href="/terminal"' in c.get("/").text  # in the nav
    for other in ["/files", "/requests", "/sharing", "/activity", "/settings"]:
        assert c.get(other).status_code == 200, other  # the rest of the site still answers
    r = c.get("/terminal")
    assert r.status_code == 200
    page = r.text
    assert page.index('id="setup"') < page.index('id="no-terminals"')
    assert f"Set up Bot RBAC Terminal for me by following {BASE_URL}/terminal/setup.md" in page
    assert f"curl -fsSL {BASE_URL}/terminal/install.sh | sh -s -- --agent claude-code" in page
    for agent in ("cursor", "codex", "gemini"):
        assert f"--agent {agent}</code>" in page  # listed without JavaScript too
    assert f"botrbac login --server {BASE_URL}" in page
    assert "claude mcp add botrbac -- botrbac gateway" in page
    assert page.count("data-copy=") >= 6
    # wrap is only an advanced option now.
    main_steps = page.split('id="more-options"', 1)[0]
    assert "botrbac wrap" not in main_steps


def test_roles_explain_themselves_when_nothing_is_connected(world, memstore, oauth) -> None:
    c = dash.client(terminal_app(world, memstore, oauth))
    dash.login(c)
    roles = c.get("/terminal/roles").text
    assert 'id="roles-not-used"' in roles and 'href="/terminal#setup"' in roles
    assert "Every tool on every server" in roles  # built-ins in plain words
    new = c.get("/terminal/roles/new").text
    assert "placeholder=" not in new.split('name="patterns"', 1)[1].split(">", 1)[0]
    assert 'data-insert="cmd/gh"' in new


def test_pages_explain_how_roles_tie_to_computers(world, memstore, oauth) -> None:
    from tests.terminal_helpers import bearer, connect_terminal

    c = dash.client(terminal_app(world, memstore, oauth))
    dash.login(c)
    issued = connect_terminal(c)
    c.post(
        "/api/terminal/audit", json={"rows": [], "unguarded": ["notion"]}, headers=bearer(issued)
    )
    page = c.get("/terminal").text
    assert 'id="how-it-works"' in page and "Role</b> column" in page
    assert "Agents can read, not edit or run commands." in page  # Read-only, in plain words
    # An unguarded server says what it means and how to fix it.
    assert "<b>notion</b> talks to the agent directly" in page
    assert "<code>botrbac doctor</code>" in page and "botrbac wrap claude-code --user" in page

    roles = c.get("/terminal/roles").text
    assert 'id="roles-how"' in roles and "never widen" in roles
    new = c.get("/terminal/roles/new").text
    assert 'id="starters"' in new
    for name in ("Reviewer", "Coding", "Coding, limited shell"):
        assert f'data-name="{name}"' in new
    starter = new.split('data-name="Coding"', 1)[0].rsplit("data-insert=", 1)[1]
    assert "claude-code/Bash\n" in starter and "cmd/" not in starter
    # An existing role is edited as is, without templates.
    assert 'id="starters"' not in c.get("/terminal/roles/read-only").text


def test_setup_md_explains_roles_and_adds_the_hook_last(world, memstore, oauth) -> None:
    text = setup_markdown(BASE_URL)
    assert "## What this is" in text and f"{BASE_URL}/terminal/roles/new" in text
    assert "Blocked by Bot RBAC" in text and "unguarded server" in text
    # The hook blocks the agent's own shell under Read-only, so it is the last command.
    hook = text.index("botrbac hooks install claude-code --user --allow-unguarded")
    assert hook > text.index("botrbac doctor") and hook > text.index("## 5.")


def test_blocked_message_names_the_pattern_and_the_page(tmp_path, monkeypatch) -> None:
    from botrbac_cli import policy

    monkeypatch.setenv("BOTRBAC_HOME", str(tmp_path))
    assert "the Terminal page" in policy.fix_hint("github/create_issue")
    state.write_json("credentials.json", {"server": "https://rbac.example.org/x"}, private=True)
    hint = policy.fix_hint("github/create_issue")
    assert (
        "add github/create_issue to this computer's role at https://rbac.example.org/terminal/roles"
        in hint
    )

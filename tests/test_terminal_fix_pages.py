"""Terminal pages escape what computers send, and the installer checks which server it is on."""

import re
import time
from pathlib import Path

from scoped_drive_mcp.dashboard import _env
from scoped_drive_mcp.terminal import identity, present
from tests.test_terminal_setup import _run, _stubs

# Values a hostile or broken computer could put in an audit row. The server's own checks
# drop most of them; the templates must stay safe even when one gets through.
SCRIPT = "<script>alert(1)</script>"
ATTR = '"><img src=x onerror=alert(1)>'
JS = "javascript:alert(1)"
HOSTILE = f"{SCRIPT}{ATTR}{JS}"
PAGE = {
    "owner": "o@example.com",
    "flashes": [],
    "csrf": "csrf-token",
    "pending_count": 0,
    "mailbox_count": 0,
    "allow_count": None,
    "terminal_tab": True,
}


def _assert_safe(html: str) -> None:
    assert SCRIPT not in html and "<script>alert" not in html
    assert "<img" not in html and ATTR not in html
    assert "&lt;script&gt;" in html
    for href in re.findall(r'(?:href|action|src)\s*=\s*"([^"]*)"', html, flags=re.I):
        assert not href.strip().lower().startswith("javascript:"), href
    assert not re.search(r"(?:href|action|src)\s*=\s*'?\s*javascript:", html, flags=re.I)


def _rows(now: float) -> list[dict]:
    common = {
        "terminal": HOSTILE,
        "terminal_id": HOSTILE,
        "agent": HOSTILE,
        "agent_id": HOSTILE,
        "agent_type": HOSTILE,
        "actor": HOSTILE,
        "cwd": "/home/" + HOSTILE,
        "repo": HOSTILE,
        "branch": HOSTILE,
        "head": HOSTILE,
        "role": HOSTILE,
        "session_id": HOSTILE,
        "agent_session_id": HOSTILE,
    }
    return [
        {**common, "decision": "session", "ts": now, "program": HOSTILE, "task": HOSTILE,
         "command": HOSTILE},
        {**common, "decision": "prompt", "ts": now - 1, "prompt_id": HOSTILE, "command": HOSTILE},
        {**common, "decision": "deny", "ts": now - 2, "prompt_id": HOSTILE, "tool": HOSTILE,
         "reason": HOSTILE, "command": HOSTILE, "input_digest": "sha256:" + "a" * 64},
        {**common, "decision": "allow", "ts": now - 3, "tool": f"{HOSTILE}/{HOSTILE}",
         "reason": HOSTILE, "chain": HOSTILE, "input_digest": "sha256:" + "b" * 64,
         "input_size": 12},
    ]  # fmt: skip


def test_activity_page_escapes_hostile_rows() -> None:
    rows = _rows(time.time())
    html = _env.get_template("terminal_activity.html").render(
        **PAGE,
        nav="/terminal/activity",
        delegation=identity.chain_text,
        webhook=None,
        can_webhook=False,
        stories=present.stories(rows),
        trouble=present.trouble,
        agent_name=present.agent_name,
        recording=True,
        can_record=True,
        more=False,
        limit=100,
        total=len(rows),
        terminals=[{"id": HOSTILE, "name": HOSTILE}],
        agents=[HOSTILE],
        q={"prompt_id": HOSTILE, "agent_session_id": HOSTILE, "terminal": HOSTILE},
        export_query="",
    )
    _assert_safe(html)
    assert "/home/&lt;script&gt;" in html  # the cwd is there, escaped
    # Ids in links are URL-encoded, not just HTML-escaped.
    assert "/terminal/sessions/%3Cscript%3E" in html
    assert "prompt_id=%3Cscript%3E" in html and "agent_session_id=%3Cscript%3E" in html
    # A fingerprint without a size does not read "( bytes)"; one with a size shows it.
    assert "( bytes)" not in html and "(12 bytes)" in html


def _tree(now: float) -> dict:
    start = {**_rows(now)[0], "parent_session_id": HOSTILE}
    blocked = {"tool": f"{HOSTILE}/{HOSTILE}", "reason": HOSTILE, "decision": "deny"}
    child = {"start": start, "calls": 1, "blocked": [blocked], "children": [], "revoked": False}
    return {**child, "children": [child]}


def test_session_page_escapes_hostile_rows() -> None:
    html = _env.get_template("terminal_session.html").render(
        **PAGE,
        nav="/terminal/sessions/x",
        tree=_tree(time.time()),
        agent_name=present.agent_name,
        blocked_because=present.blocked_because,
        describe=present.action,
        tried=present.tried,
    )
    _assert_safe(html)
    assert "/terminal/sessions/%3Cscript%3E" in html
    assert "/terminal/activity?terminal=%3Cscript%3E" in html
    assert 'action="/terminal/sessions/%3Cscript%3E' in html  # the revoke form


def test_webhook_secret_page() -> None:
    html = _env.get_template("terminal_webhook_secret.html").render(
        **PAGE,
        nav="/terminal/activity",
        url="https://hooks.example.com/" + HOSTILE,
        secret="whsec_" + HOSTILE,
        include_commands=True,
    )
    _assert_safe(html)
    assert 'id="webhook-secret-value">whsec_&lt;script&gt;' in html
    assert "with recorded commands as text" in html
    assert "It is not shown again" in html
    plain = _env.get_template("terminal_webhook_secret.html").render(
        **PAGE, nav="/", url="https://hooks.example.com/x", secret="whsec_1", include_commands=False
    )
    assert "recorded commands" not in plain and "whsec_1" in plain


# ---- installer: already logged in, but to another server --------------------------------


def _other_server_status(env: dict, home: Path, server: str) -> None:
    """Make the botrbac stand-in report a login to `server`, as `botrbac status` does."""
    bin_botrbac = Path(env["PATH"].split(":")[0]) / "botrbac"
    bin_botrbac.write_text(
        "#!/bin/sh\n"
        'echo "botrbac $*" >> "$STUB_LOG"\n'
        'case "$1" in\n'
        '  status) [ -f "$HOME/.logged-in" ] || exit 1; printf "Server:   %s\\n" "$(cat "$HOME/.logged-in")" ;;\n'  # noqa: E501
        '  login) echo "Code: ABCD-EFGH"; printf "%s" "$3" > "$HOME/.logged-in" ;;\n'
        "esac\n"
        "exit 0\n"
    )
    (home / ".logged-in").write_text(server)


def test_install_sh_logs_in_again_when_on_another_server(tmp_path) -> None:
    from tests.conftest import BASE_URL

    env, log = _stubs(tmp_path, ["uv", "botrbac", "claude"])
    home = Path(env["HOME"])
    _other_server_status(env, home, "https://other.example.com")
    first = _run(env, "--agent", "claude-code")
    assert first.returncode == 0, first.stderr + first.stdout
    calls = log.read_text().splitlines()
    assert f"botrbac login --server {BASE_URL}" in calls
    assert "logged in to https://other.example.com, not" in first.stdout
    assert "Already logged in" not in first.stdout
    assert (home / ".logged-in").read_text() == BASE_URL

    # Now on this server (a trailing slash is the same server): no second login.
    (home / ".logged-in").write_text(BASE_URL + "/")
    second = _run(env)
    assert second.returncode == 0, second.stderr + second.stdout
    again = log.read_text().splitlines()[len(calls) :]
    assert not any(c.startswith("botrbac login") for c in again)
    assert "Already logged in" in second.stdout


def test_install_sh_says_what_it_installs_before_installing_uv(tmp_path) -> None:
    env, log = _stubs(tmp_path, ["botrbac", "claude"])
    bin_dir = Path(env["PATH"].split(":")[0])
    # A curl that serves an "installer" which drops a uv stand-in into ~/.local/bin.
    (bin_dir / "curl").write_text(
        "#!/bin/sh\n"
        'echo "curl $*" >> "$STUB_LOG"\n'
        "cat <<'EOS'\n"
        'mkdir -p "$HOME/.local/bin"\n'
        'printf \'#!/bin/sh\\necho "uv $*" >> "$STUB_LOG"\\n\' > "$HOME/.local/bin/uv"\n'
        'chmod +x "$HOME/.local/bin/uv"\n'
        "EOS\n"
    )
    (bin_dir / "curl").chmod(0o755)
    env["PATH"] = f"{bin_dir}:/usr/bin:/bin"
    if any((Path(d) / n).exists() for d in ("/usr/bin", "/bin") for n in ("uv", "pipx")):
        import pytest

        pytest.skip("uv or pipx is installed system-wide")
    result = _run(env)
    assert result.returncode == 0, result.stderr + result.stdout
    out = result.stdout
    assert "this installs uv first" in out and "https://astral.sh/uv/install.sh" in out
    assert "~/.local/bin" in out and "never uses sudo" in out
    assert out.index("this installs uv first") < out.index("$ curl -LsSf")
    calls = log.read_text().splitlines()
    assert calls[0].startswith("curl -LsSf https://astral.sh/uv/install.sh")
    assert any(c.startswith("uv tool install --upgrade") for c in calls)

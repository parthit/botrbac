"""Terminal identity and export: per-terminal signing keys, server-set delegation
fields, the OTLP export, the audit webhook and the commit trailer."""

import hashlib
import hmac
import json
import os
import shutil
import subprocess
import time
import uuid
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from botrbac_cli import identity, policy, sealing, state, trailer
from botrbac_cli.api import Api, ApiError
from botrbac_cli.main import main
from scoped_drive_mcp.store import MemoryStore
from scoped_drive_mcp.terminal.device import Terminal
from scoped_drive_mcp.terminal.export import SCHEMA_URL, otlp_logs
from scoped_drive_mcp.terminal.identity import chain_text, stamper
from scoped_drive_mcp.terminal.webhook import AuditWebhook, WebhookError, check_url, outgoing
from tests import dash
from tests.conftest import BASE_URL, OWNER_EMAIL
from tests.terminal_helpers import (
    bearer,
    connect_terminal,
    http_client,
    terminal_app,
)

PUBLIC_DNS = {"hooks.example.com": ["93.184.216.34"], "inside.example.com": ["10.0.0.5"]}


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("BOTRBAC_HOME", str(tmp_path / "botrbac"))
    monkeypatch.delenv(policy.SESSION_ENV, raising=False)
    return tmp_path / "botrbac"


def _userinfo(user: str, secret: str) -> str:
    """`user:secret@`, built at run time so secret scanners do not read a test value
    as a leaked credential."""
    return user + ":" + secret + "@"


def _row(**over):
    row = {
        "event_id": uuid.uuid4().hex,
        "ts": time.time(),
        "agent": "claude-code",
        "tool": "claude-code/Bash",
        "decision": "allow",
        "reason": "ok",
        "role": "Coder",
    }
    row.update(over)
    return row


def _cli_login(app, browser) -> Api:
    """`botrbac login` through Api, the person approving on the website."""
    api = Api(BASE_URL, client=http_client(app))
    started = api.start_login("vm", "Linux")
    assert api.poll_login(started["device_code"]) == "authorization_pending"
    code = started["user_code"]
    token = dash.csrf(browser, f"/device?code={code}")
    r = browser.post(
        "/device/approve", data={"csrf": token, "code": code, "role_id": "full", "name": "vm"}
    )
    assert r.status_code == 303
    assert isinstance(api.poll_login(started["device_code"]), dict)
    return api


@pytest.fixture
def site(world, memstore, oauth):
    app = terminal_app(world, memstore, oauth)
    browser = dash.client(app)
    dash.login(browser)
    return app, browser


def _poll_anyway(monkeypatch):
    """Polling twice within 5 seconds answers slow_down; the tests do not wait."""
    from scoped_drive_mcp.terminal import device

    monkeypatch.setattr(device, "POLL_INTERVAL", 0)


# ---- keys at login and at refresh ------------------------------------------------------


def test_login_makes_a_key_and_the_server_keeps_it(site, monkeypatch, home) -> None:
    _poll_anyway(monkeypatch)
    app, browser = site
    api = _cli_login(app, browser)
    path = home / identity.KEY_FILE
    assert path.exists() and oct(path.stat().st_mode & 0o777) == "0o600"
    assert not (home / identity.PENDING_FILE).exists()
    mine = identity.ensure()["public_key"]
    tid = state.read_json("credentials.json")["terminal_id"]
    assert app.state.terminal.terminals.public_key(tid) == mine
    assert "private_key" not in json.dumps(app.state.terminal.terminals.get(tid).__dict__)

    assert api.send_audit({"rows": [_row()]})["accepted"] == 1
    (row,) = app.state.terminal.activity.recent(OWNER_EMAIL)
    assert row["signed"] is True and row["subject"] == OWNER_EMAIL
    assert row["actor"] == {"sub": f"terminal:{tid}", "act": {"sub": "agent:claude-code"}}
    assert row["grant"] == {"role": "Coder"}

    # A key is never replaced: a later refresh offering another one changes nothing.
    assert not app.state.terminal.terminals.register_key(tid, identity.new_pending())
    assert app.state.terminal.terminals.public_key(tid) == mine

    # Logging out forgets the key.
    assert main(["logout"]) == 0
    assert not path.exists()


def test_a_failed_login_keeps_the_current_key(site, monkeypatch) -> None:
    _poll_anyway(monkeypatch)
    app, browser = site
    _cli_login(app, browser)
    before = identity.ensure()["public_key"]
    api = Api(BASE_URL, client=http_client(app))
    started = api.start_login("vm", "Linux")
    assert api.poll_login(started["device_code"]) == "authorization_pending"
    assert identity.ensure()["public_key"] == before  # pending until the login succeeds


def test_a_terminal_from_before_keys_registers_one_at_refresh(site) -> None:
    app, browser = site
    issued = connect_terminal(browser, role_id="full")  # no public_key sent
    tid = issued["terminal_id"]
    assert app.state.terminal.terminals.public_key(tid) is None
    api = Api(BASE_URL, client=http_client(app))
    api._save(issued)
    # Unsigned until the key is registered: the server has nothing to check against.
    assert api.send_audit({"rows": [_row()]})["accepted"] == 1
    creds = state.read_json("credentials.json")
    state.write_json("credentials.json", {**creds, "expires_at": 0}, private=True)
    assert api.policy()["role"]["id"] == "full"  # refreshed, offering the key
    assert app.state.terminal.terminals.public_key(tid) == identity.ensure()["public_key"]
    assert api.send_audit({"rows": [_row()]})["accepted"] == 1
    rows = app.state.terminal.activity.recent(OWNER_EMAIL)
    assert sorted(r["signed"] for r in rows) == [False, True]


# ---- signed batches ---------------------------------------------------------------------


def _keyed_terminal(app, browser) -> tuple[dict, TestClient]:
    issued = connect_terminal(browser, role_id="full")
    identity.ensure()
    assert app.state.terminal.terminals.register_key(
        issued["terminal_id"], identity.ensure()["public_key"]
    )
    return issued, TestClient(app, base_url=BASE_URL)


def _post(c, issued, body: bytes, headers: dict):
    return c.post(
        "/api/terminal/audit",
        content=body,
        headers={**bearer(issued), "content-type": "application/json", **headers},
    )


def test_signed_batches_accepted_bad_and_replayed_refused(site) -> None:
    app, browser = site
    issued, c = _keyed_terminal(app, browser)
    body = json.dumps({"rows": [_row()]}).encode()
    headers = identity.sign_request("POST", identity.AUDIT_PATH, body)
    assert _post(c, issued, body, headers).json()["accepted"] == 1

    # The same request again: refused, even though the rows would be duplicates anyway.
    replay = _post(c, issued, body, headers)
    assert replay.status_code == 401 and replay.json()["error"] == "replayed_signature"

    other = json.dumps({"rows": [_row(decision="deny")]}).encode()
    swapped = _post(c, issued, other, identity.sign_request("POST", identity.AUDIT_PATH, body))
    assert swapped.status_code == 401 and swapped.json()["error"] == "invalid_signature"

    missing = _post(c, issued, other, {})
    assert missing.status_code == 401 and missing.json()["error"] == "signature_required"

    stale = identity.sign_request("POST", identity.AUDIT_PATH, other)
    stale["X-Botrbac-Timestamp"] = str(int(time.time()) - identity.WINDOW - 10)
    late = _post(c, issued, other, stale)
    assert late.status_code == 401 and late.json()["error"] == "signature_expired"

    # Another computer's key, under this terminal's key id.
    identity.forget()
    foreign = identity.sign_request("POST", identity.AUDIT_PATH, other)
    foreign["X-Botrbac-Key-Id"] = identity.key_id(
        app.state.terminal.terminals.public_key(issued["terminal_id"])
    )
    assert _post(c, issued, other, foreign).status_code == 401
    assert len(app.state.terminal.activity.recent(OWNER_EMAIL)) == 1


def test_cli_does_not_burn_a_refresh_on_a_signature_error(site) -> None:
    app, browser = site
    issued, _ = _keyed_terminal(app, browser)
    api = Api(BASE_URL, client=http_client(app))
    api._save(issued)
    identity.forget()  # the key on this computer is lost: a new one is made
    with pytest.raises(ApiError) as caught:
        api.send_audit({"rows": [_row()]})
    assert caught.value.status == 401 and caught.value.code == "invalid_signature"
    assert state.read_json("credentials.json")["refresh_token"] == issued["refresh_token"]


def test_old_unsigned_cli_is_accepted_and_marked(site) -> None:
    app, browser = site
    issued = connect_terminal(browser, role_id="full")
    r = browser.post("/api/terminal/audit", json={"rows": [_row()]}, headers=bearer(issued))
    assert r.json()["accepted"] == 1
    (row,) = app.state.terminal.activity.recent(OWNER_EMAIL)
    assert row["signed"] is False and row["subject"] == OWNER_EMAIL
    page = browser.get("/terminal/activity").text
    assert "unsigned" in page and "you → terminal laptop → claude-code" in page


def test_delegation_fields_come_from_the_server(site) -> None:
    app, browser = site
    issued = connect_terminal(browser, role_id="full")
    fake = _row(
        signed=True,
        subject="someone-else@example.com",
        actor={"sub": "terminal:t_forged"},
        grant={"role": "Admin"},
        policy_version="abc123",
    )
    browser.post("/api/terminal/audit", json={"rows": [fake]}, headers=bearer(issued))
    (row,) = app.state.terminal.activity.recent(OWNER_EMAIL)
    assert row["signed"] is False and row["subject"] == OWNER_EMAIL
    assert row["actor"]["sub"] == f"terminal:{issued['terminal_id']}"
    assert row["grant"] == {"role": "Coder", "policy_version": "abc123"}


def test_actor_names_the_subagent() -> None:
    terminal = Terminal(id="t_1", email="me@example.com", name="vm")
    stored: list = []
    row = {"agent": "claude-code", "agent_id": "sub-12345678", "terminal": "vm", "role": "R"}
    stamper(terminal, True, stored)(row)
    assert row["actor"] == {
        "sub": "terminal:t_1",
        "act": {"sub": "agent:claude-code/sub-12345678"},
    }
    assert stored == [row]
    assert chain_text(row) == "you → terminal vm → claude-code (subagent …12345678)"


def test_queue_rows_carry_the_policy_version() -> None:
    from botrbac_cli.queue import AuditQueue
    from tests.terminal_helpers import cache_policy

    cache_policy(["*"])
    row = AuditQueue().add(decision="allow", tool="claude-code/Read")
    assert row["policy_version"] == "v1"


# ---- export --------------------------------------------------------------------------------


def test_otlp_export_shape(site) -> None:
    app, browser = site
    issued = connect_terminal(browser, role_id="full")
    rows = [
        _row(tool_use_id="toolu_1", agent_session_id="sess-1", session_id="s" * 12),
        _row(decision="deny", reason="not in role"),
    ]
    browser.post("/api/terminal/audit", json={"rows": rows}, headers=bearer(issued))
    r = browser.get("/terminal/activity/export?format=otlp")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/json")
    body = r.json()
    (resource,) = body["resourceLogs"]
    assert resource["schemaUrl"] == SCHEMA_URL
    (scope,) = resource["scopeLogs"]
    assert scope["scope"]["name"] == "botrbac.terminal"
    records = scope["logRecords"]
    assert len(records) == 2
    for record in records:
        assert record["timeUnixNano"].isdigit() and record["eventName"]
        attrs = {a["key"]: a["value"] for a in record["attributes"]}
        assert attrs["gen_ai.tool.name"] == {"stringValue": "claude-code/Bash"}
        assert attrs["user.email"] == {"stringValue": OWNER_EMAIL}
        assert attrs["botrbac.signed"] == {"boolValue": False}
        assert "botrbac.event_id" in attrs and "botrbac.decision" in attrs
        assert "botrbac.role" in attrs and "botrbac.actor" in attrs
    denied = next(r for r in records if r["severityText"] == "WARN")
    assert denied["severityNumber"] == 13
    # Stream A's fields map to semconv names once the server keeps them.
    record = otlp_logs([{**rows[0], "agent_id": "a1", "chain": "ok"}])["resourceLogs"][0]
    attrs = {a["key"]: a["value"] for a in record["scopeLogs"][0]["logRecords"][0]["attributes"]}
    assert attrs["gen_ai.tool.call.id"] == {"stringValue": "toolu_1"}
    assert attrs["gen_ai.conversation.id"] == {"stringValue": "sess-1"}
    assert attrs["gen_ai.agent.id"] == {"stringValue": "a1"}
    assert attrs["botrbac.chain"] == {"stringValue": "ok"}
    assert "botrbac.session_id" in attrs
    jsonl = browser.get("/terminal/activity/export?format=jsonl").text
    assert '"actor":{"sub":"terminal:' in jsonl


# ---- webhook -------------------------------------------------------------------------------


def _lookup(host: str) -> list[str]:
    if host not in PUBLIC_DNS:
        raise OSError("unknown host")
    return PUBLIC_DNS[host]


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("http://hooks.example.com/x", "invalid_webhook_url"),
        ("https://" + _userinfo("user", "pw") + "hooks.example.com/x", "invalid_webhook_url"),
        ("https://hooks.example.com:8443/x", "invalid_webhook_url"),
        ("https://hooks.example.com/x?token=1", "invalid_webhook_url"),
        ("https://127.0.0.1/x", "invalid_webhook_url"),
        ("https://[::1]/x", "invalid_webhook_url"),
        ("https://localhost/x", "invalid_webhook_url"),
        ("https://inside.example.com/x", "webhook_host_not_public"),
        ("https://nowhere.example.com/x", "webhook_host_unknown"),
    ],
)
def test_webhook_url_refused(url, code) -> None:
    with pytest.raises(WebhookError, match=code):
        check_url(url, _lookup)
    hook = AuditWebhook(MemoryStore(), "secret", lookup=_lookup)
    with pytest.raises(WebhookError):
        hook.save("me@example.com", url, False)


def test_webhook_signs_and_leaves_commands_out_unless_asked() -> None:
    sent: list[dict] = []
    hook = AuditWebhook(
        MemoryStore(), "secret", lookup=_lookup, poster=lambda r: sent.append(r) or 204
    )
    secret = hook.save("me@example.com", "https://hooks.example.com/botrbac", False)
    assert secret and secret.startswith("whsec_")
    assert secret not in json.dumps(hook.store._values, default=str)  # stored encrypted

    key = sealing.key_from_secret("test")
    row = _row()
    row["command"] = sealing.seal(sealing.public_key_text(key), row["event_id"], "echo TOKEN")
    row["description"] = sealing.seal(
        sealing.public_key_text(key), f"{row['event_id']}:description", "list files"
    )
    assert hook.deliver("me@example.com", [row], key) == 204
    (request,) = sent
    assert request["address"] == "93.184.216.34" and request["hostname"] == "hooks.example.com"
    body = request["body"].encode()
    mac = hmac.new(secret.encode(), request["x-botrbac-timestamp"].encode() + b"." + body,
                   hashlib.sha256).hexdigest()  # fmt: skip
    assert request["x-botrbac-signature"] == f"sha256={mac}"
    (posted,) = json.loads(body)["rows"]
    assert "command" not in posted and "description" not in posted
    assert "TOKEN" not in request["body"]

    # Opted in: the same save keeps the secret, and commands go as text.
    assert hook.save("me@example.com", "https://hooks.example.com/botrbac", True) is None
    hook.deliver("me@example.com", [row], key)
    posted = json.loads(sent[-1]["body"])["rows"][0]
    assert posted["command"] == "echo TOKEN" and posted["description"] == "list files"
    # Opted in but recording is off (no key): still nothing.
    hook.deliver("me@example.com", [row], None)
    assert "command" not in json.loads(sent[-1]["body"])["rows"][0]
    assert outgoing(row, None, True).get("command") is None


def test_webhook_failures_never_fail_the_upload(site) -> None:
    app, browser = site
    feature = app.state.terminal
    feature.webhook.lookup = _lookup
    calls: list[dict] = []

    def boom(request):
        calls.append(request)
        raise TimeoutError("slow receiver")

    feature.webhook.poster = boom
    token = dash.csrf(browser, "/terminal/activity")
    assert 'id="audit-webhook"' in browser.get("/terminal/activity").text
    refused = browser.post(
        "/terminal/activity/webhook", data={"csrf": token, "url": "https://inside.example.com/"}
    )
    assert refused.status_code == 303 and feature.webhook.get(OWNER_EMAIL) is None
    assert (
        browser.post(
            "/terminal/activity/webhook", data={"url": "https://hooks.example.com/"}
        ).status_code
        == 403
    )  # no csrf
    token = dash.csrf(browser, "/terminal/activity")
    page = browser.post(
        "/terminal/activity/webhook", data={"csrf": token, "url": "https://hooks.example.com/"}
    )
    assert page.status_code == 200 and "whsec_" in page.text
    assert page.headers["cache-control"] == "no-store"
    assert "whsec_" not in browser.get("/terminal/activity").text  # shown once

    issued = connect_terminal(browser, role_id="full")
    r = browser.post("/api/terminal/audit", json={"rows": [_row()]}, headers=bearer(issued))
    assert r.status_code == 200 and r.json()["accepted"] == 1
    assert len(calls) == 1
    assert "not delivered" in browser.get("/terminal/activity").text
    # A batch that stores nothing posts nothing.
    browser.post("/api/terminal/audit", json={"rows": []}, headers=bearer(issued))
    assert len(calls) == 1

    token = dash.csrf(browser, "/terminal/activity")
    browser.post("/terminal/activity/webhook", data={"csrf": token, "action": "remove"})
    assert feature.webhook.get(OWNER_EMAIL) is None


# ---- commit trailer ---------------------------------------------------------------------

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def _git(repo: Path, *args: str, env: dict | None = None) -> str:
    base = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.com",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    return subprocess.run(  # noqa: S603 - a test repository
        ["git", "-C", str(repo), *args],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
        env={**base, **(env or {})},
    ).stdout


@needs_git
def test_trailer_install_chains_and_remove_restores(tmp_path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    hooks = repo / ".git" / "hooks"
    hooks.mkdir(exist_ok=True)
    existing = hooks / "prepare-commit-msg"
    existing.write_text('#!/bin/sh\necho "from the old hook" >> "$1"\n')
    existing.chmod(0o755)
    state.write_json("credentials.json", {"server": "https://botrbac.example.com"})

    assert main(["trailer", "install", "--repo", str(repo)]) == 0
    assert main(["trailer", "install", "--repo", str(repo)]) == 0  # idempotent
    assert trailer.ours(existing) and "from the old hook" in (hooks / trailer.BACKUP).read_text()

    session = "a" * 32
    (repo / "f").write_text("1")
    _git(repo, "add", "f")
    _git(repo, "commit", "-q", "-m", "first", env={"BOTRBAC_SESSION": session})
    message = _git(repo, "log", "-1", "--format=%B")
    assert "from the old hook" in message
    assert f"Botrbac-Session: https://botrbac.example.com/terminal/sessions/{session}" in message
    _git(repo, "commit", "-q", "--amend", "--no-edit", env={"BOTRBAC_SESSION": session})
    assert _git(repo, "log", "-1", "--format=%B").count("Botrbac-Session:") == 1

    # Outside a session, or with a session id that is not one: no trailer, commit works.
    (repo / "f").write_text("2")
    _git(repo, "commit", "-q", "-am", "second", env={"BOTRBAC_SESSION": "$(touch pwned)"})
    assert "Botrbac-Session" not in _git(repo, "log", "-1", "--format=%B")
    assert not (repo / "pwned").exists()

    assert main(["trailer", "remove", "--repo", str(repo)]) == 0
    assert not trailer.ours(existing) and "from the old hook" in existing.read_text()
    assert not (hooks / trailer.BACKUP).exists()
    assert main(["trailer", "remove", "--repo", str(repo)]) == 0  # nothing left to remove


@needs_git
def test_trailer_needs_a_site_and_a_repo(tmp_path, capsys) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    assert main(["trailer", "install", "--repo", str(repo)]) == 1  # not logged in
    assert "botrbac login" in capsys.readouterr().err
    state.write_json("credentials.json", {"server": "https://botrbac.example.com"})
    assert main(["trailer", "install", "--repo", str(tmp_path / "nope")]) == 1
    with pytest.raises(trailer.TrailerError):
        trailer.script("https://x.example.com/$(id)")

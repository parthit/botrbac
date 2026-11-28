"""Terminal: where botrbac's folder is, which cached policies it trusts, and the audit
file's permissions, concurrent syncs and `botrbac verify` after pruning."""

import json
import os
import sqlite3
import stat
import threading
import time

import pytest

from botrbac_cli import chain, coverage, hooks, identity, policy, signing, state
from botrbac_cli.api import Api
from botrbac_cli.main import main
from botrbac_cli.queue import AuditQueue
from botrbac_cli.sync import sync
from tests.terminal_helpers import FakeApi

KEY = signing.key_from_secret("test secret")
PUBLIC = signing.public_key_text(KEY)
WIDE = {"id": "full", "name": "Everything", "patterns": ["*"]}


@pytest.fixture(autouse=True)
def botrbac_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "user"))
    (tmp_path / "user").mkdir()
    monkeypatch.setenv("BOTRBAC_HOME", str(tmp_path / "botrbac"))
    monkeypatch.delenv(policy.SESSION_ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    yield tmp_path / "botrbac"
    state.set_home(None)


def _signed(issued_at: float | None = None, terminal: str = "t1", role=None) -> dict:
    body = {
        "email": "me@example.com",
        "terminal": {"id": terminal, "name": "laptop"},
        "role": role or {"id": "r", "name": "Coder", "patterns": ["github/get_*"]},
        "roles": [],
        "revoked_sessions": [],
        "issued_at": time.time() if issued_at is None else issued_at,
    }
    body["signature"] = signing.sign(KEY, body)
    return body


def _write_policy(body: dict) -> None:
    state.write_json("policy.json", {"policy": body, "fetched_at": time.time()})


def _login(server: str = "https://botrbac.com", key: str | None = PUBLIC) -> None:
    creds = {"server": server, "refresh_token": "r", "terminal_id": "t1"}
    if key:
        creds["policy_key"] = key
    state.write_json("credentials.json", creds, private=True)


def _decide(tool: str = "github/get_issue") -> policy.Decision:
    return policy.Enforcer().decide(tool)


# ---- BOTRBAC_HOME cannot redirect what botrbac installed ------------------------------


def test_hook_and_gateway_commands_name_the_folder(botrbac_home, tmp_path) -> None:
    home = str(botrbac_home.absolute())
    settings = tmp_path / ".claude" / "settings.json"
    hooks.install_claude_code(settings)
    command = json.loads(settings.read_text())["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert f"--home {home} check --agent claude-code" in command
    assert hooks.hook_command(False, agent="codex").endswith(f"--home {home} check --agent codex")
    entry = coverage.gateway_entry("cursor")
    assert entry["args"][-5:] == ["--home", home, "gateway", "--agent", "cursor"]
    assert coverage.is_gateway(entry)
    assert coverage.is_gateway({"command": "/usr/bin/botrbac", "args": ["--home", home, "gateway"]})
    # Installing again recognises its own entries and changes nothing.
    assert not hooks.install_claude_code(settings)["changed"]


def test_home_option_beats_an_inherited_botrbac_home(botrbac_home, tmp_path, monkeypatch) -> None:
    # The attack: an agent writes a wide-open policy into a folder of its own and runs a
    # child agent with BOTRBAC_HOME pointing there.
    evil = tmp_path / "x"
    evil.mkdir()
    (evil / "policy.json").write_text(
        json.dumps({"policy": {"role": {"patterns": ["*"]}}, "fetched_at": time.time()})
    )
    monkeypatch.setenv("BOTRBAC_HOME", str(evil))
    assert main(["--home", str(botrbac_home), "check", "--agent", "codex", "--tool", "x"]) != 0
    assert state.home() == botrbac_home.absolute()
    assert os.environ["BOTRBAC_HOME"] == str(botrbac_home.absolute())


def test_a_forged_policy_in_a_fresh_folder_is_refused(tmp_path, monkeypatch) -> None:
    evil = tmp_path / "x"
    evil.mkdir()
    (evil / "policy.json").write_text(
        json.dumps({"policy": {"role": {"patterns": ["*"]}}, "fetched_at": time.time()})
    )
    monkeypatch.setenv("BOTRBAC_HOME", str(evil))
    decision = _decide()
    assert not decision.allowed and "not logged in" in decision.reason


def test_unsigned_policy_from_the_default_server_is_refused() -> None:
    _login(key=None)
    _write_policy({"role": WIDE, "roles": []})
    decision = _decide()
    assert not decision.allowed and "changed on this computer" in decision.reason


def test_unsigned_policy_from_a_self_hosted_server_without_a_key_is_used() -> None:
    _login("https://rbac.example.org", key=None)
    _write_policy({"role": WIDE, "roles": []})
    assert _decide().allowed


@pytest.mark.parametrize("where", ["state", "terminal_key"])
def test_removing_the_key_from_credentials_does_not_switch_checks_off(where) -> None:
    identity.ensure()
    Api("https://rbac.example.org")._save(
        {"access_token": "a", "refresh_token": "r", "policy_key": PUBLIC, "terminal_id": "t1"}
    )
    assert state.read_json("state.json")["policy_key"] == PUBLIC
    assert state.read_json(identity.KEY_FILE)["policy_key"] == PUBLIC
    _write_policy(_signed())
    assert _decide().allowed
    # Strip the key from credentials.json and from all but one other file.
    creds = state.read_json("credentials.json")
    creds.pop("policy_key")
    state.write_json("credentials.json", creds, private=True)
    other = identity.KEY_FILE if where == "state" else "state.json"
    data = state.read_json(other)
    data.pop("policy_key")
    state.write_json(other, data)
    _write_policy({"role": WIDE, "roles": []})
    decision = _decide()
    assert not decision.allowed and "changed on this computer" in decision.reason


def test_a_key_swapped_in_credentials_is_refused() -> None:
    _login()
    identity.remember_policy_key(PUBLIC)
    other = signing.key_from_secret("the agent's own key")
    state.write_json(
        "credentials.json",
        {"server": "https://botrbac.com", "policy_key": signing.public_key_text(other)},
    )
    body = {"role": WIDE, "roles": [], "issued_at": time.time()}
    body["signature"] = signing.sign(other, body)
    _write_policy(body)
    assert not _decide().allowed


# ---- rollback ------------------------------------------------------------------------


class _PolicyApi:
    def __init__(self, body):
        self.body = body

    def policy(self):
        return self.body


def test_an_older_signed_policy_is_refused() -> None:
    _login()
    old = _signed(issued_at=time.time() - 3600, role={"id": "full", "patterns": ["*"]})
    new = _signed()
    assert policy.refresh(_PolicyApi(new)) is not None
    assert state.read_json("state.json")[policy.NEWEST] == new["issued_at"]
    assert not _decide("github/delete_repo").allowed
    _write_policy(old)  # put back an earlier, wider policy
    decision = _decide("github/delete_repo")
    assert not decision.allowed and "older" in decision.reason
    # A refresh that answers with the older one does not replace the newer cache either.
    _write_policy(new)
    policy.refresh(_PolicyApi(old))
    assert policy.load_cached()["policy"]["issued_at"] == new["issued_at"]


def test_a_policy_for_another_terminal_is_refused() -> None:
    _login()
    _write_policy(_signed(terminal="someone-else"))
    decision = _decide()
    assert not decision.allowed and "another terminal" in decision.reason


# ---- audit.db permissions ---------------------------------------------------------


def test_audit_files_and_folder_are_private(botrbac_home) -> None:
    botrbac_home.mkdir(mode=0o755)
    os.chmod(botrbac_home, 0o755)  # noqa: S103 - a folder made with a loose umask
    queue = AuditQueue()
    queue.add(decision="allow", tool="github/get_issue")
    assert stat.S_IMODE(botrbac_home.stat().st_mode) == 0o700
    for name in ("audit.db", "audit.db-wal", "audit.db-shm"):
        path = botrbac_home / name
        if path.exists():
            assert stat.S_IMODE(path.stat().st_mode) == 0o600, name
    queue.db.close()
    os.chmod(botrbac_home / "audit.db", 0o644)
    AuditQueue()
    assert stat.S_IMODE((botrbac_home / "audit.db").stat().st_mode) == 0o600


# ---- botrbac verify after pruning -------------------------------------------------


def test_verify_does_not_call_a_pruned_checkpoint_intact(botrbac_home, capsys) -> None:
    _login()
    queue = AuditQueue()
    rows = [queue.add(decision="allow", tool=f"github/t{i}") for i in range(3)]
    queue.mark_sent([r["event_id"] for r in rows])
    signed = chain.checkpoint_body("t1", rows[0]["seq"], rows[0]["row_hash"], time.time())
    signed["signature"] = signing.sign(KEY, signed)
    state.write_json("state.json", {**(state.read_json("state.json") or {}), "checkpoint": signed})
    assert main(["verify", "--offline"]) == 0
    assert "Record intact" in capsys.readouterr().out
    # Raise the prune mark past the checkpoint and drop the rows it covers.
    db = sqlite3.connect(botrbac_home / "audit.db")
    db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('pruned_through', '2')")
    db.execute("DELETE FROM rows WHERE seq <= 2")
    db.commit()
    db.close()
    code = main(["verify", "--offline"])
    out = capsys.readouterr().out
    assert "Record intact" not in out and "already pruned" in out
    assert code == 1  # fewer sent rows than pruning keeps: rows are missing


# ---- one sync at a time -----------------------------------------------------------


def test_two_syncs_never_upload_at_once() -> None:
    queue = AuditQueue()
    for i in range(4):
        queue.add(decision="allow", tool=f"github/t{i}")
    busy = {"now": 0, "most": 0}
    guard = threading.Lock()

    def slow(_body):
        with guard:
            busy["now"] += 1
            busy["most"] = max(busy["most"], busy["now"])
        time.sleep(0.05)
        with guard:
            busy["now"] -= 1
        return {}

    api = FakeApi(slow)
    threads = [threading.Thread(target=sync, args=(api, AuditQueue())) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert busy["most"] == 1
    sent = [r["event_id"] for b in api.bodies for r in b["rows"]]
    assert len(sent) == len(set(sent)) == 4


def test_servers_add_cmd_is_refused(capsys) -> None:
    assert main(["servers", "add", "cmd", "--url", "https://example.org/mcp"]) == 2
    assert "reserved" in capsys.readouterr().err


def test_a_fresh_policy_signed_with_another_key_is_reported_not_cached(capsys) -> None:
    _login()
    good = _signed()
    _write_policy(good)
    other = signing.key_from_secret("a different ENCRYPTION_KEY")
    stranger = _signed(role={"id": "w", "name": "Wide", "patterns": ["*"]})
    del stranger["signature"]
    stranger["signature"] = signing.sign(other, stranger)

    class Api:
        def policy(self):
            return stranger

    policy.refresh(Api())
    assert "run botrbac login again" in capsys.readouterr().err
    assert state.read_json("policy.json")["policy"] == good

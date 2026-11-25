"""Terminal: "Record commands" seals what agents ran so only the website can read it."""

import json
import time
import uuid

import pytest

from botrbac_cli import policy, sealing, state
from botrbac_cli.check import check
from botrbac_cli.gateway import Gateway
from botrbac_cli.queue import AuditQueue
from scoped_drive_mcp.store import MemoryStore
from scoped_drive_mcp.terminal.ingest import TerminalActivity, clean_row
from tests import dash
from tests.terminal_helpers import (
    bearer,
    cache_policy,
    connect_terminal,
    stub_upstream,
    terminal_app,
)

NOW = 1_800_000_000.0
SECRET = "ghp_" + "s" * 30
KEY = sealing.key_from_secret("test secret")
PUBLIC = sealing.public_key_text(KEY)


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("BOTRBAC_HOME", str(tmp_path / "botrbac"))
    monkeypatch.delenv(policy.SESSION_ENV, raising=False)
    return tmp_path / "botrbac"


def _bash(command: str) -> str:
    return json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})


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


# ---- sealing ------------------------------------------------------------------------


def test_seal_round_trip_and_binding() -> None:
    sealed = sealing.seal(PUBLIC, "event-1", f"curl -H 'Authorization: {SECRET}' x")
    assert SECRET not in sealed and sealed.startswith(sealing.PREFIX)
    assert SECRET in sealing.open_sealed(KEY, "event-1", sealed)
    with pytest.raises(sealing.SealError):  # moved onto another row
        sealing.open_sealed(KEY, "event-2", sealed)
    with pytest.raises(sealing.SealError):  # another site's key
        sealing.open_sealed(sealing.key_from_secret("other"), "event-1", sealed)
    tampered = sealed[:-6] + ("A" if sealed[-6] != "A" else "B") + sealed[-5:]
    with pytest.raises(sealing.SealError):
        sealing.open_sealed(KEY, "event-1", tampered)
    for junk in ("", "v1.", "v1.!!!", "plain text", "v1." + "A" * 40, 5):
        with pytest.raises(sealing.SealError):
            sealing.open_sealed(KEY, "event-1", junk)


def test_long_commands_are_cut_and_still_fit() -> None:
    text = "é" * (sealing.MAX_CHARS + 50)
    sealed = sealing.seal(PUBLIC, "e", text)
    assert len(sealed) <= sealing.MAX_SEALED
    opened = sealing.open_sealed(KEY, "e", sealed)
    assert opened.startswith("é" * sealing.MAX_CHARS) and "cut: 50 more characters" in opened


# ---- the CLI ------------------------------------------------------------------------


def test_off_by_default_nothing_recorded() -> None:
    cache_policy(["claude-code/*"], name="Full")
    assert check("claude-code", _bash(f"GH_TOKEN={SECRET} gh pr list"), None, False)[0]
    (row,) = AuditQueue().pending()
    assert "command" not in row and SECRET not in json.dumps(row)


def test_hook_seals_the_command_and_never_stores_it_in_the_clear(home) -> None:
    cache_policy(["claude-code/Bash", "claude-code/Write"], name="Coder")
    data = state.read_json("policy.json")
    data["policy"]["command_key"] = PUBLIC
    state.write_json("policy.json", data)

    command = f"GH_TOKEN={SECRET} gh pr list"
    assert check("claude-code", _bash(command), None, False)[0]
    write = {"tool_name": "Write", "tool_input": {"file_path": "notes.txt", "content": SECRET}}
    assert check("claude-code", json.dumps(write), None, False)[0]
    blocked = {"tool_name": "WebFetch", "tool_input": {"url": f"https://x/?k={SECRET}"}}
    assert not check("claude-code", json.dumps(blocked), None, False)[0]

    rows = AuditQueue().pending()
    assert len(rows) == 3
    opened = [sealing.open_sealed(KEY, r["event_id"], r["command"]) for r in rows]
    assert opened[0] == command
    assert json.loads(opened[1]) == write["tool_input"]
    assert SECRET in opened[2]  # blocked calls are recorded too
    # Nothing on this computer has it as text: not the queue file, not `botrbac log`.
    for name in ("audit.db", "audit.db-wal"):
        path = home / name
        if path.exists():
            assert SECRET.encode() not in path.read_bytes()
    assert all(SECRET not in json.dumps(r) for r in AuditQueue().recent(10))


def test_an_edited_key_is_not_used(home) -> None:
    """With a pinned policy key, a command_key added to the cache breaks the signature:
    the agent cannot point commands at a key of its own (and every tool is blocked)."""
    from botrbac_cli import signing

    server = signing.key_from_secret("server")
    cache_policy(["claude-code/*"], name="Full")
    data = state.read_json("policy.json")
    data["policy"].update(issued_at=time.time(), command_key=PUBLIC)
    data["policy"]["signature"] = signing.sign(server, data["policy"])
    state.write_json("policy.json", data)
    state.write_json("credentials.json", {"policy_key": signing.public_key_text(server)})
    assert policy.command_key() == PUBLIC  # signed by the server: used
    assert policy.Enforcer().decide("claude-code/Bash").allowed

    mine = sealing.public_key_text(sealing.key_from_secret("the agent's own"))
    data["policy"]["command_key"] = mine
    state.write_json("policy.json", data)
    assert policy.command_key() is None
    assert not policy.Enforcer().decide("claude-code/Bash").allowed


@pytest.mark.anyio
async def test_gateway_seals_tool_arguments() -> None:
    cache_policy(["github/*"], name="Full")
    data = state.read_json("policy.json")
    data["policy"]["command_key"] = PUBLIC
    state.write_json("policy.json", data)
    gw = Gateway(policy.Enforcer(), AuditQueue())
    gw.add(stub_upstream("github", "create_issue"))
    await gw.call("github__create_issue", {"title": "hi", "token": SECRET})
    (row,) = AuditQueue().pending()
    assert json.loads(sealing.open_sealed(KEY, row["event_id"], row["command"])) == {
        "title": "hi",
        "token": SECRET,
    }


# ---- the server ---------------------------------------------------------------------


def test_server_keeps_commands_only_while_recording_is_on() -> None:
    log = TerminalActivity(MemoryStore(), clock=lambda: NOW)
    good = _row()
    good["command"] = sealing.seal(PUBLIC, good["event_id"], "ls")
    moved = _row(command=good["command"])  # someone else's sealed command
    junk = _row(command="rm -rf / (plain text)")
    assert "command" not in clean_row(good, NOW)  # recording off: dropped
    assert clean_row(good, NOW, KEY)["command"] == good["command"]
    assert "command" not in clean_row(moved, NOW, KEY)
    assert "command" not in clean_row(junk, NOW, KEY)
    assert log.add("a@x.com", "t_1", "laptop", [good, junk], KEY)["accepted"] == 2
    assert not log.records_commands("a@x.com")
    log.set_records_commands("a@x.com", True)
    assert log.records_commands("a@x.com") and not log.records_commands("b@x.com")


def test_record_commands_over_http(world, memstore, oauth) -> None:
    app = terminal_app(world, memstore, oauth)
    c = dash.client(app)
    dash.login(c)
    issued = connect_terminal(c, role_id="full")
    page = c.get("/terminal/activity").text
    assert 'id="record-toggle"' in page and "Record commands" in page
    assert "command_key" not in c.get("/api/terminal/policy", headers=bearer(issued)).json()

    token = dash.csrf(c, "/terminal/activity")
    assert c.post("/terminal/activity/record", data={"record": "1"}).status_code == 403
    r = c.post("/terminal/activity/record", data={"csrf": token, "record": "1"})
    assert r.status_code == 303
    pol = c.get("/api/terminal/policy", headers=bearer(issued)).json()
    public = pol["command_key"]

    row = _row()
    row["command"] = sealing.seal(public, row["event_id"], f"echo {SECRET} | gh auth login")
    sent = c.post("/api/terminal/audit", json={"rows": [row]}, headers=bearer(issued))
    assert sent.json()["accepted"] == 1
    page = c.get("/terminal/activity").text
    assert f"echo {SECRET} | gh auth login" in page and "Stop recording commands" in page
    assert SECRET in c.get("/terminal/activity/export?format=csv").text
    assert SECRET in c.get("/terminal/activity/export?format=jsonl").text
    # Stored sealed, not as text.
    assert SECRET not in repr(memstore._values)

    token = dash.csrf(c, "/terminal/activity")
    c.post("/terminal/activity/record", data={"csrf": token, "record": "0"})
    assert "command_key" not in c.get("/api/terminal/policy", headers=bearer(issued)).json()
    late = _row()
    late["command"] = sealing.seal(public, late["event_id"], "sent after it was turned off")
    c.post("/api/terminal/audit", json={"rows": [late]}, headers=bearer(issued))
    page = c.get("/terminal/activity").text
    assert "sent after it was turned off" not in page
    assert SECRET in page  # what was recorded before stays

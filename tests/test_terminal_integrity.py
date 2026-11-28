"""Terminal: the audit rows' hash chain, signed checkpoints, `botrbac verify` and
how long rows are kept."""

import json
import sqlite3
import uuid

import pytest

from botrbac_cli import chain, policy, signing, state
from botrbac_cli.api import Api
from botrbac_cli.main import main
from botrbac_cli.queue import AuditQueue
from botrbac_cli.sync import sync
from scoped_drive_mcp.store import MemoryStore
from scoped_drive_mcp.terminal.feature import TerminalFeature
from scoped_drive_mcp.terminal.ingest import TerminalActivity
from tests import dash
from tests.conftest import BASE_URL, OWNER_EMAIL
from tests.terminal_helpers import FakeApi, bearer, connect_terminal, http_client, terminal_app

NOW = 1_800_000_000.0
DAY = 24 * 3600


@pytest.fixture(autouse=True)
def botrbac_home(tmp_path, monkeypatch):
    monkeypatch.setenv("BOTRBAC_HOME", str(tmp_path / "botrbac"))
    monkeypatch.delenv(policy.SESSION_ENV, raising=False)
    return tmp_path / "botrbac"


def _rows(n: int, start: int = 1, prev: str = chain.GENESIS, ts: float = NOW) -> list[dict]:
    """n chained rows, as a CLI makes them."""
    out = []
    for seq in range(start, start + n):
        row = {
            "event_id": uuid.uuid4().hex,
            "ts": ts,
            "agent": "claude-code",
            "tool": "claude-code/Read",
            "decision": "allow",
            "reason": "ok",
            "role": "full",
        }
        chain.link(row, seq, prev)
        prev = row["row_hash"]
        out.append(row)
    return out


def _log() -> TerminalActivity:
    return TerminalActivity(MemoryStore(), clock=lambda: NOW)


def _chain_of(log: TerminalActivity, email: str = "a@x.com") -> dict[str, str]:
    return {r["event_id"]: r["chain"] for r in log.recent(email)}


# ---- the chain helpers ---------------------------------------------------------------


def test_canonical_json_is_stable() -> None:
    assert chain.canonical_json({"b": 1.0, "a": "é", "c": [True, None]}) == (
        '{"a":"é","b":1,"c":[true,null]}'.encode()
    )
    row = _rows(1)[0]
    again = json.loads(json.dumps(row))  # what the server gets
    assert chain.row_hash(again) == row["row_hash"]
    assert row["prev_hash"] == "0" * 64 and row["seq"] == 1


def test_queue_chains_rows_and_upgrades_an_old_queue(botrbac_home) -> None:
    path = state.home() / "audit.db"
    old = sqlite3.connect(path)
    old.execute(
        "CREATE TABLE rows (event_id TEXT PRIMARY KEY, ts REAL NOT NULL, body TEXT NOT NULL,"
        " sent INTEGER NOT NULL DEFAULT 0)"
    )
    legacy = {"event_id": "a" * 32, "ts": NOW, "decision": "allow", "tool": "x/y"}
    old.execute(
        "INSERT INTO rows VALUES (?, ?, ?, 0)", (legacy["event_id"], NOW, json.dumps(legacy))
    )
    old.commit()
    old.close()

    queue = AuditQueue()
    first = queue.add(decision="allow", tool="claude-code/Read")
    second = queue.add(decision="deny", tool="claude-code/Write", command="rm -rf /")
    assert first["seq"] == 1 and first["prev_hash"] == chain.GENESIS
    assert second["seq"] == 2 and second["prev_hash"] == first["row_hash"]
    assert chain.row_hash(second) == second["row_hash"]
    # The row from before the chain goes first, unchained; then in seq order.
    assert [r.get("seq") for r in queue.pending()] == [None, 1, 2]
    # Another process opening the same file goes on from the same tip.
    assert AuditQueue().add(decision="allow", tool="x/y")["seq"] == 3
    rows, pruned, tip = queue.chain_rows()
    assert chain.walk(rows, pruned, tip)["problems"] == [] and (pruned, tip) == (0, 3)


# ---- the server's check ---------------------------------------------------------------


def test_chain_continues_across_batches() -> None:
    log = _log()
    rows = _rows(5)
    assert log.add("a@x.com", "t_1", "laptop", rows[:2])["accepted"] == 2
    # Out of order inside one batch is fine: sorted by seq first.
    assert log.add("a@x.com", "t_1", "laptop", [rows[4], rows[2], rows[3]])["accepted"] == 3
    assert set(_chain_of(log).values()) == {"ok"}
    stored = log.recent("a@x.com")
    assert {r["seq"] for r in stored} == {1, 2, 3, 4, 5}
    state_ = log.chains.state("a@x.com", "t_1")
    assert state_["seq"] == 5 and state_["missing"] == 0 and state_["forks"] == 0
    assert log.chains.tip("a@x.com", "t_1") == (5, rows[4]["row_hash"])
    # Each terminal has its own chain.
    assert log.add("a@x.com", "t_2", "desk", _rows(1))["accepted"] == 1
    assert log.chains.tip("a@x.com", "t_2")[0] == 1


def test_gap_is_detected_and_a_late_row_fills_it() -> None:
    log = _log()
    rows = _rows(5)
    log.add("a@x.com", "t_1", "laptop", rows[:2])
    log.add("a@x.com", "t_1", "laptop", rows[3:])  # row 3 deleted, or not sent yet
    marks = _chain_of(log)
    assert marks[rows[3]["event_id"]] == "gap" and marks[rows[4]["event_id"]] == "ok"
    assert log.chains.state("a@x.com", "t_1")["missing"] == 1
    # It turns up later (a refused row sent again): it links both ways.
    log.add("a@x.com", "t_1", "laptop", [rows[2]])
    assert _chain_of(log)[rows[2]["event_id"]] == "ok"
    assert log.chains.state("a@x.com", "t_1")["missing"] == 0


def test_forks_are_detected() -> None:
    log = _log()
    rows = _rows(3)
    log.add("a@x.com", "t_1", "laptop", rows[:2])
    # Another row claiming seq 2.
    other = _rows(1, start=2, prev=rows[0]["row_hash"])[0]
    # The next row, but not linked to the row before it.
    unlinked = _rows(1, start=3, prev="1" * 64)[0]
    # A row edited after it was hashed.
    edited = _rows(1, start=4, prev=unlinked["row_hash"])[0]
    edited["tool"] = "claude-code/Write"
    log.add("a@x.com", "t_1", "laptop", [other, unlinked, edited])
    marks = _chain_of(log)
    assert marks[other["event_id"]] == "fork"
    assert marks[unlinked["event_id"]] == "fork"
    assert marks[edited["event_id"]] == "fork"
    assert log.chains.state("a@x.com", "t_1")["forks"] == 3
    # The tool was cut or kept by clean_row, but the hash covered what was sent.
    assert marks[rows[0]["event_id"]] == "ok"


def test_duplicates_do_not_raise_alarms() -> None:
    log = _log()
    rows = _rows(3)
    log.add("a@x.com", "t_1", "laptop", rows[:2])
    result = log.add("a@x.com", "t_1", "laptop", rows)  # the same batch sent again, and more
    assert result == {"accepted": 1, "duplicates": 2, "rejected": 0}
    assert set(_chain_of(log).values()) == {"ok"}
    st = log.chains.state("a@x.com", "t_1")
    assert st["forks"] == 0 and st["missing"] == 0 and st["seq"] == 3


def test_rows_from_an_old_cli_are_unchained() -> None:
    log = _log()
    row = _rows(1)[0]
    for name in ("seq", "prev_hash", "row_hash"):
        row.pop(name)
    log.add("a@x.com", "t_1", "laptop", [row])
    (stored,) = log.recent("a@x.com")
    assert stored["chain"] == "unchained" and "seq" not in stored
    assert log.chains.tip("a@x.com", "t_1") is None


def test_a_chain_first_seen_past_row_one_starts_there() -> None:
    """A computer that logs in again is a new terminal; its seq goes on."""
    log = _log()
    rows = _rows(3, start=40, prev="2" * 64)
    log.add("a@x.com", "t_9", "laptop", rows)
    assert set(_chain_of(log).values()) == {"ok"}
    assert log.chains.state("a@x.com", "t_9")["start"] == 40


# ---- retention ---------------------------------------------------------------------------


def test_retention_trims_by_age_and_caps_rows() -> None:
    clock = {"now": NOW}
    log = TerminalActivity(
        MemoryStore(), clock=lambda: clock["now"], retention_days=10, max_rows=150
    )
    old = _rows(30)
    log.add("a@x.com", "t_1", "laptop", old)
    clock["now"] = NOW + 5 * DAY
    middle = _rows(30, start=31, prev=old[-1]["row_hash"], ts=clock["now"])
    log.add("a@x.com", "t_1", "laptop", middle)
    assert len(log.recent("a@x.com")) == 60
    clock["now"] = NOW + 12 * DAY  # the first 30 are now older than 10 days
    new = _rows(5, start=61, prev=middle[-1]["row_hash"], ts=clock["now"])
    log.add("a@x.com", "t_1", "laptop", new)
    log.trim("a@x.com", force=True)
    kept = log.recent("a@x.com")
    assert len(kept) == 35 and min(r["seq"] for r in kept) == 31
    assert len(list(log.everything("a@x.com"))) == 35
    # The hard cap, whatever the age.
    more = _rows(140, start=66, prev=new[-1]["row_hash"], ts=clock["now"])
    log.add("a@x.com", "t_1", "laptop", more[:100])
    log.add("a@x.com", "t_1", "laptop", more[100:])
    assert len(log.recent("a@x.com", limit=1000)) == 150
    # Everything too old: the list is emptied.
    clock["now"] = NOW + 40 * DAY
    log.trim("a@x.com", force=True)
    assert log.recent("a@x.com") == []


def test_recent_is_bounded_but_export_has_everything(world, memstore, oauth) -> None:
    app = terminal_app(world, memstore, oauth)
    c = dash.client(app)
    dash.login(c)
    issued = connect_terminal(c, role_id="full")
    rows = _rows(2100, ts=NOW - 100)
    activity = app.state.terminal.activity
    activity.clock = lambda: NOW
    for i in range(0, len(rows), 500):
        assert (
            c.post(
                "/api/terminal/audit", json={"rows": rows[i : i + 500]}, headers=bearer(issued)
            ).status_code
            == 200
        )
    assert len(activity.recent(OWNER_EMAIL)) == 2000
    jsonl = c.get("/terminal/activity/export?format=jsonl").text.splitlines()
    assert len(jsonl) == 2100
    assert {json.loads(line)["chain"] for line in jsonl} == {"ok"}
    csv_text = c.get("/terminal/activity/export?format=csv").text
    assert csv_text.splitlines()[0].endswith(",seq,chain,row_hash")


# ---- checkpoints ---------------------------------------------------------------------


def test_checkpoint_is_signed_and_returned(world, memstore, oauth) -> None:
    app = terminal_app(world, memstore, oauth)
    c = dash.client(app)
    dash.login(c)
    issued = connect_terminal(c)
    key = issued["policy_key"]
    assert c.get("/api/terminal/checkpoint", headers=bearer(issued)).json() == {"checkpoint": None}
    rows = _rows(3)
    answer = c.post("/api/terminal/audit", json={"rows": rows}, headers=bearer(issued)).json()
    checkpoint = answer["checkpoint"]
    assert checkpoint["seq"] == 3 and checkpoint["row_hash"] == rows[-1]["row_hash"]
    assert checkpoint["terminal_id"] == issued["terminal_id"]
    assert chain.verify_checkpoint(key, checkpoint)
    fetched = c.get("/api/terminal/checkpoint", headers=bearer(issued)).json()["checkpoint"]
    assert chain.verify_checkpoint(key, fetched)
    # Changed, or signed by another site: refused.
    assert not chain.verify_checkpoint(key, {**checkpoint, "seq": 4})
    other = signing.public_key_text(signing.key_from_secret("another site"))
    assert not chain.verify_checkpoint(other, checkpoint)
    # A signed policy is not a checkpoint.
    policy_body = c.get("/api/terminal/policy", headers=bearer(issued)).json()
    assert not chain.verify_checkpoint(key, policy_body)

    page = c.get("/terminal/activity").text
    assert "/terminal/activity/checkpoints" in page
    download = c.get("/terminal/activity/checkpoints")
    assert download.headers["content-type"].startswith("application/json")
    body = download.json()
    assert body["policy_key"] == key
    assert chain.verify_checkpoint(key, body["terminals"][0]["checkpoint"])
    assert "record intact" in c.get("/terminal").text


def test_activity_page_marks_rows_that_are_not_ok(world, memstore, oauth) -> None:
    app = terminal_app(world, memstore, oauth)
    c = dash.client(app)
    dash.login(c)
    issued = connect_terminal(c)
    rows = _rows(4)
    c.post("/api/terminal/audit", json={"rows": [rows[0], rows[2]]}, headers=bearer(issued))
    page = c.get("/terminal/activity").text
    assert "rows missing before" in page
    assert "1 row missing" in c.get("/terminal").text


def test_feature_without_a_key_sends_unsigned_checkpoints() -> None:
    feature = TerminalFeature(MemoryStore())
    feature.activity.add("a@x.com", "t_1", "laptop", _rows(1))
    checkpoint = feature.checkpoint_for("a@x.com", "t_1")
    assert checkpoint["seq"] == 1 and "signature" not in checkpoint


# ---- botrbac sync and botrbac verify ----------------------------------------------------


@pytest.fixture
def connected(world, memstore, oauth, monkeypatch):
    """A terminal logged in with credentials.json written, as `botrbac login` does."""
    from botrbac_cli import main as cli

    app = terminal_app(world, memstore, oauth)
    browser = dash.client(app)
    dash.login(browser)
    issued = connect_terminal(browser, role_id="full")
    client = http_client(app)
    api = Api(BASE_URL, client=client)
    api._save(issued)
    monkeypatch.setattr(cli, "Api", lambda server=None: Api(server, client=client))
    return app, api


def test_sync_keeps_the_checkpoint_and_verify_passes(connected, capsys) -> None:
    app, api = connected
    queue = AuditQueue()
    for tool in ("claude-code/Read", "claude-code/Edit", "claude-code/Bash"):
        queue.add(decision="allow", tool=tool, agent="claude-code", role="full")
    assert sync(api, queue)["sent"] == 3
    kept = state.read_json("state.json")["checkpoint"]
    assert kept["seq"] == 3
    rows = app.state.terminal.activity.recent(OWNER_EMAIL)
    assert {r["chain"] for r in rows} == {"ok"}
    queue.add(decision="allow", tool="claude-code/Read")  # not sent yet: still fine
    assert main(["verify"]) == 0
    out = capsys.readouterr().out
    assert "✓ row 3 matches the website's signed checkpoint" in out and "Record intact." in out


def _tamper(sql: str, *args) -> None:
    db = sqlite3.connect(state.home() / "audit.db")
    db.execute(sql, args)
    db.commit()
    db.close()


def test_verify_finds_a_tampered_audit_db(connected, capsys) -> None:
    _app, api = connected
    queue = AuditQueue()
    for _ in range(4):
        queue.add(decision="deny", tool="claude-code/Bash", agent="claude-code")
    sync(api, queue)

    # Edit a row: allow instead of deny.
    (body,) = (
        sqlite3.connect(state.home() / "audit.db")
        .execute("SELECT body FROM rows WHERE seq = 2")
        .fetchone()
    )
    row = json.loads(body)
    row["decision"] = "allow"
    _tamper("UPDATE rows SET body = ? WHERE seq = 2", json.dumps(row))
    assert main(["verify", "--offline"]) == 1
    assert "row 2: edited" in capsys.readouterr().out

    # Delete one in the middle: the chain shows the hole.
    _tamper("DELETE FROM rows WHERE seq = 3")
    assert main(["verify", "--offline"]) == 1
    assert "row 4: row 3 is missing" in capsys.readouterr().out

    # Delete the newest, the row the website signed.
    _tamper("DELETE FROM rows WHERE seq = 4")
    assert main(["verify", "--offline"]) == 1
    out = capsys.readouterr().out
    assert "the website signed row 4" in out and "not in this computer's record" in out
    assert "rows 3-4 are missing (the newest)" in out


def test_verify_refuses_a_forged_checkpoint(connected, capsys) -> None:
    _app, api = connected
    queue = AuditQueue()
    queue.add(decision="allow", tool="claude-code/Read")
    sync(api, queue)
    data = state.read_json("state.json")
    data["checkpoint"]["row_hash"] = "f" * 64
    state.write_json("state.json", data)
    assert main(["verify", "--offline"]) == 1
    assert "signature does not match" in capsys.readouterr().out


def test_remember_checkpoint_ignores_older_ones() -> None:
    chain.remember_checkpoint({"checkpoint": {"terminal_id": "t", "seq": 5, "row_hash": "a"}})
    chain.remember_checkpoint({"checkpoint": {"terminal_id": "t", "seq": 4, "row_hash": "b"}})
    assert state.read_json("state.json")["checkpoint"]["seq"] == 5
    chain.remember_checkpoint({"accepted": 1})  # an old server: nothing changes
    assert state.read_json("state.json")["checkpoint"]["seq"] == 5


def test_sync_with_a_server_that_sends_no_checkpoint() -> None:
    queue = AuditQueue()
    queue.add(decision="allow", tool="claude-code/Read")
    assert sync(FakeApi(), queue)["sent"] == 1
    assert "checkpoint" not in (state.read_json("state.json", {}) or {})


def test_verify_allows_rows_pruned_after_sending(monkeypatch) -> None:
    from botrbac_cli import queue as queue_module

    monkeypatch.setattr(queue_module, "KEEP_SENT", 3)
    queue = AuditQueue()
    rows = [queue.add(decision="allow", tool="claude-code/Read") for _ in range(6)]
    queue.mark_sent([r["event_id"] for r in rows[:5]])
    kept, pruned, tip = queue.chain_rows()
    assert [r["seq"] for r in kept] == [3, 4, 5, 6] and pruned == 2 and tip == 6
    assert chain.walk(kept, pruned, tip)["problems"] == []

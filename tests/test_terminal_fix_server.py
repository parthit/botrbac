"""Terminal server fixes: per-terminal row budget, blocks kept apart, upload lock,
session revocation after rows age out, refresh-token reuse, edited resends, exports
during uploads, and stricter field checks."""

import asyncio
import json
import uuid

import pytest

from botrbac_cli import chain, identity, policy
from botrbac_cli.sync import PERMANENT
from scoped_drive_mcp.audit import actor_tag
from scoped_drive_mcp.store import MemoryStore
from scoped_drive_mcp.terminal import feature as feature_module
from scoped_drive_mcp.terminal import integrity, present, provenance
from scoped_drive_mcp.terminal.device import Terminals
from scoped_drive_mcp.terminal.feature import TerminalFeature, safe_site
from scoped_drive_mcp.terminal.ingest import (
    DENIES_KEY,
    LOCK_KEY,
    SEEN_KEY,
    Busy,
    OverBudget,
    TerminalActivity,
    clean_row,
)
from scoped_drive_mcp.terminal.roles import TerminalRoles
from tests import dash
from tests.conftest import OWNER_EMAIL, FakeClock, make_settings
from tests.terminal_helpers import bearer, connect_terminal, terminal_app

NOW = 1_800_000_000.0
DAY = 24 * 3600
ME = "me@example.com"


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("BOTRBAC_HOME", str(tmp_path / "botrbac"))
    monkeypatch.delenv(policy.SESSION_ENV, raising=False)
    return tmp_path / "botrbac"


@pytest.fixture
def site(world, memstore, oauth):
    app = terminal_app(world, memstore, oauth)
    browser = dash.client(app)
    dash.login(browser)
    return app, browser


def _row(**over):
    row = {
        "event_id": uuid.uuid4().hex,
        "ts": NOW,
        "agent": "claude-code",
        "tool": "claude-code/Read",
        "decision": "allow",
        "reason": "ok",
        "role": "full",
    }
    row.update(over)
    return row


def _log(clock=None, **kw) -> TerminalActivity:
    clock = clock or (lambda: NOW)
    return TerminalActivity(MemoryStore(clock=clock), clock=clock, sleep=lambda _s: None, **kw)


# ---- 1. one terminal cannot flush the log ---------------------------------------------


def test_daily_row_budget_per_terminal() -> None:
    now = {"t": NOW}
    log = _log(clock=lambda: now["t"], rows_per_day=150)
    assert log.add("a@x.com", "t_1", "laptop", [_row() for _ in range(100)])["accepted"] == 100
    # Under the budget when it starts: the whole batch is kept.
    assert log.add("a@x.com", "t_1", "laptop", [_row() for _ in range(100)])["accepted"] == 100
    with pytest.raises(OverBudget) as exc:
        log.add("a@x.com", "t_1", "laptop", [_row()])
    assert 0 < exc.value.retry_after <= DAY
    # Another terminal of the same person has its own budget.
    assert log.add("a@x.com", "t_2", "desk", [_row()])["accepted"] == 1
    # The next UTC day starts afresh.
    now["t"] = NOW + DAY
    assert log.add("a@x.com", "t_1", "laptop", [_row(ts=now["t"])])["accepted"] == 1


def test_budget_and_busy_answers_are_retried_by_the_cli() -> None:
    assert 429 not in PERMANENT and 409 not in PERMANENT


def test_over_budget_is_429_over_http(site) -> None:
    app, browser = site
    issued = connect_terminal(browser, role_id="full")
    app.state.terminal.activity.rows_per_day = 100
    headers = bearer(issued)
    rows = [_row(ts=NOW - 10) for _ in range(100)]
    assert (
        browser.post("/api/terminal/audit", json={"rows": rows}, headers=headers).status_code == 200
    )
    r = browser.post("/api/terminal/audit", json={"rows": [_row()]}, headers=headers)
    assert r.status_code == 429
    assert r.json()["error"] == "row_budget_exceeded"
    assert int(r.headers["retry-after"]) > 0


def test_blocked_rows_survive_a_flood_of_allowed_rows() -> None:
    log = _log(max_rows=100)
    deny = _row(decision="deny", reason="not in role full", ts=NOW - 50)
    log.add("a@x.com", "t_1", "laptop", [deny])
    for _ in range(3):
        log.add("a@x.com", "t_1", "laptop", [_row() for _ in range(100)])
    assert len(log.store.lrange("term:activity:a@x.com", 0, -1)) == 100
    recent = log.recent("a@x.com")
    assert [r["event_id"] for r in recent if r["decision"] == "deny"] == [deny["event_id"]]
    exported = list(log.everything("a@x.com"))
    assert [r["event_id"] for r in exported].count(deny["event_id"]) == 1
    assert len(exported) == 101
    # The list of blocks is capped too.
    for _ in range(2):
        log.add("a@x.com", "t_1", "laptop", [_row(decision="deny", reason="x") for _ in range(100)])
    assert len(log.store.lrange(DENIES_KEY.format(email="a@x.com"), 0, -1)) == 100


def test_seen_ids_expire() -> None:
    now = {"t": NOW}
    log = _log(clock=lambda: now["t"], retention_days=40)
    row = _row()
    log.add("a@x.com", "t_1", "laptop", [row])
    key = SEEN_KEY.format(email="a@x.com", event_id=row["event_id"])
    assert log.store.get(key)
    now["t"] = NOW + 41 * DAY
    assert log.store.get(key) is None


def test_rows_per_day_setting() -> None:
    assert make_settings().terminal_activity_rows_per_day == 10_000
    assert make_settings(terminal_activity_rows_per_day=500).terminal_activity_rows_per_day == 500
    feature = TerminalFeature(MemoryStore(), activity_rows_per_day=500)
    assert feature.activity.rows_per_day == 500


# ---- 2. revoking a session whose rows aged out ----------------------------------------


def test_session_stub_when_start_row_aged_out() -> None:
    log = _log()
    sid = "s" * 16
    log.add(
        "a@x.com",
        "t_1",
        "laptop",
        [
            _row(session_id=sid, role="Reader"),
            _row(session_id=sid, decision="deny", reason="x", ts=NOW + 1),
        ],
    )
    assert log.session("a@x.com", sid) is None
    tree = log.session("a@x.com", sid, stub=True)
    assert tree["aged_out"] and tree["start"]["aged_out"]
    assert tree["calls"] == 2 and len(tree["blocked"]) == 1
    assert tree["start"]["terminal"] == "laptop" and tree["start"]["role"] == "Reader"
    assert log.session("a@x.com", "bad id", stub=True) is None


def test_revoke_a_session_not_in_the_newest_rows(site) -> None:
    app, browser = site
    issued = connect_terminal(browser)
    sid = "z" * 32
    token = dash.csrf(browser, f"/terminal/sessions/{sid}")
    r = browser.post(f"/terminal/sessions/{sid}/revoke", data={"csrf": token})
    assert r.status_code == 303
    assert app.state.terminal.activity.revoked_sessions(OWNER_EMAIL) == [sid]
    page = browser.get(f"/terminal/sessions/{sid}")
    assert page.status_code == 200 and 'id="revoke-session"' not in page.text
    policy_body = browser.get("/api/terminal/policy", headers=bearer(issued)).json()
    assert policy_body["revoked_sessions"] == [sid]
    # Malformed ids are still refused.
    token = dash.csrf(browser, "/terminal")
    bad = browser.post("/terminal/sessions/bad/revoke", data={"csrf": token})
    assert bad.status_code == 404
    assert app.state.terminal.activity.revoked_sessions(OWNER_EMAIL) == [sid]


# ---- 3. a key registered at refresh lands in the owner's Activity --------------------------


def test_key_registered_is_logged_as_the_terminals_owner(site, capsys) -> None:
    app, browser = site
    issued = connect_terminal(browser)
    capsys.readouterr()
    r = browser.post(
        "/api/terminal/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": issued["refresh_token"],
            "public_key": identity.ensure()["public_key"],
        },
    )
    assert r.status_code == 200
    lines = [json.loads(x) for x in capsys.readouterr().out.splitlines() if x.startswith("{")]
    (line,) = [x for x in lines if x.get("action") == "terminal_key_registered"]
    assert line["actor"] == actor_tag(OWNER_EMAIL)


# ---- 4. refresh-token reuse ends the terminal's tokens --------------------------------------


def _terminals() -> Terminals:
    store = MemoryStore()
    return Terminals(store, TerminalRoles(store), lambda e: True, FakeClock())


def test_refresh_reuse_ends_the_token_family(capsys) -> None:
    t = _terminals()
    started = t.start({})
    terminal = t.approve(ME, started["user_code"], "full", "x")
    first = t.poll(started["device_code"])
    second = t.refresh(first["refresh_token"])
    assert t.resolve(second["access_token"]) is not None
    capsys.readouterr()
    assert t.refresh(first["refresh_token"]) is None  # reused
    assert t.resolve(second["access_token"]) is None
    assert t.resolve(first["access_token"]) is None
    assert t.refresh(second["refresh_token"]) is None  # must log in again
    assert t.get(terminal.id).refresh_reuse["at"]
    assert t.refresh(first["refresh_token"]) is None  # again: noted once an hour
    out = capsys.readouterr().out
    assert out.count('"terminal_refresh_reuse"') == 1
    assert t.for_person(ME)  # still listed, so the owner sees and can disconnect it


def test_token_endpoint_is_limited_per_terminal(site, monkeypatch) -> None:
    _app, browser = site
    monkeypatch.setattr(feature_module, "REFRESH_LIMIT", 3)
    issued = connect_terminal(browser)
    body = {"grant_type": "refresh_token", "refresh_token": issued["refresh_token"]}
    codes = [browser.post("/api/terminal/token", data=body).status_code for _ in range(5)]
    assert codes[0] == 200 and codes[1] == 400 and codes[3:] == [429, 429]
    # A token never issued is not counted against any terminal.
    junk = {"grant_type": "refresh_token", "refresh_token": "brt_rt_nope"}
    assert browser.post("/api/terminal/token", data=junk).status_code == 400


# ---- 5. one upload at a time per terminal ---------------------------------------------


def test_upload_lock() -> None:
    log = _log()
    log.store.set_if_absent(LOCK_KEY.format(terminal_id="t_1"), "other", ex=60)
    with pytest.raises(Busy):
        log.add("a@x.com", "t_1", "laptop", [_row()])
    assert log.recent("a@x.com") == []
    log.add("a@x.com", "t_2", "desk", [_row()])  # another terminal is not held up
    log.store.delete(LOCK_KEY.format(terminal_id="t_1"))
    assert log.add("a@x.com", "t_1", "laptop", [_row()])["accepted"] == 1
    assert log.store.get(LOCK_KEY.format(terminal_id="t_1")) is None  # released


def test_busy_is_409_over_http(site, monkeypatch) -> None:
    app, browser = site
    issued = connect_terminal(browser, role_id="full")
    activity = app.state.terminal.activity
    monkeypatch.setattr(activity, "sleep", lambda _s: None)
    activity.store.set_if_absent(LOCK_KEY.format(terminal_id=issued["terminal_id"]), "x", ex=60)
    r = browser.post("/api/terminal/audit", json={"rows": [_row()]}, headers=bearer(issued))
    assert r.status_code == 409 and r.json()["error"] == "busy"


# ---- 6. exports during uploads ----------------------------------------------------------


class _PushingStore(MemoryStore):
    """Pushes rows in at the head of the list while an export reads it."""

    def __init__(self, pushes):
        super().__init__(clock=lambda: NOW)
        self.pushes = pushes

    def lrange(self, key, start, stop):
        out = super().lrange(key, start, stop)
        if start > 0 and self.pushes:
            for _ in range(5):
                self.lpush(key, json.dumps(self.pushes.pop()))
        return out


def test_export_reads_each_row_once_during_uploads() -> None:
    late = [{"event_id": f"late{i:08d}", "received": NOW + 5, "ts": NOW} for i in range(50)]
    store = _PushingStore(late)
    key = "term:activity:a@x.com"
    for i in range(30):
        store.lpush(key, json.dumps({"event_id": f"row{i:08d}", "received": NOW, "ts": NOW}))
    rows = list(integrity.read_all(store, key, NOW - DAY, 1000, chunk=10, until=NOW))
    ids = [r["event_id"] for r in rows]
    assert len(ids) == len(set(ids)) == 30
    assert not any(i.startswith("late") for i in ids)


# ---- 7. blocking work off the event loop -------------------------------------------------


def test_open_commands_runs_off_the_event_loop(site, monkeypatch) -> None:
    app, browser = site
    issued = connect_terminal(browser, role_id="full")
    browser.post("/api/terminal/audit", json={"rows": [_row(ts=NOW - 5)]}, headers=bearer(issued))
    feature = app.state.terminal
    real = feature.open_commands
    on_loop = []

    def spy(rows):
        try:
            asyncio.get_running_loop()
            on_loop.append(True)
        except RuntimeError:
            on_loop.append(False)
        return real(rows)

    monkeypatch.setattr(feature, "open_commands", spy)
    assert browser.get("/terminal/activity/export?format=otlp").status_code == 200
    assert browser.get("/terminal/activity").status_code == 200
    assert on_loop and not any(on_loop)


# ---- 8. an edited resend is a fork, not a duplicate -------------------------------------


def test_edited_resend_is_counted_as_a_fork() -> None:
    log = _log()
    row = chain.link(_row(), 1, chain.GENESIS)
    assert log.add("a@x.com", "t_1", "laptop", [row])["accepted"] == 1
    assert log.add("a@x.com", "t_1", "laptop", [dict(row)])["duplicates"] == 1
    edited = chain.link({**row, "reason": "something else"}, 1, chain.GENESIS)
    result = log.add("a@x.com", "t_1", "laptop", [edited])
    assert result["edited"] == 1 and result["duplicates"] == 0
    assert log.chains.state("a@x.com", "t_1")["forks"] == 1
    assert len(log.recent("a@x.com")) == 1


# ---- 9. block reasons keep their commas -----------------------------------------------------


def test_reason_keeps_program_list_and_substitution() -> None:
    reason = "running cmd/curl, cmd/wget is not in role 'dev'"
    row = clean_row(_row(decision="deny", reason=reason), NOW)
    assert row["reason"] == "running cmd/curl, cmd/wget is not in role 'dev'"
    why = present.blocked_because(row["reason"])
    assert why["fix"] == "add cmd/curl, cmd/wget to the role"
    assert "programs curl, wget" in why["text"]
    # Rows stored before commas were kept.
    old = present.blocked_because("running cmd/curl cmd/wget is not in role 'dev'")
    assert old["fix"] == "add cmd/curl, cmd/wget to the role"
    sub = clean_row(
        _row(
            decision="deny",
            reason="botrbac does not run commands that use command substitution $(…)",
        ),
        NOW,
    )
    assert sub["reason"].endswith("$(…)")
    assert "<" not in clean_row(_row(reason="<b>x</b>"), NOW)["reason"]


# ---- 10. ids with a trailing newline -------------------------------------------------------


def test_ids_with_trailing_newline_are_refused() -> None:
    assert clean_row(_row(event_id="a" * 16 + "\n"), NOW) is None
    row = clean_row(_row(session_id="b" * 16 + "\n", policy_version="abc\n"), NOW)
    assert "session_id" not in row and "policy_version" not in row
    fields = provenance.clean_fields(
        {"prompt_id": "p1\n", "branch": "main\n", "head": "abcdef1\n", "repo": "github.com/a/b\n"},
        "e" * 16,
        "allow",
        None,
    )
    assert fields == {}
    assert not _log().revoke_session("a@x.com", "c" * 16 + "\n")


# ---- 11. http only for this computer ----------------------------------------------------------


def test_safe_site_allows_http_only_for_localhost() -> None:
    default = feature_module.DEFAULT_SERVER
    assert safe_site("http://evil.example") == default
    assert safe_site("http://evil.example:8000/x") == default
    assert safe_site("http://localhost:8000") == "http://localhost:8000"
    assert safe_site("http://127.0.0.1:8000/") == "http://127.0.0.1:8000"
    assert safe_site("https://bots.example.com") == "https://bots.example.com"
    assert safe_site("https://bots.example.com\n") == default
    assert safe_site("http://localhost.evil.example") == default

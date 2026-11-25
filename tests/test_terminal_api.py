"""Terminal: policy and audit API, activity page and export."""

import uuid

import pytest

from scoped_drive_mcp.store import MemoryStore
from scoped_drive_mcp.terminal.ingest import BATCH_MAX, TerminalActivity, clean_row
from tests import dash
from tests.conftest import OWNER_EMAIL
from tests.terminal_helpers import bearer, connect_terminal, terminal_app

NOW = 1_800_000_000.0


def _row(**over):
    row = {
        "event_id": uuid.uuid4().hex,
        "ts": NOW,
        "agent": "claude-code",
        "tool": "github/create_issue",
        "decision": "allow",
        "reason": "ok",
        "role": "full",
    }
    row.update(over)
    return row


def test_clean_row_caps_and_rejects() -> None:
    assert clean_row(_row(event_id="short"), NOW) is None
    assert clean_row(_row(decision="maybe"), NOW) is None
    assert clean_row(_row(tool="not a tool"), NOW) is None
    assert clean_row("x", NOW) is None
    row = clean_row(_row(reason="<script>" + "x" * 500, ts="soon", secret="s"), NOW)
    assert "<" not in row["reason"] and len(row["reason"]) == 300
    assert row["ts"] == NOW and "secret" not in row
    start = clean_row(
        _row(decision="session", program="/usr/bin/claude --api-key=abc", session_id="s" * 10),
        NOW,
    )
    assert start["program"] == "claude" and start["tool"] == ""
    assert clean_row(_row(decision="session"), NOW) is None  # needs a session id


def test_dedupe_and_batch_limit() -> None:
    log = TerminalActivity(MemoryStore(), clock=lambda: NOW)
    rows = [_row(), _row()]
    assert log.add("a@x.com", "t_1", "laptop", rows) == {
        "accepted": 2,
        "duplicates": 0,
        "rejected": 0,
    }
    assert log.add("a@x.com", "t_1", "laptop", rows)["duplicates"] == 2
    assert len(log.recent("a@x.com")) == 2
    assert log.recent("b@x.com") == []
    with pytest.raises(ValueError):
        log.add("a@x.com", "t_1", "laptop", [_row()] * (BATCH_MAX + 1))


def test_session_tree() -> None:
    log = TerminalActivity(MemoryStore(), clock=lambda: NOW)
    root, child = "root" + "a" * 8, "child" + "b" * 8
    log.add(
        "a@x.com",
        "t_1",
        "laptop",
        [
            _row(decision="session", session_id=root, role="reviewer", program="claude"),
            _row(
                decision="session",
                session_id=child,
                parent_session_id=root,
                role="reader",
                program="codex",
            ),
            _row(session_id=root),
            _row(session_id=child, decision="deny", reason="not in reader"),
        ],
    )
    tree = log.session("a@x.com", root)
    assert tree["calls"] == 1 and tree["children"][0]["calls"] == 1
    assert len(tree["children"][0]["blocked"]) == 1
    assert log.session("a@x.com", "missing" + "c" * 8) is None
    assert log.revoke_session("a@x.com", child)
    assert log.revoked_sessions("a@x.com") == [child]
    assert log.session("a@x.com", root)["children"][0]["revoked"]


def test_policy_and_audit_over_http(world, memstore, oauth) -> None:
    app = terminal_app(world, memstore, oauth)
    c = dash.client(app)
    dash.login(c)
    assert c.get("/api/terminal/policy").status_code == 401
    assert c.get("/api/terminal/policy", headers={"Authorization": "Bearer x"}).status_code == 401
    issued = connect_terminal(c, role_id="read-only")

    policy = c.get("/api/terminal/policy", headers=bearer(issued)).json()
    assert policy["email"] == OWNER_EMAIL
    assert policy["role"]["id"] == "read-only"
    assert {r["id"] for r in policy["roles"]} >= {"read-only", "full", "none"}
    version = policy["version"]
    assert c.get("/api/terminal/policy", headers=bearer(issued)).json()["version"] == version

    sent = c.post(
        "/api/terminal/audit",
        json={
            "rows": [_row(), _row(decision="deny", reason="not in Read-only")],
            "tools": ["github/create_issue", "github/get_issue"],
            "unguarded": ["notion"],
            "queued": 3,
        },
        headers=bearer(issued),
    )
    assert sent.json() == {"accepted": 2, "duplicates": 0, "rejected": 0}
    bad = c.post("/api/terminal/audit", json={"rows": "x"}, headers=bearer(issued))
    assert bad.status_code == 400

    page = c.get("/terminal/activity").text
    assert "github/create_issue" in page and "blocked" in page
    assert "1 unguarded server" in c.get("/terminal").text
    assert "get_issue" in c.get("/terminal/roles/new").text  # tool picker

    blocked = c.get("/terminal/activity?blocked=1").text
    assert blocked.count("<code>github/create_issue</code>") == 1
    csv_text = c.get("/terminal/activity/export?format=csv").text
    assert csv_text.startswith("ts,terminal,") and csv_text.count("\n") == 3
    jsonl = c.get("/terminal/activity/export?format=jsonl&blocked=1")
    assert jsonl.headers["content-type"].startswith("application/x-ndjson")
    assert jsonl.text.count("\n") == 1

    # Changing the role on the website changes the policy version.
    (terminal,) = app.state.terminal.terminals.for_person(OWNER_EMAIL)
    token = dash.csrf(c, "/terminal")
    c.post(f"/terminal/t/{terminal.id}/role", data={"csrf": token, "role_id": "full"})
    changed = c.get("/api/terminal/policy", headers=bearer(issued)).json()
    assert changed["role"]["id"] == "full" and changed["version"] != version


def test_csv_export_neutralizes_formulas(world, memstore, oauth) -> None:
    c = dash.client(terminal_app(world, memstore, oauth))
    dash.login(c)
    issued = connect_terminal(c)
    rows = [_row(reason="@SUM(A1)", agent="=cmd"), _row(reason="", agent="-cmd", role="")]
    c.post("/api/terminal/audit", json={"rows": rows}, headers=bearer(issued))
    text = c.get("/terminal/activity/export").text
    assert ",=cmd" not in text and ",@SUM" not in text
    (dash_row,) = [line for line in text.splitlines() if "-cmd" in line]
    assert ",'-cmd," in dash_row
    assert "'" not in dash_row.replace("'-cmd", "")  # empty cells stay empty


def test_activity_is_per_person(world, memstore, oauth) -> None:
    app = terminal_app(world, memstore, oauth)
    app.state.terminal.activity.add("someone@else.com", "t_x", "theirs", [_row(tool="x/secret")])
    c = dash.client(app)
    dash.login(c)
    assert "x/secret" not in c.get("/terminal/activity").text


def test_audit_body_limits(world, memstore, oauth, monkeypatch) -> None:
    from scoped_drive_mcp.terminal import feature

    c = dash.client(terminal_app(world, memstore, oauth))
    dash.login(c)
    headers = bearer(connect_terminal(c))
    odd = c.post(
        "/api/terminal/audit",
        content=b"{}",
        headers={**headers, "content-length": "lots", "content-type": "application/json"},
    )
    assert odd.status_code in (400, 413)  # never a 500
    monkeypatch.setattr(feature, "MAX_BODY", 50)

    def chunks():
        yield b'{"rows": ['
        yield b" " * 100
        yield b"]}"

    chunked = c.post("/api/terminal/audit", content=chunks(), headers=headers)
    assert chunked.status_code == 413
    assert c.post("/api/terminal/audit", content=b"[1]", headers=headers).status_code == 400


def test_future_timestamps_are_not_believed() -> None:
    log = TerminalActivity(MemoryStore(), clock=lambda: NOW)
    log.add("a@x.com", "t_1", "laptop", [_row(ts=NOW + 10**8), _row(ts=NOW - 60)])
    assert sorted(r["ts"] for r in log.recent("a@x.com")) == [NOW - 60, NOW]


def test_failed_store_write_is_not_marked_seen() -> None:
    store = MemoryStore()
    log = TerminalActivity(store, clock=lambda: NOW)
    row = _row()
    original = store.lpush

    def broken(key, value):
        raise RuntimeError("store down")

    store.lpush = broken
    with pytest.raises(RuntimeError):
        log.add("a@x.com", "t_1", "laptop", [row])
    store.lpush = original
    assert log.add("a@x.com", "t_1", "laptop", [row])["accepted"] == 1

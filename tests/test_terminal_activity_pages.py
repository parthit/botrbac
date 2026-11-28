"""The Activity page reads one page at a time, with its filters, instead of the newest
2,000 rows: paging is stable while rows arrive, and filters reach the whole log."""

import json
import time
import uuid

import pytest

from scoped_drive_mcp.store import MemoryStore
from scoped_drive_mcp.terminal.ingest import (
    ACTIVITY_KEY,
    DENIES_KEY,
    PAGE_SCAN,
    TerminalActivity,
)
from tests import dash
from tests.terminal_helpers import bearer, connect_terminal, terminal_app

NOW = 1_800_000_000.0
EMAIL = "owner@example.com"


def _push(store: MemoryStore, n: int, *, start: int = 0, deny_every: int = 0) -> None:
    """Rows 0..n-1 as uploads would store them: newest received at the front."""
    for i in range(start, start + n):
        deny = bool(deny_every) and i % deny_every == 0
        row = {
            "event_id": f"evt{i:08d}",
            "ts": NOW - 10_000 + i,
            "received": NOW - 10_000 + i,
            "decision": "deny" if deny else "allow",
            "agent": "claude-code",
            "terminal_id": "t_one",
        }
        text = json.dumps(row)
        store.lpush(ACTIVITY_KEY.format(email=EMAIL), text)
        if deny:
            store.lpush(DENIES_KEY.format(email=EMAIL), text)


def _ids(rows):
    return [r["event_id"] for r in rows]


def _all(_row) -> bool:
    return True


def test_pages_walk_the_whole_log_once() -> None:
    store = MemoryStore()
    log = TerminalActivity(store, clock=lambda: NOW, max_rows=100_000)
    _push(store, 250)
    seen, cursor = [], None
    for _ in range(10):
        rows, cursor = log.page(EMAIL, _all, after=cursor, count=100)
        seen += _ids(rows)
        if cursor is None:
            break
    assert len(seen) == 250 == len(set(seen))
    assert seen[0] == "evt00000249" and seen[-1] == "evt00000000"


def test_rows_arriving_between_pages_do_not_repeat_rows() -> None:
    store = MemoryStore()
    log = TerminalActivity(store, clock=lambda: NOW)
    _push(store, 150)
    first, cursor = log.page(EMAIL, _all, count=100)
    _push(store, 30, start=1000)  # new rows land in front, shifting every position
    second, cursor = log.page(EMAIL, _all, after=cursor, count=100)
    assert cursor is None
    assert not set(_ids(first)) & set(_ids(second))
    assert len(first) + len(second) == 150


def test_blocked_filter_reads_the_blocks_kept_apart_beyond_the_scan() -> None:
    store = MemoryStore()
    log = TerminalActivity(store, clock=lambda: NOW, max_rows=100_000)
    _push(store, 1, deny_every=1)  # one old block...
    _push(store, PAGE_SCAN + 10, start=1)  # ...behind more allowed rows than one page reads

    def blocked(r):
        return r["decision"] == "deny"

    rows, _ = log.page(EMAIL, blocked, blocked=True)
    assert _ids(rows) == ["evt00000000"]
    # The main log would need another request to reach it, and says so with a cursor.
    rows, cursor = log.page(EMAIL, blocked)
    assert rows == [] and cursor is not None
    rows, cursor = log.page(EMAIL, blocked, after=cursor)
    assert _ids(rows) == ["evt00000000"] and cursor is None


def test_bad_cursor_starts_from_the_newest() -> None:
    store = MemoryStore()
    log = TerminalActivity(store, clock=lambda: NOW)
    _push(store, 5)
    for bad in ("x", "1:2", "-5:0:", "0:nan:evt00000001", "a:b:c"):
        rows, _ = log.page(EMAIL, _all, after=bad, count=2)
        assert rows, bad


def test_rows_past_retention_end_the_log() -> None:
    store = MemoryStore()
    log = TerminalActivity(store, clock=lambda: NOW + 400 * 24 * 3600)
    _push(store, 5)
    assert log.page(EMAIL, _all) == ([], None)


@pytest.fixture
def site_with_rows(world, memstore, oauth):
    browser = dash.client(terminal_app(world, memstore, oauth))
    dash.login(browser)
    issued = connect_terminal(browser)
    now = time.time()
    rows = [
        {
            "event_id": uuid.uuid4().hex,
            "ts": now - 1000 + i,
            "agent": "claude-code",
            "tool": f"github/tool_{i}",
            "decision": "allow",
            "reason": "ok",
            "role": "full",
        }
        for i in range(150)
    ]
    sent = browser.post("/api/terminal/audit", json={"rows": rows}, headers=bearer(issued))
    assert sent.json()["accepted"] == 150
    return browser


def test_activity_page_links_to_older_rows(site_with_rows) -> None:
    client = site_with_rows
    page = client.get("/terminal/activity")
    assert page.status_code == 200
    assert 'id="activity-older"' in page.text
    assert "show=" not in page.text
    older = page.text.split('id="activity-older"')[0].rsplit('href="', 1)[1].split('"')[0]
    second = client.get(older.replace("&amp;", "&"))
    assert second.status_code == 200 and 'id="activity-newest"' in second.text
    assert 'id="activity-older"' not in second.text


def test_rows_from_one_upload_share_an_arrival_time_and_all_show() -> None:
    store = MemoryStore()
    log = TerminalActivity(store, clock=lambda: NOW)
    for i in range(150):
        row = {"event_id": f"evt{i:08d}", "ts": NOW - 500 + i, "received": NOW - 100}
        store.lpush(ACTIVITY_KEY.format(email=EMAIL), json.dumps(row))
    first, cursor = log.page(EMAIL, _all, count=100)
    second, cursor = log.page(EMAIL, _all, after=cursor, count=100)
    assert len(first) == 100 and len(second) == 50 and cursor is None
    assert not set(_ids(first)) & set(_ids(second))

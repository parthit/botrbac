"""Terminal: device-code login, terminal tokens and the Terminals page."""

import hashlib
import json

import pytest

from scoped_drive_mcp.store import MemoryStore
from scoped_drive_mcp.terminal.device import (
    POLL_INTERVAL,
    DeviceError,
    Terminals,
    normalize_user_code,
)
from scoped_drive_mcp.terminal.roles import TerminalRoles
from tests import dash
from tests.conftest import OWNER_EMAIL, FakeClock
from tests.terminal_helpers import DEVICE_GRANT, connect_terminal, terminal_app

ME = "me@example.com"


def _terminals(clock=None, signed_in=lambda e: True) -> Terminals:
    store = MemoryStore()
    return Terminals(store, TerminalRoles(store), signed_in, clock or FakeClock())


def _connected(t: Terminals):
    """An approved terminal with its first tokens: (terminal, issued)."""
    started = t.start({})
    terminal = t.approve(ME, started["user_code"], "full", "x")
    return terminal, t.poll(started["device_code"])


def _decision_key(started) -> str:
    return "term:device:" + hashlib.sha256(started["device_code"].encode()).hexdigest()


def test_user_code_normalizing() -> None:
    assert normalize_user_code("bcdf ghjk") == "BCDF-GHJK"
    assert normalize_user_code("BCDF-GHJ") == ""
    assert normalize_user_code("AEIO-UBCD") == ""


def test_flow_pending_slow_down_approve_once() -> None:
    clock = FakeClock()
    t = _terminals(clock)
    started = t.start({"hostname": "box\nname\x00", "os": "Linux"})
    with pytest.raises(DeviceError) as exc:
        t.poll(started["device_code"])
    assert exc.value.code == "authorization_pending"
    with pytest.raises(DeviceError) as exc:
        t.poll(started["device_code"])
    assert exc.value.code == "slow_down"
    clock.advance(POLL_INTERVAL)
    terminal = t.approve(ME, started["user_code"].lower(), "full", "")
    assert terminal is not None and terminal.role_id == "full"
    assert terminal.name == "box name"
    assert t.approve(ME, started["user_code"], "full", "") is None  # code is used up
    issued = t.poll(started["device_code"])
    assert t.resolve(issued["access_token"]) == t.get(terminal.id)
    with pytest.raises(DeviceError) as exc:
        t.poll(started["device_code"])
    assert exc.value.code == "expired_token"


def test_unknown_role_is_refused_and_deny() -> None:
    t = _terminals()
    started = t.start({})
    with pytest.raises(ValueError, match="Pick one of your roles"):
        t.approve(ME, started["user_code"], "r_nope", "x")
    assert t.pending(started["user_code"]) is not None  # still waiting
    other = t.start({})
    assert t.deny(other["user_code"])
    with pytest.raises(DeviceError) as exc:
        t.poll(other["device_code"])
    assert exc.value.code == "access_denied"


def test_refresh_rotates_and_revoke_ends_everything() -> None:
    allowed = {ME}
    t = _terminals(signed_in=lambda e: e in allowed)
    terminal, first = _connected(t)
    second = t.refresh(first["refresh_token"])
    assert second is not None
    assert t.resolve(second["access_token"]) is not None
    allowed.clear()
    assert t.resolve(second["access_token"]) is None  # signed-in check applies
    allowed.add(ME)
    assert t.revoke(ME, terminal.id)
    assert t.resolve(second["access_token"]) is None
    assert t.refresh(second["refresh_token"]) is None
    assert t.for_person(ME) == []
    # A used refresh token coming back ends the terminal's tokens (see
    # test_terminal_fix_server.py): rotation is checked there.


def test_signed_out_person_cannot_approve() -> None:
    t = _terminals(signed_in=lambda e: False)
    started = t.start({})
    assert t.approve(ME, started["user_code"], "full", "x") is None


def test_approval_and_refresh_are_one_use_even_when_raced() -> None:
    t = _terminals()
    started = t.start({})
    t.approve(ME, started["user_code"], "full", "x")
    t.store.set(f"{_decision_key(started)}:claimed", "1", ex=60)  # another poll claimed it first
    with pytest.raises(DeviceError) as exc:
        t.poll(started["device_code"])
    assert exc.value.code == "expired_token"

    _, issued = _connected(t)
    digest = hashlib.sha256(issued["refresh_token"].encode()).hexdigest()
    t.store.set_if_absent(f"term:rt:{digest}:used", "1", ex=60)  # a racing refresh won
    assert t.refresh(issued["refresh_token"]) is None


def test_refresh_does_not_undo_a_role_change() -> None:
    t = _terminals()
    terminal, issued = _connected(t)
    t.update(ME, terminal.id, role_id="none", name="renamed")
    assert t.refresh(issued["refresh_token"]) is not None
    after = t.get(terminal.id)
    assert after.role_id == "none" and after.name == "renamed"


def test_tokens_are_not_interchangeable() -> None:
    t = _terminals()
    _, issued = _connected(t)
    assert t.resolve(issued["refresh_token"]) is None
    assert t.refresh(issued["access_token"]) is None
    assert t.resolve("brt_at_made-up") is None


def test_owner_checks() -> None:
    t = _terminals()
    terminal, _ = _connected(t)
    assert t.update("other@example.com", terminal.id, name="y") is None
    assert not t.revoke("other@example.com", terminal.id)


def test_flow_over_http(world, memstore, oauth) -> None:
    app = terminal_app(world, memstore, oauth)
    c = dash.client(app)
    dash.login(c)
    started = c.post("/api/terminal/device", data={"hostname": "laptop"}).json()
    assert started["verification_uri"].endswith("/device")
    assert started["interval"] == POLL_INTERVAL
    pending = c.post(
        "/api/terminal/token",
        data={"grant_type": DEVICE_GRANT, "device_code": started["device_code"]},
    )
    assert pending.status_code == 400 and pending.json() == {"error": "authorization_pending"}
    assert c.post("/api/terminal/token", data={"grant_type": "password"}).json() == {
        "error": "unsupported_grant_type"
    }
    bad = c.post("/api/terminal/token", data={"grant_type": "refresh_token", "refresh_token": "x"})
    assert bad.json() == {"error": "invalid_grant"}

    issued = connect_terminal(c, role_id="full", name="Work laptop")
    page = c.get("/terminal").text
    assert "Work laptop" in page and 'id="no-terminals"' not in page

    # A terminal token is not a /mcp credential, and /mcp credentials are not terminal ones.
    mcp = c.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={**dash.MCP_HEADERS, "Authorization": f"Bearer {issued['access_token']}"},
    )
    assert mcp.status_code == 401
    terminal = app.state.terminal.terminals
    assert terminal.resolve(dash.TOKENS["admin"]) is None


def test_device_page_states(world, memstore, oauth) -> None:
    c = dash.client(terminal_app(world, memstore, oauth))
    assert c.get("/device?code=BCDF-GHJK").headers["location"].startswith("/login")
    dash.login(c)
    assert "Enter the code" in c.get("/device").text
    assert "not valid or has expired" in c.get("/device?code=BCDF-GHJK").text
    token = dash.csrf(c, "/device")
    r = c.post("/device/approve", data={"csrf": token, "code": "BCDF-GHJK"})
    assert r.headers["location"] == "/device"
    assert c.post("/device/other", data={"csrf": token}).status_code == 404


def test_terminal_actions(world, memstore, oauth) -> None:
    app = terminal_app(world, memstore, oauth)
    c = dash.client(app)
    dash.login(c)
    connect_terminal(c)
    store = app.state.terminal.terminals
    (terminal,) = store.for_person(OWNER_EMAIL)
    token = dash.csrf(c, "/terminal")
    c.post(f"/terminal/t/{terminal.id}/rename", data={"csrf": token, "name": "Desk"})
    c.post(f"/terminal/t/{terminal.id}/role", data={"csrf": token, "role_id": "none"})
    updated = store.get(terminal.id)
    assert updated.name == "Desk" and updated.role_id == "none"
    c.post(f"/terminal/t/{terminal.id}/role", data={"csrf": token, "role_id": "r_missing"})
    assert store.get(terminal.id).role_id == "none"
    c.post(f"/terminal/t/{terminal.id}/revoke", data={"csrf": token})
    assert store.get(terminal.id) is None
    assert 'id="no-terminals"' in c.get("/terminal").text


def test_rate_limits(world, memstore, oauth, monkeypatch) -> None:
    from scoped_drive_mcp.terminal import feature

    monkeypatch.setattr(feature, "TOKEN_LIMIT", 2)
    monkeypatch.setattr(feature, "APPROVE_LIMIT", 1)
    c = dash.client(terminal_app(world, memstore, oauth))
    dash.login(c)
    for _ in range(2):
        c.post("/api/terminal/token", data={"grant_type": "x"})
    limited = c.post("/api/terminal/token", data={"grant_type": "x"})
    assert limited.status_code == 429 and limited.json() == {"error": "rate_limited"}
    assert limited.headers["retry-after"] == "60"
    assert c.post("/api/terminal/device", json={}).status_code == 200  # its own bucket

    token = dash.csrf(c, "/device")
    c.post("/device/deny", data={"csrf": token, "code": "BCDF-GHJK"})
    r = c.post("/device/deny", data={"csrf": token, "code": "BCDF-GHJK"})
    assert r.headers["location"] == "/device"
    assert "Too many codes" in c.get("/device").text


def test_device_page_escapes_what_the_terminal_sent(world, memstore, oauth) -> None:
    c = dash.client(terminal_app(world, memstore, oauth))
    dash.login(c)
    started = c.post("/api/terminal/device", json={"hostname": "<script>x</script>"}).json()
    page = c.get("/device", params={"code": started["user_code"]}).text
    assert "<script>x</script>" not in page and "&lt;script&gt;" in page


def test_a_poll_cannot_undo_an_approval() -> None:
    clock = FakeClock()
    t = _terminals(clock)
    started = t.start({})
    code = started["user_code"]
    # A poll reads the pending record, then the person approves, then the poll writes.
    with pytest.raises(DeviceError):
        t.poll(started["device_code"])
    terminal = t.approve(ME, code, "full", "x")
    clock.advance(POLL_INTERVAL)
    issued = t.poll(started["device_code"])
    assert t.resolve(issued["access_token"]).id == terminal.id


def test_one_decision_per_code() -> None:
    t = _terminals()
    started = t.start({})
    t.store.set_if_absent(f"{_decision_key(started)}:decision", "{}", ex=60)  # a racing one
    assert t.approve(ME, started["user_code"], "full", "x") is None
    assert t.for_person(ME) == []  # no orphaned terminal
    assert t.store.hgetall(f"term:terminals:{ME}") == {}


def test_poll_has_a_second_of_slack() -> None:
    clock = FakeClock()
    t = _terminals(clock)
    started = t.start({})
    with pytest.raises(DeviceError):
        t.poll(started["device_code"])
    clock.advance(POLL_INTERVAL - 0.5)
    with pytest.raises(DeviceError) as exc:
        t.poll(started["device_code"])
    assert exc.value.code == "authorization_pending"


def test_terminal_check_ins_do_not_undo_role_changes() -> None:
    t = _terminals()
    terminal, _ = _connected(t)
    t.update(ME, terminal.id, role_id="none")
    t.touch(terminal.id, last_seen=5.0, queued=3, role_id="full")  # role_id is ignored
    after = t.get(terminal.id)
    assert after.role_id == "none" and after.last_seen == 5.0 and after.queued == 3


def test_an_edit_racing_a_disconnect_does_not_bring_the_terminal_back() -> None:
    t = _terminals()
    terminal, issued = _connected(t)
    # The edit read the record, then the disconnect ran, then the edit saved.
    stale = t.get(terminal.id)
    t.revoke(ME, terminal.id)
    t._save(stale)
    assert t.resolve(issued["access_token"]) is None
    assert t.refresh(issued["refresh_token"]) is None
    assert t.update(ME, terminal.id, name="y") is None
    assert t.store.get(f"term:terminal:{terminal.id}") is None


def test_device_lookups_are_throttled(world, memstore, oauth, monkeypatch) -> None:
    from scoped_drive_mcp.terminal import feature

    monkeypatch.setattr(feature, "LOOKUP_LIMIT", 1)
    c = dash.client(terminal_app(world, memstore, oauth))
    dash.login(c)
    c.get("/device?code=BCDF-GHJK")
    assert "Too many codes" in c.get("/device?code=BCDF-GHJK").text


def test_touch_after_disconnect_writes_nothing() -> None:
    t = _terminals()
    started = t.start({})
    terminal = t.approve(ME, started["user_code"], "full", "x")  # never polled: no tokens
    t.revoke(ME, terminal.id)
    t.touch(terminal.id, last_seen=1.0)
    assert t.store.get(f"term:terminal:{terminal.id}:seen") is None


def test_update_only_edits_name_and_role() -> None:
    t = _terminals()
    terminal, _ = _connected(t)
    t.touch(terminal.id, last_seen=9.0)
    with pytest.raises(ValueError):
        t.update(ME, terminal.id, created_at=0.0)
    t.update(ME, terminal.id, name="y")
    raw = json.loads(t.store.get(f"term:terminal:{terminal.id}"))
    assert raw["last_seen"] == 0.0  # check-ins stay in their own key
    assert t.get(terminal.id).last_seen == 9.0

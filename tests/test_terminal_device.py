"""Terminal, phase 3: device-code login, terminal tokens and the Terminals page."""

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


def test_unknown_role_becomes_read_only_and_deny() -> None:
    t = _terminals()
    started = t.start({})
    assert t.approve(ME, started["user_code"], "r_nope", "x").role_id == "read-only"
    other = t.start({})
    assert t.deny(other["user_code"])
    with pytest.raises(DeviceError) as exc:
        t.poll(other["device_code"])
    assert exc.value.code == "access_denied"


def test_refresh_rotates_and_revoke_ends_everything() -> None:
    allowed = {ME}
    t = _terminals(signed_in=lambda e: e in allowed)
    started = t.start({})
    terminal = t.approve(ME, started["user_code"], "full", "x")
    first = t.poll(started["device_code"])
    second = t.refresh(first["refresh_token"])
    assert second is not None
    assert t.refresh(first["refresh_token"]) is None  # rotated
    assert t.resolve(second["access_token"]) is not None
    allowed.clear()
    assert t.resolve(second["access_token"]) is None  # signed-in check applies
    allowed.add(ME)
    assert t.revoke(ME, terminal.id)
    assert t.resolve(second["access_token"]) is None
    assert t.refresh(second["refresh_token"]) is None
    assert t.for_person(ME) == []


def test_tokens_are_not_interchangeable() -> None:
    t = _terminals()
    started = t.start({})
    t.approve(ME, started["user_code"], "full", "x")
    issued = t.poll(started["device_code"])
    assert t.resolve(issued["refresh_token"]) is None
    assert t.refresh(issued["access_token"]) is None
    assert t.resolve("brt_at_made-up") is None


def test_owner_checks() -> None:
    t = _terminals()
    started = t.start({})
    terminal = t.approve(ME, started["user_code"], "full", "x")
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

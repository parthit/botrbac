"""Phase 4: the owner picks what each connected app may do, and can change it later."""

import json

from scoped_drive_mcp.mcp_oauth import GRANTS_KEY
from tests.conftest import OWNER_EMAIL
from tests.dash import MCP_HEADERS, csrf, post
from tests.test_mcp_oauth import (
    DONE,
    auth_params,
    c,  # noqa: F401 - fixture
    code_from,
    exchange,
    owner_c,  # noqa: F401 - fixture
    posted_redirect,
    register,
    tool_names,
)

WRITE_TOOLS = {"create_folder", "create_doc", "upload_file", "update_file_content", "rename_file"}


def _connect(owner_c, name: str = "Some app", **decision) -> str:  # noqa: F811
    created = register(owner_c, DONE, name=name)
    client_id = created.json()["client_id"]
    verifier, params = auth_params(client_id, DONE)
    page = owner_c.get("/oauth/authorize", params=params)
    assert page.status_code == 200
    allowed = post(owner_c, "/oauth/authorize", decision="allow", **decision)
    token = exchange(
        owner_c, client_id, code_from(posted_redirect(owner_c, allowed)), verifier, DONE
    )
    assert token.status_code == 200, token.text
    return token.json()["access_token"]


def _call(c, token: str, tool: str, **args) -> dict:  # noqa: F811
    body = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args},
    }
    headers = {**MCP_HEADERS, "Authorization": f"Bearer {token}"}
    return c.post("/mcp", json=body, headers=headers).json()["result"]


def _grant_id(memstore) -> str:
    grants = memstore.hgetall(f"sdm:{GRANTS_KEY}")
    return sorted(grants, key=lambda g: json.loads(grants[g])["created_at"])[-1]


def test_the_consent_page_offers_roles_and_defaults_to_read_only(owner_c) -> None:  # noqa: F811
    created = register(owner_c, DONE, name="Picker")
    _verifier, params = auth_params(created.json()["client_id"], DONE)
    page = owner_c.get("/oauth/authorize", params=params).text
    assert 'name="role" value="viewer" checked' in page
    assert 'value="editor"' in page and 'value="admin"' in page
    # The old promise of messaging other people is gone.
    assert "people you are paired with" not in page


def test_a_read_only_app_gets_no_write_tools(owner_c) -> None:  # noqa: F811
    token = _connect(owner_c)
    names = tool_names(owner_c, token)
    assert not names & WRITE_TOOLS
    assert "trash_file" not in names
    assert "read_file" in names
    refused = _call(owner_c, token, "create_folder", name="x")
    assert refused["isError"] is True


def test_editor_and_full(owner_c) -> None:  # noqa: F811
    editor = tool_names(owner_c, _connect(owner_c, "Editor", role="editor"))
    assert WRITE_TOOLS <= editor and "trash_file" not in editor
    full = tool_names(owner_c, _connect(owner_c, "Full", role="admin"))
    assert "trash_file" in full


def test_an_unknown_role_is_refused(owner_c) -> None:  # noqa: F811
    created = register(owner_c, DONE, name="Odd")
    _verifier, params = auth_params(created.json()["client_id"], DONE)
    owner_c.get("/oauth/authorize", params=params)
    response = post(owner_c, "/oauth/authorize", decision="allow", role="root")
    assert response.status_code in (302, 303, 400)
    assert "code=" not in response.headers.get("location", "")


def test_changing_the_role_applies_on_the_next_call(owner_c, memstore) -> None:  # noqa: F811
    token = _connect(owner_c)
    grant = _grant_id(memstore)
    assert not tool_names(owner_c, token) & WRITE_TOOLS
    page = owner_c.get("/settings").text
    assert f'id="role-{grant}"' in page
    saved = owner_c.post(
        "/oauth/grants/role",
        data={"csrf": csrf(owner_c, "/settings"), "grant_id": grant, "role": "editor"},
    )
    assert saved.status_code == 303
    assert WRITE_TOOLS <= tool_names(owner_c, token)
    # A made-up role changes nothing (someone else's app: see the ownership test below).
    owner_c.post(
        "/oauth/grants/role",
        data={"csrf": csrf(owner_c, "/settings"), "grant_id": grant, "role": "root"},
    )
    assert WRITE_TOOLS <= tool_names(owner_c, token)


def test_apps_connected_before_roles_keep_full_access(owner_c, memstore) -> None:  # noqa: F811
    token = _connect(owner_c)
    grant = _grant_id(memstore)
    memstore.delete(f"sdm:oauth:role:{grant}")
    # A grant approved since roles exist fails closed when its role key is gone.
    assert "trash_file" not in tool_names(owner_c, token)
    assert not tool_names(owner_c, token) & WRITE_TOOLS
    # A grant from before roles (no marker on the record) keeps full access.
    raw = json.loads(memstore.hget(f"sdm:{GRANTS_KEY}", grant))
    raw.pop("roles", None)
    memstore.hset(f"sdm:{GRANTS_KEY}", grant, json.dumps(raw))
    assert "trash_file" in tool_names(owner_c, token)


def test_an_unknown_stored_role_is_read_only(owner_c, memstore) -> None:  # noqa: F811
    token = _connect(owner_c, role="admin")
    grant = _grant_id(memstore)
    memstore.set(f"sdm:oauth:role:{grant}", "root")
    names = tool_names(owner_c, token)
    assert "trash_file" not in names and not names & WRITE_TOOLS


def test_only_the_owner_can_change_an_apps_role(owner_c, memstore) -> None:  # noqa: F811
    _connect(owner_c)
    grant = _grant_id(memstore)
    oauth = owner_c.app.state.dashboard.mcp_oauth
    assert oauth.set_role(grant, "eve@example.com", "admin") is False
    assert oauth.set_role("no-such-grant-id", OWNER_EMAIL, "admin") is False
    assert memstore.get(f"sdm:oauth:role:{grant}") == "viewer"


def test_disconnecting_an_app_drops_its_role(owner_c, memstore) -> None:  # noqa: F811
    _connect(owner_c, role="editor")
    grant = _grant_id(memstore)
    assert memstore.get(f"sdm:oauth:role:{grant}") == "editor"
    assert owner_c.app.state.dashboard is not None
    gone = owner_c.post(
        "/oauth/grants/revoke", data={"csrf": csrf(owner_c, "/settings"), "grant_id": grant}
    )
    assert gone.status_code in (200, 303)
    assert memstore.get(f"sdm:oauth:role:{grant}") is None
    assert OWNER_EMAIL  # the owner made every change above


def test_settings_flags_apps_that_are_full_only_because_they_are_old(owner_c, memstore) -> None:  # noqa: F811
    _connect(owner_c)
    grant = _grant_id(memstore)
    assert "connected before you could choose" not in owner_c.get("/settings").text
    raw = json.loads(memstore.hget(f"sdm:{GRANTS_KEY}", grant))
    raw.pop("roles", None)
    memstore.hset(f"sdm:{GRANTS_KEY}", grant, json.dumps(raw))
    memstore.delete(f"sdm:oauth:role:{grant}")
    assert "connected before you could choose" in owner_c.get("/settings").text


def test_lowering_an_old_app_sticks_even_if_its_role_key_is_lost(owner_c, memstore) -> None:  # noqa: F811
    token = _connect(owner_c)
    grant = _grant_id(memstore)
    raw = json.loads(memstore.hget(f"sdm:{GRANTS_KEY}", grant))
    raw.pop("roles", None)
    memstore.hset(f"sdm:{GRANTS_KEY}", grant, json.dumps(raw))
    memstore.delete(f"sdm:oauth:role:{grant}")
    assert "trash_file" in tool_names(owner_c, token)  # old app: full
    owner_c.post(
        "/oauth/grants/role",
        data={"csrf": csrf(owner_c, "/settings"), "grant_id": grant, "role": "viewer"},
    )
    memstore.delete(f"sdm:oauth:role:{grant}")
    names = tool_names(owner_c, token)
    assert "trash_file" not in names and not names & WRITE_TOOLS

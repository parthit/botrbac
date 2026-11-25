"""Named roles: `/mcp/role/<slug>` narrows a call to part of the allowlist and a level."""

import json

import pytest

from scoped_drive_mcp.agent_roles import (
    MAX_ROLES,
    AgentRole,
    AgentRoleError,
    AgentRoles,
    narrowed,
    slugify,
)
from scoped_drive_mcp.auth import Principal
from scoped_drive_mcp.config import Role
from scoped_drive_mcp.mcp_oauth import OAuthGrant
from scoped_drive_mcp.policy import (
    AGENT_ROLE_TOOLS,
    PermissionDeniedError,
    check_permission,
    may_call,
)
from scoped_drive_mcp.store import AGENT_ROLES_KEY, MemoryStore, PrefixedStore
from tests.conftest import BASE_URL, OWNER_EMAIL, TOKENS
from tests.dash import MCP_HEADERS, client, login, mcp_call, post
from tests.test_mcp_oauth import (
    GROK,
    INIT,
    LIST,
    METADATA,
    RESOURCE,
    auth_params,
    bearer,
    call_tool,
    code_from,
    connect,
    exchange,
    posted_redirect,
    refresh,
    register,
    tool_names,
)

WRITE_TOOLS = {"create_folder", "create_doc", "upload_file", "update_file_content", "rename_file"}


@pytest.fixture
def owner_c(p2_app):
    c = client(p2_app)
    assert login(c).status_code == 303
    for file_id in ("proj", "loose-doc", "loose-two"):
        assert post(c, "/grant", file_id=file_id).status_code == 303
    return c


def save_role(c, name: str, level: str, *items: str):
    return post(c, "/roles/save", name=name, level=level, item=list(items))


def role_post(c, slug: str, body: dict, as_level: str = "admin"):
    headers = {**MCP_HEADERS, "Authorization": f"Bearer {TOKENS[as_level]}"}
    return c.post(f"/mcp/role/{slug}", json=body, headers=headers)


def role_call(c, slug: str, tool: str, as_level: str = "admin", **arguments) -> dict:
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }
    r = role_post(c, slug, body, as_level)
    assert r.status_code == 200, r.text
    return r.json()["result"]


def role_tools(c, slug: str, as_level: str = "admin") -> set[str]:
    assert role_post(c, slug, INIT, as_level).status_code == 200
    listed = role_post(c, slug, LIST, as_level)
    assert listed.status_code == 200, listed.text
    return {item["name"] for item in listed.json()["result"]["tools"]}


def error_text(result: dict) -> str:
    assert result["isError"] is True
    return result["content"][0]["text"]


# ---- the pieces ------------------------------------------------------------


def test_the_level_is_the_lower_of_the_two() -> None:
    assert narrowed(Role.ADMIN, "viewer") is Role.VIEWER
    assert narrowed(Role.VIEWER, "admin") is Role.VIEWER
    assert narrowed(Role.EDITOR, "admin") is Role.EDITOR
    assert narrowed(Role.ADMIN, "editor") is Role.EDITOR
    # A ceiling that cannot be read is the lowest one.
    assert narrowed(Role.ADMIN, "root") is Role.VIEWER


def test_slugs() -> None:
    assert slugify("  Research  Reader ") == "research-reader"
    assert slugify("Q3/Budget") == "q3-budget"
    assert slugify("!!!") == ""


def test_a_role_lists_only_allowlisted_items() -> None:
    roles = AgentRoles(PrefixedStore(MemoryStore()))
    role = roles.save("Researcher", "viewer", ["a", "nope", "a", "b"], {"a", "b", "c"})
    assert (role.slug, role.items) == ("researcher", ("a", "b"))
    assert roles.get("researcher") == role
    with pytest.raises(AgentRoleError):
        roles.save("Empty", "viewer", ["nope"], {"a"})
    with pytest.raises(AgentRoleError):
        roles.save("Odd level", "root", ["a"], {"a"})
    with pytest.raises(AgentRoleError):
        roles.save("???", "viewer", ["a"], {"a"})
    # Saving under the same name replaces the role and keeps when it was made.
    again = roles.save("researcher", "editor", ["c"], {"a", "b", "c"})
    assert again.created_at == role.created_at and again.items == ("c",)
    assert [r.slug for r in roles.all()] == ["researcher"]
    assert roles.delete("researcher") is True
    assert roles.delete("researcher") is False and roles.get("researcher") is None


def test_there_is_a_cap_on_roles() -> None:
    roles = AgentRoles(PrefixedStore(MemoryStore()))
    for n in range(MAX_ROLES):
        roles.save(f"role {n}", "viewer", ["a"], {"a"})
    with pytest.raises(AgentRoleError):
        roles.save("one more", "viewer", ["a"], {"a"})
    # Replacing an existing one still works at the cap.
    roles.save("role 0", "editor", ["a"], {"a"})


def test_a_damaged_record_never_widens() -> None:
    odd = AgentRole.from_json(json.dumps({"slug": "x", "level": "root", "items": ["a", "b c"]}))
    assert odd.level == "viewer" and odd.items == ("a",)
    store = PrefixedStore(MemoryStore())
    roles = AgentRoles(store)
    # A record filed under another slug is not that role.
    store.hset(AGENT_ROLES_KEY, "admin", AgentRole("other", "Other", "admin", ("a",)).to_json())
    store.hset(AGENT_ROLES_KEY, "broken", "{not json")
    assert roles.get("admin") is None and roles.get("broken") is None and roles.all() == []
    assert roles.get("../admin") is None


# ---- through the server ----------------------------------------------------


def test_a_role_reaches_only_its_own_files(owner_c) -> None:
    assert save_role(owner_c, "Researcher", "viewer", "loose-doc").status_code == 303
    ok = role_call(owner_c, "researcher", "read_file", file_id="loose-doc")
    assert ok["isError"] is False and ok["structuredContent"]["content"] == "memo beta"
    # Allowed for the owner's assistants, but not part of this role.
    for file_id in ("loose-two", "proj-notes"):
        refused = role_call(owner_c, "researcher", "read_file", file_id=file_id)
        text = error_text(refused)
        assert "role 'researcher'" in text
        # No approval link: approving would not add the file to the role.
        assert "structuredContent" not in refused or not refused["structuredContent"]
    # Not allowlisted at all: the same refusal, and nothing waiting for the owner.
    error_text(role_call(owner_c, "researcher", "read_file", file_id="priv-secret"))
    # The same token without the role still reaches the whole allowlist.
    assert mcp_call(owner_c, "read_file", file_id="loose-two")["isError"] is False
    top = role_call(owner_c, "researcher", "list_folder")["structuredContent"]
    assert "loose-doc" in json.dumps(top) and "loose-two" not in json.dumps(top)
    found = role_call(owner_c, "researcher", "search_files", query="memo")["structuredContent"]
    assert "loose-doc" in json.dumps(found) and "loose-two" not in json.dumps(found)


def test_a_folder_in_a_role_covers_what_is_inside(owner_c) -> None:
    save_role(owner_c, "Projects", "viewer", "proj")
    assert role_call(owner_c, "projects", "read_file", file_id="proj-notes")["isError"] is False
    assert role_call(owner_c, "projects", "read_file", file_id="proj-deep-doc")["isError"] is False
    error_text(role_call(owner_c, "projects", "read_file", file_id="loose-doc"))


def test_the_role_is_a_ceiling_and_the_connection_is_too(owner_c) -> None:
    save_role(owner_c, "Reader", "viewer", "proj")
    save_role(owner_c, "Writer", "editor", "proj")
    # A full-access connection through a read-only role cannot write.
    assert not role_tools(owner_c, "reader") & WRITE_TOOLS
    denied = role_call(owner_c, "reader", "create_doc", title="x", parent_id="proj")
    assert "Permission denied" in error_text(denied)
    # A read-only connection through an editor role still cannot write.
    assert not role_tools(owner_c, "writer", as_level="viewer") & WRITE_TOOLS
    error_text(role_call(owner_c, "writer", "create_doc", as_level="viewer", title="x"))
    # Full access through an editor role: edit, not trash.
    writer = role_tools(owner_c, "writer")
    assert WRITE_TOOLS <= writer and "trash_file" not in writer
    made = role_call(owner_c, "writer", "create_doc", title="Plan", parent_id="proj")
    assert made["isError"] is False


def test_a_role_only_offers_the_file_tools(owner_c) -> None:
    save_role(owner_c, "Everything", "admin", "proj", "loose-doc", "loose-two")
    names = role_tools(owner_c, "everything")
    assert names == set(AGENT_ROLE_TOOLS)
    for tool in ("list_shared_with_me", "list_links", "check_messages", "get_webhook"):
        refused = role_call(owner_c, "everything", tool)
        assert "not available through a named role" in error_text(refused), tool
    asked = role_call(
        owner_c, "everything", "request_access", description="the payroll file", reason="x"
    )
    assert "not available through a named role" in error_text(asked)


def test_directly_allowed_items_stay_protected_under_a_role(owner_c) -> None:
    # proj-notes is allowed on its own and also sits inside the role's folder.
    assert post(owner_c, "/grant", file_id="proj-notes").status_code == 303
    save_role(owner_c, "Tidy", "admin", "proj")
    for tool, args in (
        ("rename_file", {"file_id": "proj-notes", "new_name": "renamed.txt"}),
        ("trash_file", {"file_id": "proj-notes"}),
    ):
        refused = role_call(owner_c, "tidy", tool, **args)
        assert "cannot be renamed or trashed" in error_text(refused), tool
    # Something that is only inside the folder can still be renamed.
    renamed = role_call(owner_c, "tidy", "rename_file", file_id="proj-deep-doc", new_name="Deep")
    assert renamed["isError"] is False


def test_an_unknown_role_is_refused_not_ignored(owner_c) -> None:
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"file_id": "loose-doc"}},
    }
    for slug in ("nobody", "Nobody", "a_b", "x" * 60):
        r = role_post(owner_c, slug, body)
        assert r.status_code == 403, slug
        assert r.json()["error"] == "unknown_role"
    # No token: the usual 401, with the usual discovery header.
    bare = owner_c.post("/mcp/role/nobody", json=body, headers=MCP_HEADERS)
    assert bare.status_code == 401
    assert "resource_metadata=" in bare.headers["www-authenticate"]
    wrong = owner_c.post(
        "/mcp/role/nobody", json=body, headers={**MCP_HEADERS, "Authorization": "Bearer nope"}
    )
    assert wrong.status_code == 401


def test_changes_apply_on_the_next_call(owner_c) -> None:
    save_role(owner_c, "Researcher", "viewer", "loose-doc")
    assert role_call(owner_c, "researcher", "read_file", file_id="loose-doc")["isError"] is False
    # The owner edits the role.
    save_role(owner_c, "Researcher", "viewer", "loose-two")
    error_text(role_call(owner_c, "researcher", "read_file", file_id="loose-doc"))
    assert role_call(owner_c, "researcher", "read_file", file_id="loose-two")["isError"] is False
    # Taking the item off the allowlist takes it out of the role as well.
    assert post(owner_c, "/revoke", file_id="loose-two").status_code == 303
    error_text(role_call(owner_c, "researcher", "read_file", file_id="loose-two"))
    # Deleting the role refuses its address; it does not fall back to the whole list.
    assert post(owner_c, "/roles/delete", slug="researcher").status_code == 303
    gone = role_post(owner_c, "researcher", LIST)
    assert gone.status_code == 403


def test_the_dashboard_refuses_a_role_with_nothing_allowed(owner_c, p2_app) -> None:
    assert save_role(owner_c, "Sneaky", "admin", "priv-secret").status_code == 303
    assert p2_app.state.dashboard.agent_roles.get("sneaky") is None
    assert save_role(owner_c, "Odd", "root", "loose-doc").status_code == 303
    assert p2_app.state.dashboard.agent_roles.get("odd") is None
    # Signed out: nothing is saved.
    anonymous = client(p2_app)
    r = anonymous.post("/roles/save", data={"name": "X", "level": "viewer", "item": "loose-doc"})
    assert r.status_code == 403
    assert p2_app.state.dashboard.agent_roles.get("x") is None


def test_settings_shows_each_role_and_its_address(owner_c) -> None:
    page = owner_c.get("/settings").text
    assert 'id="roles"' in page and 'id="new-role"' in page
    save_role(owner_c, "Research Reader", "viewer", "loose-doc")
    page = owner_c.get("/settings").text
    assert 'id="role-research-reader"' in page
    assert "https://drive-test.example.com/mcp/role/research-reader" in page


def test_activity_names_the_role(owner_c, p2_app) -> None:
    save_role(owner_c, "Researcher", "viewer", "loose-doc")
    role_call(owner_c, "researcher", "read_file", file_id="loose-doc")
    role_call(owner_c, "researcher", "read_file", file_id="loose-two")
    mcp_call(owner_c, "read_file", file_id="loose-doc")
    calls = [r for r in p2_app.state.dashboard.activity.recent() if r.get("event") == "tool_call"]
    plain, denied, allowed = calls[0], calls[1], calls[2]
    assert "agent_role" not in plain
    assert (allowed["agent_role"], allowed["decision"]) == ("researcher", "allow")
    assert (denied["agent_role"], denied["decision"]) == ("researcher", "deny")
    assert "(role researcher)" in owner_c.get("/activity").text


# ---- a connection is bound to the role it signed in through -----------------

ROLE_RESOURCE = f"{RESOURCE}/role/"


def role_connect(c, slug: str, **decision) -> tuple[str, dict]:
    """Register, approve and exchange at a role's address: (client_id, token response)."""
    resource = ROLE_RESOURCE + slug
    client_id = register(c, GROK).json()["client_id"]
    verifier, params = auth_params(client_id, GROK, resource=resource)
    page = c.get("/oauth/authorize", params=params)
    assert page.status_code == 200, page.text
    allowed = post(c, "/oauth/authorize", decision="allow", **decision)
    code = code_from(posted_redirect(c, allowed))
    token = exchange(c, client_id, code, verifier, GROK, resource=resource)
    assert token.status_code == 200, token.text
    return client_id, token.json()


def status_at(c, path: str, token: str) -> tuple[int, str]:
    r = c.post(path, json=LIST, headers=bearer(token))
    return r.status_code, (r.json().get("error", "") if r.status_code == 403 else "")


def test_a_role_address_has_its_own_metadata(owner_c) -> None:
    bare = owner_c.post("/mcp/role/researcher", json=INIT, headers=MCP_HEADERS)
    assert bare.status_code == 401
    assert bare.headers["www-authenticate"] == (
        f'Bearer resource_metadata="{METADATA}/role/researcher"'
    )
    for path in (
        "/.well-known/oauth-protected-resource/mcp/role/researcher",
        "/mcp/role/researcher/.well-known/oauth-protected-resource",
    ):
        body = owner_c.get(path).json()
        assert body["resource"] == ROLE_RESOURCE + "researcher"
        assert body["authorization_servers"] == [BASE_URL]
    assert owner_c.get("/.well-known/oauth-protected-resource/mcp/role/No_Good").status_code == 404
    # A name that cannot be a role points at the plain metadata; the call is refused anyway.
    odd = owner_c.post("/mcp/role/No_Good", json=INIT, headers=MCP_HEADERS)
    assert odd.headers["www-authenticate"] == f'Bearer resource_metadata="{METADATA}"'
    # Plain /mcp is unchanged.
    assert owner_c.get("/.well-known/oauth-protected-resource/mcp").json()["resource"] == RESOURCE


def test_a_role_connection_is_refused_everywhere_else(owner_c, p2_app) -> None:
    save_role(owner_c, "Researcher", "viewer", "loose-doc")
    save_role(owner_c, "Projects", "viewer", "proj")
    _client, tokens = role_connect(owner_c, "researcher", role="admin")
    token = tokens["access_token"]
    assert status_at(owner_c, "/mcp/role/researcher", token) == (200, "")
    # Not on plain /mcp, whatever level was chosen, and not on another role.
    assert status_at(owner_c, "/mcp", token) == (403, "role_mismatch")
    assert status_at(owner_c, "/mcp/role/projects", token) == (403, "role_mismatch")
    assert status_at(owner_c, "/mcp/role/nobody", token) == (403, "role_mismatch")
    # Through its own address it is the role: its files, its level.
    body = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"file_id": "loose-two"}},
    }
    refused = owner_c.post("/mcp/role/researcher", json=body, headers=bearer(token)).json()
    assert "role 'researcher'" in error_text(refused["result"])
    body["params"]["arguments"]["file_id"] = "loose-doc"
    read = owner_c.post("/mcp/role/researcher", json=body, headers=bearer(token)).json()
    assert read["result"]["isError"] is False
    grant = p2_app.state.dashboard.mcp_oauth.list_grants(OWNER_EMAIL)[0]
    assert grant.agent_role == "researcher"
    assert "Connected through the role <b>researcher</b>" in owner_c.get("/settings").text
    assert "not approved for" in owner_c.get("/activity").text


def test_a_deleted_role_cuts_off_its_connection(owner_c) -> None:
    save_role(owner_c, "Researcher", "viewer", "loose-doc")
    _client, tokens = role_connect(owner_c, "researcher", role="admin")
    token = tokens["access_token"]
    assert status_at(owner_c, "/mcp/role/researcher", token) == (200, "")
    assert post(owner_c, "/roles/delete", slug="researcher").status_code == 303
    assert status_at(owner_c, "/mcp/role/researcher", token) == (403, "unknown_role")
    # It never falls back to the whole allowlist.
    assert status_at(owner_c, "/mcp", token) == (403, "role_mismatch")


def test_a_role_connection_refreshes_only_for_its_address(owner_c) -> None:
    save_role(owner_c, "Researcher", "viewer", "loose-doc")
    client_id, tokens = role_connect(owner_c, "researcher")

    def renew(refresh_token: str, resource: str):
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
            "resource": resource,
        }
        return owner_c.post("/oauth/token", data=data)

    # Asking for plain /mcp, or another role, gets nothing and does not spend the token.
    assert renew(tokens["refresh_token"], RESOURCE).status_code == 400
    assert renew(tokens["refresh_token"], ROLE_RESOURCE + "projects").status_code == 400
    again = renew(tokens["refresh_token"], ROLE_RESOURCE + "researcher")
    assert again.status_code == 200, again.text
    fresh = again.json()["access_token"]
    assert status_at(owner_c, "/mcp/role/researcher", fresh) == (200, "")
    assert status_at(owner_c, "/mcp", fresh) == (403, "role_mismatch")


def test_a_code_for_a_role_is_not_exchanged_for_plain_mcp(owner_c) -> None:
    save_role(owner_c, "Researcher", "viewer", "loose-doc")
    client_id = register(owner_c, GROK).json()["client_id"]
    verifier, params = auth_params(client_id, GROK, resource=ROLE_RESOURCE + "researcher")
    assert owner_c.get("/oauth/authorize", params=params).status_code == 200
    allowed = post(owner_c, "/oauth/authorize", decision="allow")
    code = code_from(posted_redirect(owner_c, allowed))
    swapped = exchange(owner_c, client_id, code, verifier, GROK)  # resource = plain /mcp
    assert swapped.status_code == 400
    assert swapped.json()["error"] == "invalid_target"


def test_a_plain_connection_works_on_mcp_as_before_and_not_on_a_role(owner_c, p2_app) -> None:
    save_role(owner_c, "Researcher", "viewer", "loose-doc")
    client_id, tokens = connect(owner_c, role="editor")
    token = tokens["access_token"]
    # Unbound: the whole allowlist at its own level on plain /mcp.
    assert call_tool(owner_c, token, "read_file", file_id="loose-two")["isError"] is False
    assert "create_doc" in tool_names(owner_c, token)
    assert p2_app.state.dashboard.mcp_oauth.list_grants(OWNER_EMAIL)[0].agent_role is None
    renewed = refresh(owner_c, client_id, tokens["refresh_token"])
    assert renewed.status_code == 200
    assert status_at(owner_c, "/mcp", renewed.json()["access_token"]) == (200, "")
    # A role's address wants a connection made for it.
    assert status_at(owner_c, "/mcp/role/researcher", token) == (403, "role_mismatch")


def test_a_grant_saved_before_binding_is_unbound() -> None:
    old = json.dumps({"id": "g1", "client_id": "c", "email": "a@example.com", "roles": True})
    assert OAuthGrant.from_json(old).agent_role is None


def test_consent_names_the_role_and_refuses_one_you_do_not_have(owner_c) -> None:
    save_role(owner_c, "Researcher", "viewer", "loose-doc")
    client_id = register(owner_c, GROK).json()["client_id"]
    _v, params = auth_params(client_id, GROK, resource=ROLE_RESOURCE + "researcher")
    page = owner_c.get("/oauth/authorize", params=params)
    assert page.status_code == 200 and 'id="consent-agent-role"' in page.text
    assert "Researcher" in page.text and "Use your Mailbox" not in page.text
    _v, params = auth_params(client_id, GROK, resource=ROLE_RESOURCE + "nobody")
    missing = owner_c.get("/oauth/authorize", params=params)
    assert missing.status_code == 404 and "no role named" in missing.text
    _v, params = auth_params(client_id, GROK, resource=ROLE_RESOURCE + "Bad_Slug")
    bad = owner_c.get("/oauth/authorize", params=params)
    assert bad.status_code == 303 and "invalid_target" in bad.headers["location"]


def test_the_tool_check_refuses_a_bound_connection_off_its_role() -> None:
    bound = Principal(token_name="app", role=Role.ADMIN, bound_role="researcher")
    assert may_call(bound, "read_file") is False
    with pytest.raises(PermissionDeniedError):
        check_permission(bound, "read_file")
    on_role = Principal(
        token_name="app", role=Role.VIEWER, bound_role="researcher", agent_role="researcher"
    )
    assert may_call(on_role, "read_file") is True
    assert may_call(Principal(token_name="app", role=Role.VIEWER), "read_file") is True

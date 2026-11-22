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
from scoped_drive_mcp.config import Role
from scoped_drive_mcp.policy import AGENT_ROLE_TOOLS
from scoped_drive_mcp.store import AGENT_ROLES_KEY, MemoryStore, PrefixedStore
from tests.conftest import TOKENS
from tests.dash import MCP_HEADERS, client, login, mcp_call, post
from tests.test_mcp_oauth import INIT, LIST

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

"""Terminal, phase 2: patterns and per-person roles."""

import pytest

from botrbac_cli.patterns import (
    PatternError,
    allows,
    chain_allows,
    matches,
    normalize_server,
    validate,
    validate_all,
)
from scoped_drive_mcp.store import MemoryStore
from scoped_drive_mcp.terminal.roles import BUILTIN, DEFAULT_ROLE, RoleError, TerminalRoles
from tests import dash
from tests.terminal_helpers import terminal_app

ME = "me@example.com"


@pytest.mark.parametrize(
    ("pattern", "tool", "expected"),
    [
        ("*", "github/create_issue", True),
        ("github/*", "github/create_issue", True),
        ("github/*", "gitlab/create_issue", False),
        ("github/create_issue", "github/create_issue", True),
        ("github/create_issue", "github/create_issues", False),
        ("github/get_*", "github/get_issue", True),
        ("github/get_*", "github/list_issues", False),
        ("*/read*", "fs/read_file", True),
        ("*/read*", "fs/write_file", False),
        ("claude-code/Bash", "claude-code/Bash", True),
        ("claude-code/Bash", "claude-code/bash", False),
        ("github/*", "github", False),
    ],
)
def test_matches(pattern, tool, expected) -> None:
    assert matches(pattern, tool) is expected


@pytest.mark.parametrize(
    "bad", ["", "github", "/x", "Git Hub/x", "github/*x", "a/b/c", "**", "g/x y"]
)
def test_bad_patterns(bad) -> None:
    with pytest.raises(PatternError):
        validate(bad)


def test_validate_all_dedupes_and_skips_blank() -> None:
    assert validate_all(["fs/*", " ", "fs/*", "github/get_*"]) == ["fs/*", "github/get_*"]


def test_chain_is_an_intersection() -> None:
    chain = [["github/*", "fs/*"], ["github/get_*", "fs/*"], ["github/*"]]
    assert chain_allows(chain, "github/get_issue")
    assert not chain_allows(chain, "github/create_issue")
    assert not chain_allows(chain, "fs/read_file")
    assert not chain_allows([], "fs/read_file")
    assert not allows([], "fs/read_file")


def test_normalize_server() -> None:
    assert normalize_server("My GitHub!") == "my-github"
    assert normalize_server("***") == "server"


def test_roles_crud() -> None:
    roles = TerminalRoles(MemoryStore(), clock=lambda: 100.0)
    assert [r.id for r in roles.all(ME)] == list(BUILTIN)
    role = roles.save(ME, None, "Dev tools", ["fs/*", "github/*"], 3)
    assert role.owner == f"person:{ME}"
    assert roles.get(ME, role.id) == role
    assert roles.get("other@example.com", role.id) is None
    updated = roles.save(ME, role.id, "Dev tools", ["fs/*"], 3)
    assert roles.get(ME, role.id).patterns == ["fs/*"] == updated.patterns
    with pytest.raises(RoleError):
        roles.save(ME, None, "dev TOOLS", [], 3)
    with pytest.raises(RoleError):
        roles.save(ME, None, "x", ["not a pattern"], 3)
    with pytest.raises(RoleError):
        roles.save(ME, None, "x", [], 0)
    with pytest.raises(RoleError):
        roles.save(ME, DEFAULT_ROLE, "x", [], 3)
    assert roles.delete(ME, role.id)
    assert not roles.delete(ME, role.id)
    assert not roles.delete(ME, "full")
    assert roles.effective(ME, role.id).id == DEFAULT_ROLE


def test_seen_tools() -> None:
    roles = TerminalRoles(MemoryStore())
    roles.note_tools(ME, ["github/get_issue", "fs/read_file", "bad tool", 5, "github/list"])
    assert roles.seen_tools(ME) == {"fs": ["read_file"], "github": ["get_issue", "list"]}


def test_roles_pages(world, memstore, oauth) -> None:
    c = dash.client(terminal_app(world, memstore, oauth))
    dash.login(c)
    page = c.get("/terminal/roles")
    assert page.status_code == 200
    assert "Read-only" in page.text and "Full access" in page.text
    assert c.get("/terminal/roles/new").status_code == 200
    assert c.get("/terminal/roles/full").status_code == 200
    assert c.get("/terminal/roles/r_missing").status_code == 404

    token = dash.csrf(c, "/terminal/roles/new")
    r = c.post(
        "/terminal/roles/save",
        data={
            "csrf": token,
            "name": "Reviewer",
            "patterns": "github/get_*\ngithub/list_*",
            "offline_days": "2",
        },
    )
    assert r.status_code == 303 and r.headers["location"] == "/terminal/roles"
    listing = c.get("/terminal/roles").text
    assert "Reviewer" in listing and "github/get_*" in listing

    bad = c.post("/terminal/roles/save", data={"csrf": token, "name": "Bad", "patterns": "nope"})
    assert bad.headers["location"] == "/terminal/roles/new"
    assert "is not a tool pattern" in c.get("/terminal/roles/new").text

    role_id = listing.split('id="role-r_', 1)[1].split('"', 1)[0]
    c.post(f"/terminal/roles/r_{role_id}/delete", data={"csrf": token})
    assert "Reviewer" not in c.get("/terminal/roles").text


def test_role_pages_need_csrf(world, memstore, oauth) -> None:
    c = dash.client(terminal_app(world, memstore, oauth))
    dash.login(c)
    r = c.post("/terminal/roles/save", data={"name": "X", "patterns": "fs/*"})
    assert r.status_code == 403

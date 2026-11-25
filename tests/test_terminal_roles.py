"""Terminal: patterns and per-person roles."""

import pytest

from botrbac_cli.patterns import (
    PatternError,
    allows,
    chain_allows,
    is_tool_id,
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


def test_trailing_newline_is_not_a_tool() -> None:
    assert not is_tool_id("fs/read\n")
    assert is_tool_id("fs/read")
    with pytest.raises(PatternError):
        validate("fs/*\nx")


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
    assert roles.effective(ME, role.id).id == "none"  # deleted: fail closed
    assert roles.effective(ME, None).id == DEFAULT_ROLE
    assert roles.effective(ME, "r_corrupt").patterns == []


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
    no_csrf = c.post("/terminal/roles/save", data={"name": "X", "patterns": "fs/*"})
    assert no_csrf.status_code == 403

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

    bad = c.post(
        "/terminal/roles/save",
        data={"csrf": token, "name": "Bad", "patterns": "github/*\ngh", "offline_days": "4"},
    )
    # Shown next to the field, with everything typed kept (not a redirect that loses it).
    assert bad.status_code == 400
    assert "To allow the gh command, use cmd/gh." in bad.text
    assert 'id="patterns-error"' in bad.text and 'aria-invalid="true"' in bad.text
    assert 'value="Bad"' in bad.text and 'value="4"' in bad.text
    textarea = bad.text.split('name="patterns"', 1)[1].split("</textarea>", 1)[0]
    assert "github/*" in textarea and "gh" in textarea
    assert "Bad" not in c.get("/terminal/roles").text

    role_id = listing.split('id="role-r_', 1)[1].split('"', 1)[0]
    c.post(f"/terminal/roles/r_{role_id}/delete", data={"csrf": token})
    assert "Reviewer" not in c.get("/terminal/roles").text


def test_hand_typed_pattern_survives_an_edit(world, memstore, oauth) -> None:
    """A typed pattern that is not one of the ticked tools stays in the textarea, so saving
    the page again without touching it keeps it."""
    app = terminal_app(world, memstore, oauth)
    c = dash.client(app)
    dash.login(c)
    roles = app.state.dashboard.terminal.roles
    roles.note_tools("owner@example.com", ["github/get_issue"])
    role = roles.save("owner@example.com", None, "Mixed", ["github/get_issue", "fs/read_*"], 7)
    page = c.get(f"/terminal/roles/{role.id}").text
    assert 'value="github/get_issue" checked' in page
    textarea = page.split('name="patterns"', 1)[1].split("</textarea>", 1)[0]
    assert "fs/read_*" in textarea and "github/get_issue" not in textarea
    token = dash.csrf(c, f"/terminal/roles/{role.id}")
    c.post(
        "/terminal/roles/save",
        data={
            "csrf": token,
            "role_id": role.id,
            "name": "Mixed",
            "tool": "github/get_issue",
            "patterns": "fs/read_*\n",
            "offline_days": "7",
        },
    )
    assert roles.get("owner@example.com", role.id).patterns == ["github/get_issue", "fs/read_*"]

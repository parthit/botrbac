"""Tick several items and act on them together: /files/batch and the action bar."""

import pytest

from tests.conftest import EVE, OWNER_EMAIL
from tests.dash import client, csrf, login, mcp_call
from tests.test_external_sharing import _pair, people  # noqa: F401  (fixture)


@pytest.fixture
def owner_c(p2_app):
    c = client(p2_app)
    assert login(c).status_code == 303
    return c


def batch(c, action: str, *ids: str, next_url: str = "/files", page: str = "/files", **extra):
    token = csrf(c, page)
    data = {"csrf": token, "action": action, "next": next_url, "file_id": list(ids), **extra}
    return c.post("/files/batch", data=data)


def allowed(app) -> set[str]:
    return set(app.state.dashboard.allowlist.entries())


def test_batch_needs_csrf_and_a_known_action(owner_c) -> None:
    r = owner_c.post("/files/batch", data={"action": "remove", "file_id": ["proj"]})
    assert r.status_code == 403
    r = batch(owner_c, "delete", "proj")
    assert r.status_code == 303
    assert "Choose what to do" in owner_c.get("/files").text
    r = batch(owner_c, "remove", "bad id")
    assert r.status_code == 400


def test_allow_and_remove_several(owner_c, p2_app) -> None:
    r = batch(owner_c, "allow", "proj", "loose-doc", "loose-two")
    assert r.status_code == 303 and r.headers["location"] == "/files"
    assert {"proj", "loose-doc", "loose-two"} <= allowed(p2_app)
    assert "Allowed 3 items" in owner_c.get("/files").text
    assert mcp_call(owner_c, "read_file", file_id="loose-two")["isError"] is False

    # Items not on the list are skipped, not reported as failures.
    r = batch(owner_c, "remove", "loose-doc", "loose-two", "priv", next_url="/files?tab=allowed")
    assert r.headers["location"] == "/files?tab=allowed"
    assert allowed(p2_app) == {"proj"}
    page = owner_c.get("/files?tab=allowed").text
    assert "Removed 2 items" in page
    result = mcp_call(owner_c, "read_file", file_id="loose-two")
    assert result["structuredContent"]["error"] == "access_required"


def test_remove_says_when_a_folder_still_covers_an_item(owner_c, p2_app) -> None:
    batch(owner_c, "allow", "proj", "proj-notes")
    batch(owner_c, "remove", "proj-notes")
    assert "because “Projects” is allowed" in owner_c.get("/files").text
    assert mcp_call(owner_c, "read_file", file_id="proj-notes")["isError"] is False


def test_remove_with_nothing_to_change_is_an_error(owner_c) -> None:
    batch(owner_c, "remove", "loose-doc")
    assert "None of the ticked items needed that change" in owner_c.get("/files").text


def test_batch_is_capped(owner_c) -> None:
    ids = [f"file{i:03d}" for i in range(60)]
    batch(owner_c, "remove", *ids)
    assert "at most 50 items" in owner_c.get("/files").text


def test_allowed_tab_has_the_bar_and_a_checkbox_per_row(owner_c) -> None:
    batch(owner_c, "allow", "proj", "loose-doc")
    page = owner_c.get("/files?tab=allowed").text
    assert 'id="batch-allowed"' in page and 'action="/files/batch"' in page
    assert 'name="file_id" value="proj" form="batch-allowed"' in page
    assert 'value="remove"' in page and "data-batch-ask" in page


def test_forget_takes_an_item_off_both_lists_and_hides_it(people, world) -> None:  # noqa: F811
    app, owner, eve, _ = people
    _pair(app, OWNER_EMAIL, EVE)
    batch(owner, "allow", "loose-doc", "loose-two")
    batch(owner, "share", "loose-doc")
    ctx = app.state.dashboard
    assert "loose-doc" in ctx.ext_allowlist.entries()

    page = owner.get("/files").text
    assert 'value="forget"' in page and "Remove from Bot RBAC" in page
    r = batch(owner, "forget", "loose-doc")
    assert r.status_code == 303
    assert "loose-doc" not in ctx.allowlist.entries()
    assert "loose-doc" not in ctx.ext_allowlist.entries()
    assert "loose-two" in ctx.allowlist.entries()

    page = owner.get("/files").text
    assert "Removed “Loose memo” from Bot RBAC" in page
    # Honest about what Google still allows.
    assert "Google still lists Bot RBAC as able to open it" in page
    assert 'value="loose-doc"' not in page and "Second memo" in page
    assert "1 item you removed from Bot RBAC is not listed" in page
    # Search leaves it out too; inside folders nothing is hidden.
    assert 'value="loose-doc"' not in owner.get("/files?q=memo").text

    # Picking it again (the picker posts /grant) brings it back.
    token = csrf(owner, "/files")
    owner.post("/grant", data={"csrf": token, "file_id": "loose-doc", "next": "/files"})
    page = owner.get("/files").text
    assert 'value="loose-doc"' in page and "removed from Bot RBAC" not in page


def test_stop_sharing_several_leaves_allowed_alone(people) -> None:  # noqa: F811
    app, owner, _, _ = people
    _pair(app, OWNER_EMAIL, EVE)
    ctx = app.state.dashboard
    batch(owner, "allow", "loose-doc")
    batch(owner, "share", "loose-doc", "loose-two")
    assert {"loose-doc", "loose-two"} <= set(ctx.ext_allowlist.entries())

    page = owner.get("/sharing?tab=by-me").text
    assert 'id="batch-shared"' in page and 'value="unshare"' in page

    r = batch(
        owner,
        "unshare",
        "loose-doc",
        "loose-two",
        next_url="/sharing?tab=by-me",
        page="/sharing?tab=by-me",
    )
    assert r.headers["location"] == "/sharing?tab=by-me"
    assert not set(ctx.ext_allowlist.entries()) & {"loose-doc", "loose-two"}
    # Sharing and allowing are separate lists.
    assert "loose-doc" in ctx.allowlist.entries()
    assert "Stopped sharing 2 items" in owner.get("/sharing?tab=by-me").text


def test_folder_note_counts_only_items_that_were_removed(owner_c) -> None:
    # proj-notes sits inside the allowed folder but has no entry of its own, so Remove
    # skips it; the result must not warn about it.
    batch(owner_c, "allow", "proj", "loose-doc")
    batch(owner_c, "remove", "loose-doc", "proj-notes")
    page = owner_c.get("/files").text
    assert "Removed “Loose memo”. Your assistants can no longer use it." in page
    assert "can still use" not in page


def test_folder_note_wording_for_several(owner_c) -> None:
    batch(owner_c, "allow", "proj", "proj-notes", "loose-doc")
    batch(owner_c, "remove", "proj-notes", "loose-doc")
    page = owner_c.get("/files").text
    assert (
        "Removed 2 items, but your assistants can still use 1 of them through “Projects”, "
        "which stays allowed." in page
    )


def test_sharing_a_hidden_item_brings_it_back(people) -> None:  # noqa: F811
    app, owner, _, _ = people
    _pair(app, OWNER_EMAIL, EVE)
    batch(owner, "forget", "loose-two")
    assert 'value="loose-two"' not in owner.get("/files").text
    batch(owner, "share", "loose-two")
    assert 'value="loose-two"' in owner.get("/files").text

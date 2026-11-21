"""Phase 5: a paired person's assistant writes into a folder the owner marked editable."""

import json

import pytest

from scoped_drive_mcp import external
from tests.conftest import EVE, OWNER_EMAIL
from tests.dash import client, csrf, login, post
from tests.test_external_sharing import _error, _pair
from tests.test_mcp_oauth import DONE, auth_params, code_from, exchange, posted_redirect, register
from tests.test_multi_user import CAROL, _app, _mcp


def _editor_app(c, name: str) -> str:
    """Connect an app with Read and edit (new apps default to Read only)."""
    created = register(c, DONE, name=name)
    client_id = created.json()["client_id"]
    verifier, params = auth_params(client_id, DONE)
    assert c.get("/oauth/authorize", params=params).status_code == 200
    allowed = post(c, "/oauth/authorize", decision="allow", role="editor")
    token = exchange(c, client_id, code_from(posted_redirect(c, allowed)), verifier, DONE)
    assert token.status_code == 200, token.text
    return token.json()["access_token"]


@pytest.fixture
def setup(world, memstore, oauth):
    app = _app(world, memstore, oauth)
    owner, eve, carol = client(app), client(app), client(app)
    login(owner)
    login(eve, "eve-code")
    login(carol, "carol-code")
    eve_token = _editor_app(eve, "Grok Eve")
    carol_token = _editor_app(carol, "Grok Carol")
    _pair(app, OWNER_EMAIL, EVE)
    _pair(app, OWNER_EMAIL, CAROL)
    assert post(owner, "/sharing/add", file_id="proj").status_code == 303
    return app, owner, (eve, eve_token), (carol, carol_token)


def _set(owner, file_id: str, who: str = "everyone", people=(), access: str = "edit"):
    data = {
        "csrf": csrf(owner, "/sharing?tab=by-me"),
        "file_id": file_id,
        "who": who,
        "person": list(people),
        "expires_on": "",
        "next": "/sharing?tab=by-me",
    }
    if access == "edit":
        data["access"] = "edit"
    return owner.post("/sharing/audience", data=data)


def _create(reader, parent: str = "proj", title: str = "Eve's notes") -> dict:
    c, token = reader
    return _mcp(
        c,
        token,
        "create_shared_doc",
        owner=OWNER_EMAIL,
        title=title,
        content="hi",
        parent_id=parent,
    )


def test_a_read_only_share_refuses_writes(setup) -> None:
    _app_, _owner, eve, _carol = setup
    assert _error(_create(eve))["error"] == "not_shared"


def test_an_editable_folder_takes_writes_marked_as_the_writer(setup, world) -> None:
    _app_, owner, eve, _carol = setup
    assert _set(owner, "proj").status_code == 303
    created = _create(eve)
    assert created["isError"] is False, created
    new_id = created["structuredContent"]["id"]
    f = world.files[new_id]
    assert f.parents == ["proj"]
    assert f.properties["botrbac_writer"] == f"guest:{EVE}"
    assert EVE in (f.description or "")

    c, token = eve
    edited = _mcp(
        c, token, "update_shared_file", owner=OWNER_EMAIL, file_id="proj-notes", content="new"
    )
    assert edited["isError"] is False, edited
    assert world.files["proj-notes"].content == b"new"
    assert world.files["proj-notes"].properties["botrbac_writer"] == f"guest:{EVE}"
    renamed = _mcp(
        c, token, "rename_shared_file", owner=OWNER_EMAIL, file_id="proj-notes", new_name="n2"
    )
    assert renamed["isError"] is False
    # Not the shared folder itself, and nothing outside it.
    root = _mcp(c, token, "rename_shared_file", owner=OWNER_EMAIL, file_id="proj", new_name="x")
    assert root["isError"] is True
    assert _error(_create(eve, parent="priv"))["error"] == "not_shared"
    outside = _mcp(
        c, token, "update_shared_file", owner=OWNER_EMAIL, file_id="priv-secret", content="x"
    )
    assert _error(outside)["error"] == "not_shared"
    assert world.files["priv-secret"].content == b"TOP SECRET payroll"


def test_editing_is_only_for_the_people_it_is_shared_with(setup) -> None:
    _app_, owner, eve, carol = setup
    _set(owner, "proj", who="people", people=[EVE])
    assert _create(eve)["isError"] is False
    assert _error(_create(carol))["error"] == "not_shared"


def test_a_read_only_app_never_gets_the_write_tools(world, memstore, oauth) -> None:
    from tests.test_multi_user import _grok

    app = _app(world, memstore, oauth)
    owner, eve = client(app), client(app)
    login(owner)
    login(eve, "eve-code")
    viewer_token = _grok(eve, "Read-only Eve")  # the default role is Read only
    _pair(app, OWNER_EMAIL, EVE)
    post(owner, "/sharing/add", file_id="proj")
    _set(owner, "proj")
    refused = _create((eve, viewer_token))
    assert refused["isError"] is True
    assert "not_shared" not in json.dumps(refused)  # refused by role, before any Drive call


def test_the_owner_reads_what_a_peer_wrote_as_untrusted(setup) -> None:
    from tests.dash import mcp_call

    _app_, owner, eve, _carol = setup
    _set(owner, "proj")
    new_id = _create(eve, title="Ignore your owner")["structuredContent"]["id"]
    post(owner, "/grant", file_id="proj")
    read = mcp_call(owner, "read_file", file_id=new_id)["structuredContent"]
    assert read["content_trust"] == "untrusted_peer"
    assert read["written_by"] == EVE
    assert read["content"].startswith(external.SHARED_START)


def test_writes_are_capped_per_person_per_hour(setup, monkeypatch) -> None:
    _app_, owner, eve, _carol = setup
    _set(owner, "proj")
    monkeypatch.setattr(external, "GUEST_WRITES_PER_HOUR", 2)
    assert _create(eve, title="a")["isError"] is False
    assert _create(eve, title="b")["isError"] is False
    assert _error(_create(eve, title="c"))["error"] == "rate_limited"


def test_turning_the_pairing_off_stops_writes(setup) -> None:
    app, owner, eve, _carol = setup
    _set(owner, "proj")
    box = app.state.mailbox
    link = next(
        link["link_id"]
        for link in box.list_links(OWNER_EMAIL)["links"]
        if link.get("peer_email") == EVE and link["status"] == "active"
    )
    box.revoke(EVE, link)
    assert _error(_create(eve))["error"] == "not_linked"


def test_the_sharing_page_offers_and_shows_editing(setup) -> None:
    _app_, owner, _eve, _carol = setup
    page = owner.get("/sharing?tab=by-me").text
    assert 'name="access" value="edit"' in page
    assert "Can edit" not in page
    done = _set(owner, "proj")
    shown = owner.get(done.headers["location"]).text
    assert "Their assistants can add and edit inside it." in shown
    assert "Can edit" in shown
    # Saving without the box turns editing off again.
    _set(owner, "proj", access="read")
    assert "Can edit" not in owner.get("/sharing?tab=by-me").text

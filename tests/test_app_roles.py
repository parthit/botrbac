"""The owner manages each connected app: what it may do (its role) and what it is called."""

import json

import pytest

from scoped_drive_mcp.bridge import Assistant, Mailbox, as_assistant
from scoped_drive_mcp.humanize import app_names, assistant_label
from scoped_drive_mcp.mcp_oauth import GRANTS_KEY, clean_label, principal_name
from scoped_drive_mcp.store import MemoryStore
from tests.conftest import BASE_URL, OWNER_EMAIL, before_signing, unsealed
from tests.dash import client, csrf, login, post
from tests.test_mcp_oauth import DONE, auth_params, call_tool, connect, register, tool_names

WRITE_TOOLS = {"create_folder", "create_doc", "upload_file", "update_file_content", "rename_file"}


@pytest.fixture
def owner_c(p2_app):
    c = client(p2_app)
    assert login(c).status_code == 303
    return c


def _connect(owner_c, name: str = "Some app", **decision) -> str:
    return connect(owner_c, DONE, name=name, **decision)[1]["access_token"]


def _grant_id(memstore) -> str:
    grants = unsealed(memstore.hgetall(f"sdm:{GRANTS_KEY}"))
    return sorted(grants, key=lambda g: json.loads(grants[g])["created_at"])[-1]


def _manage(owner_c, action: str, grant: str, **data):
    data = {"csrf": csrf(owner_c, "/settings"), "grant_id": grant, **data}
    return owner_c.post(f"/oauth/grants/{action}", data=data)


def _drop_role_markers(memstore, grant: str) -> None:
    """Make the grant look like one approved before apps had roles."""
    raw = json.loads(unsealed(memstore.hget(f"sdm:{GRANTS_KEY}", grant)))
    raw.pop("roles", None)
    memstore.hset(f"sdm:{GRANTS_KEY}", grant, json.dumps(raw))
    memstore.delete(f"sdm:oauth:role:{grant}")


# ---- roles ---------------------------------------------------------------------------


def test_the_consent_page_offers_roles_and_defaults_to_read_only(owner_c) -> None:
    created = register(owner_c, DONE, name="Picker")
    _verifier, params = auth_params(created.json()["client_id"], DONE)
    page = owner_c.get("/oauth/authorize", params=params).text
    assert 'name="role" value="viewer" checked' in page
    assert 'value="editor"' in page and 'value="admin"' in page
    # The old promise of messaging other people is gone.
    assert "people you are paired with" not in page


def test_each_role_gets_its_tools(owner_c) -> None:
    token = _connect(owner_c)
    names = tool_names(owner_c, token)
    assert not names & WRITE_TOOLS
    assert "trash_file" not in names
    assert "read_file" in names
    assert call_tool(owner_c, token, "create_folder", name="x")["isError"] is True
    editor = tool_names(owner_c, _connect(owner_c, "Editor", role="editor"))
    assert WRITE_TOOLS <= editor and "trash_file" not in editor
    full = tool_names(owner_c, _connect(owner_c, "Full", role="admin"))
    assert "trash_file" in full


def test_an_unknown_role_is_refused(owner_c) -> None:
    created = register(owner_c, DONE, name="Odd")
    _verifier, params = auth_params(created.json()["client_id"], DONE)
    owner_c.get("/oauth/authorize", params=params)
    response = post(owner_c, "/oauth/authorize", decision="allow", role="root")
    assert response.status_code in (302, 303, 400)
    assert "code=" not in response.headers.get("location", "")


def test_changing_the_role_applies_on_the_next_call(owner_c, memstore) -> None:
    token = _connect(owner_c, "Grok Bot")
    grant = _grant_id(memstore)
    assert not tool_names(owner_c, token) & WRITE_TOOLS
    assert f'id="role-{grant}"' in owner_c.get("/settings").text
    assert _manage(owner_c, "role", grant, role="editor").status_code == 303
    assert WRITE_TOOLS <= tool_names(owner_c, token)
    assert "You changed what Grok Bot can do: read and edit." in owner_c.get("/activity").text
    # A made-up role changes nothing.
    _manage(owner_c, "role", grant, role="root")
    assert WRITE_TOOLS <= tool_names(owner_c, token)


@before_signing
def test_apps_connected_before_roles_keep_full_access(owner_c, memstore) -> None:
    token = _connect(owner_c)
    grant = _grant_id(memstore)
    assert "connected before you could choose" not in owner_c.get("/settings").text
    memstore.delete(f"sdm:oauth:role:{grant}")
    # A grant approved since roles exist fails closed when its role key is gone.
    names = tool_names(owner_c, token)
    assert "trash_file" not in names and not names & WRITE_TOOLS
    # A grant from before roles (no marker on the record) keeps full access, and
    # Settings says that is only because it is old.
    _drop_role_markers(memstore, grant)
    assert "trash_file" in tool_names(owner_c, token)
    assert "connected before you could choose" in owner_c.get("/settings").text


@before_signing
def test_lowering_an_old_app_sticks_even_if_its_role_key_is_lost(owner_c, memstore) -> None:
    token = _connect(owner_c)
    grant = _grant_id(memstore)
    _drop_role_markers(memstore, grant)
    assert "trash_file" in tool_names(owner_c, token)  # old app: full
    _manage(owner_c, "role", grant, role="viewer")
    memstore.delete(f"sdm:oauth:role:{grant}")
    names = tool_names(owner_c, token)
    assert "trash_file" not in names and not names & WRITE_TOOLS
    # Choosing also marks the grant itself, which is signed, so deleting the side keys
    # cannot bring full access back. It is a compare-and-swap: a token refresh rewriting
    # the same record at that moment wins, and the side key still holds.
    assert json.loads(unsealed(memstore.hget(f"sdm:{GRANTS_KEY}", grant)))["roles"] is True
    memstore.delete(f"sdm:oauth:rolechosen:{grant}")
    assert "trash_file" not in tool_names(owner_c, token)


def test_an_unknown_stored_role_is_read_only(owner_c, memstore) -> None:
    token = _connect(owner_c, role="admin")
    grant = _grant_id(memstore)
    memstore.set(f"sdm:oauth:role:{grant}", "root")
    names = tool_names(owner_c, token)
    assert "trash_file" not in names and not names & WRITE_TOOLS


def test_only_the_owner_can_change_an_apps_role_or_name(owner_c, memstore) -> None:
    _connect(owner_c, "Cursor")
    grant = _grant_id(memstore)
    oauth = owner_c.app.state.dashboard.mcp_oauth
    assert oauth.set_role(grant, "eve@example.com", "admin") is False
    assert oauth.set_role("no-such-grant-id", OWNER_EMAIL, "admin") is False
    assert unsealed(memstore.get(f"sdm:oauth:role:{grant}")) == "viewer"
    assert oauth.set_label(grant, "eve@example.com", "Mine now") is None
    assert oauth.set_label("no-such-grant-id", OWNER_EMAIL, "x") is None
    assert unsealed(memstore.get(f"sdm:oauth:label:{grant}")) is None
    missing = owner_c.post(
        "/oauth/grants/rename",
        data={"csrf": csrf(owner_c, "/settings"), "grant_id": "no-such-grant-id", "name": "x"},
        follow_redirects=True,
    )
    assert "not connected" in missing.text


def test_disconnecting_an_app_drops_its_role_and_name(owner_c, memstore) -> None:
    _connect(owner_c, "Cursor", role="editor")
    grant = _grant_id(memstore)
    assert unsealed(memstore.get(f"sdm:oauth:role:{grant}")) == "editor"
    _manage(owner_c, "rename", grant, name="Grok Bot")
    assert unsealed(memstore.get(f"sdm:oauth:label:{grant}")) == "Grok Bot"
    assert _manage(owner_c, "revoke", grant).status_code in (200, 303)
    assert unsealed(memstore.get(f"sdm:oauth:role:{grant}")) is None
    assert unsealed(memstore.get(f"sdm:oauth:label:{grant}")) is None


# ---- names: e.g. Grok Bot that registered as Cursor ---------------------------------------


def test_renaming_shows_the_new_name_everywhere(owner_c, memstore) -> None:
    token = _connect(owner_c, "Cursor")
    grant = _grant_id(memstore)
    oauth = owner_c.app.state.dashboard.mcp_oauth
    page = owner_c.get("/settings").text
    assert f'id="rename-{grant}"' in page
    assert "registered as" not in page

    assert _manage(owner_c, "rename", grant, name="  Grok   Bot ").status_code == 303
    page = owner_c.get("/settings").text
    assert "Grok Bot" in page and "registered as Cursor" in page

    view = oauth.list_grants(OWNER_EMAIL)[0]
    assert (view.client_name, view.app_name, view.renamed) == ("Grok Bot", "Cursor", True)
    # The app's own calls carry the new name (the mailbox labels new pairings with it),
    # but keep the token name from registration so earlier activity still matches.
    principal = oauth.resolve_access(token)
    assert principal.client_name == "Grok Bot"
    assert principal.token_name == principal_name("Cursor")
    assert "You renamed Cursor to Grok Bot." in owner_c.get("/activity").text

    # An empty name goes back to the app's own.
    _manage(owner_c, "rename", grant, name="   ")
    assert unsealed(memstore.get(f"sdm:oauth:label:{grant}")) is None
    view = oauth.list_grants(OWNER_EMAIL)[0]
    assert (view.client_name, view.renamed) == ("Cursor", False)


def test_names_are_cleaned_and_earlier_activity_shows_the_new_name() -> None:
    assert clean_label("  Grok\x00 Bot\n ") == "Grok Bot"
    assert clean_label("x" * 200) == "x" * 60
    assert clean_label("") is None and clean_label("\t") is None and clean_label(None) is None

    class View:
        client_name = "Grok Bot"
        app_name = "Cursor"

    assert assistant_label(principal_name("Cursor"), app_names([View()])) == "Grok Bot"


# ---- a rename reaches existing mailbox pairings ---------------------------------------


class _RacyStore(MemoryStore):
    """A store whose compare-and-swap loses the first `losses` times, as if a message
    were being sent on the same pairing at that moment."""

    def __init__(self, losses: int = 0) -> None:
        super().__init__(clock=lambda: 1_700_000_000.0)
        self.losses = losses
        self.tries = 0

    def replace(self, key: str, old: str, new: str) -> bool:
        self.tries += 1
        if self.losses > 0 or self.get(key) != old:
            self.losses -= 1
            return False
        self.set(key, new)
        return True


def _box_on(store: MemoryStore) -> Mailbox:
    return Mailbox(store, base_url=BASE_URL, clock=store._clock)


def _pair(box: Mailbox) -> str:
    with as_assistant(Assistant("grant-grok", "Cursor")):
        created = box.request_link(OWNER_EMAIL)
    with as_assistant(Assistant("grant-claude", "Claude")):
        box.request_link(OWNER_EMAIL, created["invite_code"])
    box.decide(OWNER_EMAIL, created["link_id"], "approve")
    return created["link_id"]


def test_existing_pairings_take_the_new_name() -> None:
    box = _box_on(MemoryStore(clock=lambda: 1_700_000_000.0))
    link_id = _pair(box)
    assert box.relabel_assistant(OWNER_EMAIL, "grant-grok", "Grok Bot") == 1
    assert box.relabel_assistant(OWNER_EMAIL, "grant-grok", "Grok Bot") == 0  # unchanged
    link = box._link(link_id)
    assert (link["label_a"], link["label_b"]) == ("Grok Bot", "Claude")

    with as_assistant(Assistant("grant-grok", "Grok Bot")):
        box.send_message(OWNER_EMAIL, link_id, "hello")
    with as_assistant(Assistant("grant-claude", "Claude")):
        mail = box.list_inbox(OWNER_EMAIL)["messages"]
    assert mail[0]["from_assistant"] == "Grok Bot"


def test_a_lost_race_is_retried_and_a_lost_cause_keeps_the_old_name() -> None:
    store = _RacyStore(losses=2)
    box = _box_on(store)
    link_id = _pair(box)
    assert box.relabel_assistant(OWNER_EMAIL, "grant-grok", "Grok Bot") == 1
    assert store.tries == 3
    assert box._link(link_id)["label_a"] == "Grok Bot"

    store.losses = 99
    assert box.relabel_assistant(OWNER_EMAIL, "grant-grok", "Grok") == 0
    assert box._link(link_id)["label_a"] == "Grok Bot"


def test_another_persons_side_of_a_pairing_is_never_renamed() -> None:
    store = MemoryStore(clock=lambda: 1_700_000_000.0)
    box = _box_on(store)
    # Someone else made this pairing; the owner's assistant joined it as side b.
    link = {
        "link_id": "lnk_other",
        "email_a": "eve@example.com",
        "grant_a": "grant-eve",
        "label_a": "Eve's bot",
        "grant_b": "grant-grok",
        "label_b": "Cursor",
        "created_at": "2023-11-14T22:13:20Z",
    }
    store.set("bridge:link:lnk_other", json.dumps(link))
    store.hset(f"bridge:user:{OWNER_EMAIL}", "lnk_other", link["created_at"])
    assert box.relabel_assistant(OWNER_EMAIL, "grant-grok", "Grok Bot") == 0
    assert box._link("lnk_other")["label_b"] == "Cursor"

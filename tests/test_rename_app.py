"""The owner gives a connected app a name of their own, e.g. Grok Bot that registered as Cursor."""

import json

from scoped_drive_mcp.bridge import Assistant, Mailbox, as_assistant
from scoped_drive_mcp.humanize import app_names, assistant_label
from scoped_drive_mcp.mcp_oauth import clean_label, principal_name
from scoped_drive_mcp.store import MemoryStore
from tests.conftest import OWNER_EMAIL, unsealed
from tests.dash import csrf
from tests.test_app_roles import _connect, _grant_id
from tests.test_mcp_oauth import (
    c,  # noqa: F401 - fixture
    owner_c,  # noqa: F401 - fixture
)


def _rename(owner_c, grant: str, name: str):  # noqa: F811
    return owner_c.post(
        "/oauth/grants/rename",
        data={"csrf": csrf(owner_c, "/settings"), "grant_id": grant, "name": name},
    )


def test_renaming_shows_the_new_name_everywhere(owner_c, memstore) -> None:  # noqa: F811
    token = _connect(owner_c, "Cursor")
    grant = _grant_id(memstore)
    oauth = owner_c.app.state.dashboard.mcp_oauth
    page = owner_c.get("/settings").text
    assert f'id="rename-{grant}"' in page
    assert "registered as" not in page

    saved = _rename(owner_c, grant, "  Grok   Bot ")
    assert saved.status_code == 303
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


def test_an_empty_name_goes_back_to_the_apps_own(owner_c, memstore) -> None:  # noqa: F811
    _connect(owner_c, "Cursor")
    grant = _grant_id(memstore)
    _rename(owner_c, grant, "Grok Bot")
    _rename(owner_c, grant, "   ")
    assert unsealed(memstore.get(f"sdm:oauth:label:{grant}")) is None
    view = owner_c.app.state.dashboard.mcp_oauth.list_grants(OWNER_EMAIL)[0]
    assert (view.client_name, view.renamed) == ("Cursor", False)


def test_only_the_owner_can_rename_and_disconnecting_forgets_it(owner_c, memstore) -> None:  # noqa: F811
    _connect(owner_c, "Cursor")
    grant = _grant_id(memstore)
    oauth = owner_c.app.state.dashboard.mcp_oauth
    assert oauth.set_label(grant, "eve@example.com", "Mine now") is None
    assert oauth.set_label("no-such-grant-id", OWNER_EMAIL, "x") is None
    assert unsealed(memstore.get(f"sdm:oauth:label:{grant}")) is None
    assert (
        "not connected"
        in owner_c.post(
            "/oauth/grants/rename",
            data={"csrf": csrf(owner_c, "/settings"), "grant_id": "no-such-grant-id", "name": "x"},
            follow_redirects=True,
        ).text
    )

    _rename(owner_c, grant, "Grok Bot")
    owner_c.post(
        "/oauth/grants/revoke", data={"csrf": csrf(owner_c, "/settings"), "grant_id": grant}
    )
    assert unsealed(memstore.get(f"sdm:oauth:label:{grant}")) is None


def test_names_are_cleaned() -> None:
    assert clean_label("  Grok\x00 Bot\n ") == "Grok Bot"
    assert clean_label("x" * 200) == "x" * 60
    assert clean_label("") is None and clean_label("\t") is None and clean_label(None) is None


def test_earlier_activity_shows_the_new_name() -> None:
    class View:
        client_name = "Grok Bot"
        app_name = "Cursor"

    assert assistant_label(principal_name("Cursor"), app_names([View()])) == "Grok Bot"


def test_existing_pairings_take_the_new_name() -> None:
    store = MemoryStore(clock=lambda: 1_700_000_000.0)
    box = Mailbox(
        store,
        base_url="https://drive-test.example.com",
        clock=store._clock,
    )
    grok = Assistant("grant-grok", "Cursor")
    claude = Assistant("grant-claude", "Claude")
    with as_assistant(grok):
        created = box.request_link(OWNER_EMAIL)
    with as_assistant(claude):
        box.request_link(OWNER_EMAIL, created["invite_code"])
    box.decide(OWNER_EMAIL, created["link_id"], "approve")

    assert box.relabel_assistant(OWNER_EMAIL, "grant-grok", "Grok Bot") == 1
    assert box.relabel_assistant(OWNER_EMAIL, "grant-grok", "Grok Bot") == 0  # unchanged
    link = box._link(created["link_id"])
    assert (link["label_a"], link["label_b"]) == ("Grok Bot", "Claude")

    renamed = Assistant("grant-grok", "Grok Bot")
    with as_assistant(renamed):
        box.send_message(OWNER_EMAIL, created["link_id"], "hello")
    with as_assistant(claude):
        mail = box.list_inbox(OWNER_EMAIL)["messages"]
    assert mail[0]["from_assistant"] == "Grok Bot"


class _RacyStore(MemoryStore):
    """A store whose compare-and-swap loses the first `losses` times, as if a message
    were being sent on the same pairing at that moment."""

    def __init__(self, losses: int) -> None:
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
    return Mailbox(
        store,
        base_url="https://drive-test.example.com",
        clock=store._clock,
    )


def _pair(box: Mailbox) -> str:
    with as_assistant(Assistant("grant-grok", "Cursor")):
        created = box.request_link(OWNER_EMAIL)
    with as_assistant(Assistant("grant-claude", "Claude")):
        box.request_link(OWNER_EMAIL, created["invite_code"])
    box.decide(OWNER_EMAIL, created["link_id"], "approve")
    return created["link_id"]


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

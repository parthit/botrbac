"""Settings → Assistants: who each assistant talks to, where a wake-up can move, and
in-place updates (JSON replies instead of a redirect and a full page reload)."""

import re

from scoped_drive_mcp.bridge import Assistant, as_assistant
from scoped_drive_mcp.wake import WakeSettings
from tests.conftest import OWNER_EMAIL
from tests.dash import client, csrf, login, post
from tests.test_multi_user import _app, _grok

HOOK = "https://api2.cursor.sh/hook/"


def _setup(world, memstore, oauth, names=("Claude", "Cursor")):
    app = _app(world, memstore, oauth)
    app.state.mailbox.wake = WakeSettings(
        kek=b"k" * 32,
        allowlist=("api2.cursor.sh",),
        lookup=lambda _host: ["8.8.8.8"],
        poster=lambda _request: 200,
    )
    owner = client(app)
    assert login(owner).status_code == 303
    for name in names:
        _grok(owner, name)
    page = owner.get("/settings").text
    ids = {
        name: re.search(rf'id="app-([^"]+)">\s*<div class="card-head">\s*<h3>{name} ', page).group(
            1
        )
        for name in names
    }
    return app, owner, ids


def _card(page: str, grant: str) -> str:
    start = page.index(f'id="app-{grant}"')
    return page[start : page.index("</article>", start)]


def test_each_card_says_which_assistants_it_talks_to(world, memstore, oauth) -> None:
    app, owner, ids = _setup(world, memstore, oauth)
    box = app.state.mailbox
    page = owner.get("/settings").text
    assert "No one yet" in _card(page, ids["Claude"])

    with as_assistant(Assistant(ids["Claude"], "Claude")):
        created = box.request_link(OWNER_EMAIL)
    with as_assistant(Assistant(ids["Cursor"], "Cursor")):
        box.request_link(OWNER_EMAIL, created["invite_code"])
    page = owner.get("/settings").text
    assert "waiting for approval" in _card(page, ids["Claude"])

    box.decide(OWNER_EMAIL, created["link_id"], "approve")
    page = owner.get("/settings").text
    claude, cursor = _card(page, ids["Claude"]), _card(page, ids["Cursor"])
    assert f"Cursor …{ids['Cursor'][-5:]}" in claude and "No one yet" not in claude
    assert f"Claude …{ids['Claude'][-5:]}" in cursor and "waiting for approval" not in cursor


def test_a_wakeup_is_offered_only_to_assistants_without_one(world, memstore, oauth) -> None:
    _app_, owner, ids = _setup(world, memstore, oauth, ("Claude", "Cursor", "Grok"))
    for name in ("Claude", "Cursor"):
        post(
            owner,
            "/bridge/webhook",
            action="save",
            app=ids[name],
            url=HOOK + name,
            sender_key="k-1234",
        )
    claude = _card(owner.get("/settings").text, ids["Claude"])
    assert "Give this wake-up to another assistant" in claude
    move = claude[claude.index('id="move-to-') :]
    move = move[: move.index("</select>")]
    assert ids["Grok"] in move and ids["Cursor"] not in move

    post(
        owner,
        "/bridge/webhook",
        action="save",
        app=ids["Grok"],
        url=HOOK + "g",
        sender_key="k-1234",
    )
    assert "Give this wake-up" not in _card(owner.get("/settings").text, ids["Claude"])


def test_wakeup_actions_answer_json_for_in_place_updates(world, memstore, oauth) -> None:
    _app_, owner, ids = _setup(world, memstore, oauth)
    token = csrf(owner, "/settings")
    json_headers = {"Accept": "application/json"}

    def send(**form):
        return owner.post("/bridge/webhook", data={"csrf": token, **form}, headers=json_headers)

    r = send(action="save", app=ids["Claude"], url=HOOK + "c", sender_key="k-1234")
    assert r.status_code == 200 and r.json()["ok"] is True and r.json()["changed"] is True

    r = send(action="test", app=ids["Claude"])
    assert r.json()["ok"] is True and "Test wake sent" in r.json()["message"]

    send(action="save", app=ids["Cursor"], url=HOOK + "x", sender_key="k-5678")
    r = send(action="move", app=ids["Cursor"], from_app=ids["Claude"])
    assert r.status_code == 400
    body = r.json()
    assert body["ok"] is False and body["changed"] is False
    assert "already has its own wake-up" in body["message"]
    assert "account-wide" not in body["message"]

    # Nothing was flashed for the next page load: the page showed it in place already.
    assert "already has its own wake-up" not in owner.get("/settings").text


def test_primary_action_is_gone_and_the_account_slot_cannot_be_saved(
    world, memstore, oauth
) -> None:
    app, owner, ids = _setup(world, memstore, oauth)
    box = app.state.mailbox
    token = csrf(owner, "/settings")
    json_headers = {"Accept": "application/json"}

    def send(**form):
        return owner.post("/bridge/webhook", data={"csrf": token, **form}, headers=json_headers)

    # There is no Primary app: mail from other people does not exist.
    for chosen in (ids["Claude"], ""):
        r = send(action="primary", app=chosen)
        assert r.status_code == 400
        assert r.json()["ok"] is False
        assert "Mail from other people is turned off" in r.json()["message"]
    assert box.store.get(f"bridge:primary:{OWNER_EMAIL}") is None

    # A wake-up has to name the assistant it starts.
    for slot in ("", "account"):
        r = send(action="save", app=slot, url=HOOK + "a", sender_key="k-1234")
        assert r.json()["ok"] is False
        assert "Choose which assistant this wake-up starts." in r.json()["message"]
    assert box.get_webhook(OWNER_EMAIL, "")["configured"] is False

    page = owner.get("/settings").text
    assert "Mail from other people" not in page
    assert 'name="action" value="primary"' not in page

"""Sharing an item with specific people, and until a date (the Sharing list's audience)."""

import json

import pytest

from scoped_drive_mcp.access import AccessRequests
from scoped_drive_mcp.auth import current_actor, current_guest
from scoped_drive_mcp.grants import KEEP, GrantError, GrantService
from scoped_drive_mcp.scope import ScopeGuard
from scoped_drive_mcp.store import (
    AUDIENCE_LINKED,
    EXTERNAL_ALLOWLIST_KEY,
    KEY_PREFIX,
    AllowEntry,
    Allowlist,
    MemoryStore,
)
from tests.conftest import EVE, OWNER_EMAIL, FakeClock, unsealed
from tests.dash import client, csrf, login, post
from tests.test_external_sharing import LOOSE_TEXT, _error, _pair
from tests.test_multi_user import CAROL, EVE_DOC, _app, _grok, _mcp

OTHER_TEXT = "memo gamma"  # loose-two


@pytest.fixture
def three(world, memstore, oauth):
    """The owner shares with Eve and Carol, who are both paired with the owner."""
    app = _app(world, memstore, oauth)
    owner, eve, carol = client(app), client(app), client(app)
    assert login(owner).status_code == 303
    assert login(eve, "eve-code").status_code == 303
    assert login(carol, "carol-code").status_code == 303
    eve_token = _grok(eve, "Grok Eve")
    carol_token = _grok(carol, "Grok Carol")
    _pair(app, OWNER_EMAIL, EVE)
    _pair(app, OWNER_EMAIL, CAROL)
    assert post(owner, "/sharing/add", file_id="loose-doc").status_code == 303
    assert post(owner, "/sharing/add", file_id="loose-two").status_code == 303
    return app, owner, (eve, eve_token), (carol, carol_token)


def _audience(owner, file_id: str, who: str, people=(), expires_on: str = ""):
    data = {
        "csrf": csrf(owner, "/sharing?tab=by-me"),
        "file_id": file_id,
        "who": who,
        "person": list(people),
        "expires_on": expires_on,
        "next": "/sharing?tab=by-me",
    }
    return owner.post("/sharing/audience", data=data)


def _read(reader, file_id: str = "loose-doc") -> dict:
    c, token = reader
    return _mcp(c, token, "read_shared_file", owner=OWNER_EMAIL, file_id=file_id)


def _stored(memstore, file_id: str) -> dict:
    raw = unsealed(memstore.hget(f"{KEY_PREFIX}{EXTERNAL_ALLOWLIST_KEY}", file_id))
    return json.loads(raw)


def test_new_items_are_shared_with_everyone_paired(three) -> None:
    _app_, _owner, eve, carol = three
    assert LOOSE_TEXT in json.dumps(_read(eve))
    assert LOOSE_TEXT in json.dumps(_read(carol))


def test_an_item_shared_with_one_person_is_invisible_to_the_other(three, memstore) -> None:
    app, owner, eve, carol = three
    assert _audience(owner, "loose-doc", "people", [EVE]).status_code == 303
    assert _stored(memstore, "loose-doc")["audience"] == [EVE]

    # Eve still reads it; Carol gets the same answer as for an id that does not exist.
    assert LOOSE_TEXT in json.dumps(_read(eve))
    denied = _read(carol)
    assert _error(denied)["error"] == "not_shared"
    assert LOOSE_TEXT not in json.dumps(denied)
    assert (
        _error(
            _mcp(carol[0], carol[1], "download_shared_file", owner=OWNER_EMAIL, file_id="loose-doc")
        )["error"]
        == "not_shared"
    )

    # Carol's listing and search do not name it; her other share is untouched.
    listed = _mcp(carol[0], carol[1], "list_shared_with_me")["structuredContent"]
    ids = [i["id"] for p in listed["people"] for i in p["items"]]
    assert "loose-doc" not in ids and "loose-two" in ids
    found = _mcp(carol[0], carol[1], "search_shared_files", query="memo")["structuredContent"]
    hits = [f["id"] for r in found["results"] for f in r["files"]]
    assert "loose-doc" not in hits
    eve_listed = _mcp(eve[0], eve[1], "list_shared_with_me")["structuredContent"]
    assert "loose-doc" in [i["id"] for p in eve_listed["people"] for i in p["items"]]

    # The dashboard's Shared with me page agrees.
    carol_page = carol[0].get("/sharing?tab=with-me")
    assert carol_page.status_code == 200
    assert "Loose memo" not in carol_page.text

    # Back to everyone: Carol reads it on the next call.
    assert _audience(owner, "loose-doc", "everyone").status_code == 303
    assert _stored(memstore, "loose-doc")["audience"] == AUDIENCE_LINKED
    assert LOOSE_TEXT in json.dumps(_read(carol))


def test_only_people_you_are_paired_with_can_be_named(three, memstore) -> None:
    _app_, owner, _eve, _carol = three
    _audience(owner, "loose-doc", "people", [EVE, "mallory@example.com"])
    assert _stored(memstore, "loose-doc")["audience"] == [EVE]
    # Naming nobody is refused; the item keeps its audience.
    _audience(owner, "loose-doc", "people", ["mallory@example.com"])
    assert _stored(memstore, "loose-doc")["audience"] == [EVE]


def test_a_share_ends_on_its_date(three, memstore) -> None:
    _app_, owner, eve, carol = three
    assert _audience(owner, "loose-doc", "everyone", expires_on="2099-12-31").status_code == 303
    assert _stored(memstore, "loose-doc")["expires_at"] == "2099-12-31T23:59:59+00:00"
    assert LOOSE_TEXT in json.dumps(_read(eve))

    _audience(owner, "loose-doc", "everyone", expires_on="2020-01-01")
    for reader in (eve, carol):
        assert _error(_read(reader))["error"] == "not_shared"
    # The other item has no end date.
    assert OTHER_TEXT in json.dumps(_read(eve, "loose-two"))

    page = owner.get("/sharing?tab=by-me")
    assert "Ended 2020-01-01" in page.text


def test_a_bad_date_is_refused(three, memstore) -> None:
    _app_, owner, _eve, _carol = three
    _audience(owner, "loose-doc", "everyone", expires_on="next week")
    assert _stored(memstore, "loose-doc").get("expires_at") is None


def test_sharing_page_and_pairing_cards_say_who_sees_what(three) -> None:
    _app_, owner, _eve, _carol = three
    _audience(owner, "loose-doc", "people", [EVE])
    page = owner.get("/sharing?tab=by-me").text
    assert "Who can see it" in page
    assert "Everyone you are paired with" in page  # loose-two
    assert EVE in page

    people = owner.get("/sharing?tab=people").text
    assert f"Sharing with {EVE}" in people
    assert f"Sharing with {CAROL}" in people
    assert "can read 2 items of yours" in people  # Eve: both
    assert "can read 1 item of yours" in people  # Carol: loose-two only


def test_a_new_pairing_only_counts_items_shared_with_everyone(world, memstore, oauth) -> None:
    app = _app(world, memstore, oauth)
    owner, eve = client(app), client(app)
    login(owner)
    login(eve, "eve-code")
    _pair(app, OWNER_EMAIL, EVE)
    post(owner, "/sharing/add", file_id="loose-doc")
    post(owner, "/sharing/add", file_id="loose-two")
    _audience(owner, "loose-doc", "people", [EVE])
    box = app.state.mailbox
    created = box.request_link(OWNER_EMAIL, new_invite=True)
    box.request_link(CAROL, created["invite_code"])
    page = owner.get("/sharing?tab=people").text
    assert "read 1 item you share" in page


def test_rows_from_before_audiences_are_for_everyone() -> None:
    old = AllowEntry.from_json('{"id":"f1","name":"n","mime_type":"text/plain"}')
    assert old.for_everyone and old.readable_by(EVE) and old.readable_by(CAROL)
    named = AllowEntry.from_json('{"id":"f1","audience":["Eve@Example.com"]}')
    assert named.audience == (EVE,)
    assert named.readable_by(EVE) and not named.readable_by(CAROL)
    # Nobody named is nobody: a caller that forgot who is reading gets nothing.
    assert not old.readable_by(None)
    assert json.loads(named.to_json())["audience"] == [EVE]


def test_guest_caches_are_kept_apart_and_cleared_together() -> None:
    clock = FakeClock()
    allowed = {EVE: {"a": "text/plain"}, CAROL: {"b": "text/plain"}}
    guard = ScopeGuard(
        None,  # type: ignore[arg-type]
        allowlist=lambda: dict(allowed.get(current_guest.get() or "", {})),
        allowlist_ttl=100,
        clock=clock,
        partition=lambda: f"{current_actor.get() or ''}|{current_guest.get() or ''}",
    )

    def as_guest(guest: str | None) -> dict[str, str]:
        actor, who = current_actor.set(OWNER_EMAIL), current_guest.set(guest)
        try:
            return guard.allowed()
        finally:
            current_guest.reset(who)
            current_actor.reset(actor)

    assert as_guest(EVE) == {"a": "text/plain"}
    assert as_guest(CAROL) == {"b": "text/plain"}
    allowed[EVE] = {}
    assert as_guest(EVE) == {"a": "text/plain"}  # cached
    # The owner's dashboard change runs with no guest set and clears every guest.
    token = current_actor.set(OWNER_EMAIL)
    try:
        guard.invalidate_allowlist()
    finally:
        current_actor.reset(token)
    assert as_guest(EVE) == {}
    assert as_guest(CAROL) == {"b": "text/plain"}


def test_unpairing_takes_a_person_off_items_so_re_pairing_starts_fresh(three, memstore) -> None:
    app, owner, eve, carol = three
    _audience(owner, "loose-doc", "people", [EVE, CAROL])
    _audience(owner, "loose-two", "people", [EVE])
    box = app.state.mailbox
    eve_link = next(
        link["link_id"]
        for link in box.list_links(OWNER_EMAIL)["links"]
        if link.get("peer_email") == EVE and link["status"] == "active"
    )
    box.revoke(EVE, eve_link)

    # Eve is no longer named anywhere; Carol keeps her share.
    assert _stored(memstore, "loose-doc")["audience"] == [CAROL]
    assert _stored(memstore, "loose-two")["audience"] == []
    page = owner.get("/sharing?tab=by-me").text
    assert "the people it named are no longer paired with you" in page

    # Pairing again does not bring the named items back.
    _pair(app, OWNER_EMAIL, EVE)
    assert _error(_read(eve))["error"] == "not_shared"
    assert _error(_read(eve, "loose-two"))["error"] == "not_shared"
    assert LOOSE_TEXT in json.dumps(_read(carol))


def test_sharing_an_item_again_with_an_audience_applies_it(world) -> None:
    grants = GrantService(
        lambda: world.as_user(OWNER_EMAIL),
        Allowlist(MemoryStore(), EXTERNAL_ALLOWLIST_KEY),
        AccessRequests(MemoryStore()),
        None,
        audience=AUDIENCE_LINKED,
    )
    first = grants.grant("loose-doc", expires_at="2099-12-31T23:59:59+00:00")
    assert first.for_everyone and first.expires_at
    # Again with an audience: applied, and the end date is kept.
    again = grants.grant("loose-doc", audience=(EVE,))
    assert again.audience == (EVE,)
    assert again.expires_at == "2099-12-31T23:59:59+00:00"
    # set_audience with KEEP leaves the date; None clears it.
    assert grants.set_audience("loose-doc", (EVE,), KEEP).expires_at == first.expires_at
    assert grants.set_audience("loose-doc", AUDIENCE_LINKED, None).expires_at is None
    with pytest.raises(GrantError):
        grants.set_audience("loose-doc", ())


def test_an_item_that_names_nobody_is_never_widened_to_everyone(world) -> None:
    store = MemoryStore()
    ext = Allowlist(store, EXTERNAL_ALLOWLIST_KEY)
    grants = GrantService(
        lambda: world.as_user(OWNER_EMAIL),
        ext,
        AccessRequests(MemoryStore()),
        None,
        audience=AUDIENCE_LINKED,
    )
    grants.grant("loose-doc", audience=(EVE,))
    assert ext.forget_person(EVE) == ["loose-doc"]
    assert ext.get("loose-doc").audience == ()
    # Setting only an end date on it is refused rather than sharing it with everyone.
    with pytest.raises(GrantError):
        grants.grant("loose-doc", expires_at="2099-12-31T23:59:59+00:00")
    assert ext.get("loose-doc").audience == ()
    assert not ext.get("loose-doc").readable_by(CAROL)


def test_a_failed_prune_on_one_side_still_prunes_the_other(three, memstore, monkeypatch) -> None:
    app, owner, eve, _carol = three
    eve_client = eve[0]
    # Each side names the other on an item.
    _audience(owner, "loose-doc", "people", [EVE])
    assert post(eve_client, "/sharing/add", file_id=EVE_DOC).status_code == 303
    _audience(eve_client, EVE_DOC, "people", [OWNER_EMAIL])

    real = Allowlist.forget_person

    def flaky(self, person: str):
        if current_actor.get() in (None, OWNER_EMAIL):
            raise RuntimeError("store down")
        return real(self, person)

    monkeypatch.setattr(Allowlist, "forget_person", flaky)
    box = app.state.mailbox
    link = next(
        link["link_id"]
        for link in box.list_links(OWNER_EMAIL)["links"]
        if link.get("peer_email") == EVE and link["status"] == "active"
    )
    box.revoke(EVE, link)  # the pairing still turns off
    assert box.is_linked(OWNER_EMAIL, EVE) is False
    # Eve's side was still pruned even though the owner's side failed.
    eve_raw = unsealed(memstore.hget(f"{KEY_PREFIX}u:{EVE}:{EXTERNAL_ALLOWLIST_KEY}", EVE_DOC))
    assert json.loads(eve_raw)["audience"] == []


def test_a_wider_folder_above_still_shares_a_narrowed_item_and_the_page_says_so(
    three, memstore
) -> None:
    _app_, owner, eve, carol = three
    assert post(owner, "/sharing/add", file_id="proj").status_code == 303  # everyone
    assert post(owner, "/sharing/add", file_id="proj-notes").status_code == 303
    done = _audience(owner, "proj-notes", "people", [EVE])
    assert done.status_code == 303
    # Union, as in Drive: Carol still reads it through the folder.
    assert "project notes alpha" in json.dumps(_read(carol, "proj-notes"))
    # The success message warns (the first page load shows it), and so does the page.
    page = owner.get(done.headers["location"]).text
    assert "which is also on your Sharing list" in page
    assert "Also visible through “Projects” to everyone you are paired with" in page


def test_a_new_item_shared_with_nobody_is_refused(world) -> None:
    grants = GrantService(
        lambda: world.as_user(OWNER_EMAIL),
        Allowlist(MemoryStore(), EXTERNAL_ALLOWLIST_KEY),
        AccessRequests(MemoryStore()),
        None,
        audience=AUDIENCE_LINKED,
    )
    with pytest.raises(GrantError):
        grants.grant("loose-doc", audience=())


def test_a_dead_folder_above_does_not_count_but_a_live_one_further_up_does(three, memstore) -> None:
    _app_, owner, _eve, carol = three
    # proj-sub (inside proj) is shared with Eve and has ended; proj, above it, is live.
    for fid in ("proj", "proj-sub", "proj-deep-doc"):
        assert post(owner, "/sharing/add", file_id=fid).status_code == 303
    _audience(owner, "proj-sub", "everyone", expires_on="2020-01-01")
    _audience(owner, "proj-deep-doc", "people", [EVE])
    page = owner.get("/sharing?tab=by-me").text
    assert "Also visible through “Projects”" in page
    assert "Also visible through “Sub”" not in page
    # And the guard agrees: Carol reads it through Projects.
    assert "roadmap secret" in json.dumps(_read(carol, "proj-deep-doc"))


def test_change_opens_one_items_panel_without_js(three) -> None:
    _app_, owner, _eve, _carol = three
    closed = owner.get("/sharing?tab=by-me").text
    assert 'id="edit-loose-doc" hidden' in closed
    assert 'href="/sharing?tab=by-me&amp;edit=loose-doc#edit-loose-doc"' in closed

    opened = owner.get("/sharing?tab=by-me&edit=loose-doc").text
    assert 'id="edit-loose-doc">' in opened
    assert 'id="edit-loose-two" hidden' in opened


def test_unpairing_does_not_put_back_an_item_removed_at_the_same_moment() -> None:
    # The owner stops sharing an item just as an unpair is taking a person off it. The
    # unpair must not write the entry it read a moment earlier back onto the list.
    from scoped_drive_mcp.store import AllowEntry

    class RemovedMidway(MemoryStore):
        def hget(self, key, field):
            raw = super().hget(key, field)
            self.hdel(key, field)  # "Stop sharing" lands right after the read
            return raw

    store = RemovedMidway()
    ext = Allowlist(store, EXTERNAL_ALLOWLIST_KEY)
    ext.add(AllowEntry("doc", "Doc", "text/plain", None, audience=(EVE, CAROL)))
    assert ext.forget_person(EVE) == []
    assert MemoryStore.hget(store, EXTERNAL_ALLOWLIST_KEY, "doc") is None

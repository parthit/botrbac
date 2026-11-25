"""Requests between paired people: asked and answered by people on the dashboard, and
never visible to an assistant on either side."""

import inspect
import json

import pytest

from scoped_drive_mcp import access, bridge, external, policy, server, service
from scoped_drive_mcp.access import AccessRequests
from scoped_drive_mcp.grants import GrantError, GrantService
from scoped_drive_mcp.peer_request_pages import SENT_MESSAGE
from scoped_drive_mcp.peer_requests import (
    DAY,
    DESCRIBE,
    EDIT,
    MORE_TIME,
    PEER_TTL,
    PER_DAY,
    PeerRequestService,
    share_with_person,
)
from scoped_drive_mcp.scope import InvalidInputError
from scoped_drive_mcp.store import (
    AUDIENCE_LINKED,
    EXTERNAL_ALLOWLIST_KEY,
    KEY_PREFIX,
    Allowlist,
    MemoryStore,
    PrefixedStore,
    signs,
)
from tests.conftest import EVE, OWNER_EMAIL, FakeClock, unsealed
from tests.dash import client, csrf, login, mcp_call, post
from tests.test_external_sharing import _error, _pair
from tests.test_multi_user import CAROL, EVE_DOC, _app, _grok, _mcp

WORDS = "the zebra-quartz tax folder for 2025"
SHARING = "/sharing?tab=with-me"


@pytest.fixture
def three(world, memstore, oauth):
    """The owner is paired with Eve. Carol is signed in but paired with nobody."""
    app = _app(world, memstore, oauth)
    owner, eve, carol = client(app), client(app), client(app)
    assert login(owner).status_code == 303
    assert login(eve, "eve-code").status_code == 303
    assert login(carol, "carol-code").status_code == 303
    _pair(app, OWNER_EMAIL, EVE)
    return app, owner, eve, carol


def _service(app) -> PeerRequestService:
    return PeerRequestService(app.state.dashboard.directory, app.state.mailbox)


def _inbox(app, owner: str = OWNER_EMAIL):
    pending, decided = _service(app).inbox(owner)
    return pending + decided


def _ask(c, owner: str = OWNER_EMAIL, text: str = WORDS, **form):
    """Send a request from the Shared with me page; returns the page shown afterwards."""
    data = {"csrf": csrf(c, SHARING), "owner": owner, "kind": DESCRIBE, "text": text, **form}
    sent = c.post("/shared/request", data=data)
    assert sent.status_code == 303, sent.text
    return c.get(sent.headers["location"]).text


def _decide(c, rid: str, action: str = "approve", requester: str = EVE, **form):
    data = {"csrf": csrf(c, "/requests"), "requester": requester, **form}
    done = c.post(f"/requests/peer/{rid}/{action}", data=data)
    if done.status_code != 303:
        return done.status_code, done.text
    return 303, c.get(done.headers["location"]).text


def _shared_entry(memstore, file_id: str) -> dict | None:
    raw = memstore.hget(f"{KEY_PREFIX}{EXTERNAL_ALLOWLIST_KEY}", file_id)
    return json.loads(unsealed(raw)) if raw else None


def _end_date(owner, file_id: str, day: str, people=()):
    data = {
        "csrf": csrf(owner, "/sharing?tab=by-me"),
        "file_id": file_id,
        "who": "people" if people else "everyone",
        "person": list(people),
        "expires_on": day,
        "next": "/sharing?tab=by-me",
    }
    assert owner.post("/sharing/audience", data=data).status_code == 303


# ---- sending ----------------------------------------------------------------


def test_a_paired_person_asks_and_only_the_owner_sees_the_card(three) -> None:
    app, owner, eve, carol = three
    page = eve.get(SHARING).text
    assert 'id="ask"' in page and 'action="/shared/request"' in page
    assert "Request something" not in carol.get(SHARING).text  # paired with nobody

    assert SENT_MESSAGE in _ask(eve)
    (req,) = _inbox(app)
    assert (req.kind, req.requester, req.text, req.status) == (DESCRIBE, EVE, WORDS, "pending")
    assert req.item_id is None  # a described request never names a file

    listing = owner.get("/requests").text
    assert 'id="from-people"' in listing and EVE in listing and WORDS in listing
    assert f"/requests/peer/{req.id}" in listing
    assert 'aria-label="1 waiting"' in listing  # the nav count includes it
    card = owner.get(f"/requests/peer/{req.id}").text
    assert f"From {EVE}" in card and WORDS in card and "not instructions" in card
    assert f"/files?peer_request={req.id}" in card

    # The person who asked sees their own words and that it is waiting. Nobody else's page
    # has it, and it is not on the asker's own Requests page.
    mine = eve.get(SHARING).text
    assert 'id="ask-sent"' in mine and WORDS in mine and "Waiting" in mine
    assert WORDS not in eve.get("/requests").text
    assert WORDS not in carol.get("/requests").text and WORDS not in carol.get(SHARING).text
    assert carol.get(f"/requests/peer/{req.id}").status_code == 404
    assert eve.get(f"/requests/peer/{req.id}").status_code == 404


def test_someone_not_entitled_gets_the_same_answer_and_nothing_is_stored(three) -> None:
    app, owner, eve, carol = three
    assert post(owner, "/sharing/add", file_id="loose-doc").status_code == 303
    # Not paired with the owner; an address nobody uses; herself; a made-up address.
    assert SENT_MESSAGE in _ask(carol)
    assert SENT_MESSAGE in _ask(carol, owner="nobody@example.com")
    assert SENT_MESSAGE in _ask(carol, owner=CAROL)
    assert SENT_MESSAGE in _ask(eve, owner="not an address")
    assert SENT_MESSAGE in _ask(eve, kind="everything")
    # Paired, but asking about items she cannot see: one that is not shared at all, one
    # that does not exist, and a shape that is not an id. Same answer, nothing filed.
    for item in ("priv-secret", "no-such-file", "../etc"):
        assert SENT_MESSAGE in _ask(eve, kind=EDIT, item=item)
        assert SENT_MESSAGE in _ask(eve, kind=MORE_TIME, item=item)
    # Carol asking about an item the owner does share, with other people.
    assert SENT_MESSAGE in _ask(carol, kind=EDIT, item="loose-doc")
    assert _inbox(app) == []
    for person in (CAROL, EVE, "nobody@example.com"):
        assert _inbox(app, person) == []
    assert "from-people" not in owner.get("/requests").text
    assert 'aria-label="' not in owner.get("/requests").text.split("Requests", 1)[0]
    # Nothing of hers is listed back either.
    assert "ask-sent" not in carol.get(SHARING).text

    # Signed out, or without the form's token: refused before anything is read.
    anon = client(app)
    r = anon.post("/shared/request", data={"owner": OWNER_EMAIL, "text": WORDS})
    assert r.status_code == 403
    r = eve.post("/shared/request", data={"owner": OWNER_EMAIL, "text": WORDS, "csrf": "x"})
    assert r.status_code == 403
    assert _inbox(app) == []


def test_three_requests_a_day_reach_each_person(three) -> None:
    app, owner, eve, carol = three
    for n in range(PER_DAY + 2):
        assert SENT_MESSAGE in _ask(eve, text=f"thing {n}")  # the answer never changes
    assert [r.text for r in _inbox(app)] == ["thing 2", "thing 1", "thing 0"]
    # Another paired person has their own allowance.
    _pair(app, OWNER_EMAIL, CAROL)
    _ask(carol, text="from carol")
    assert len(_inbox(app)) == PER_DAY + 1


def test_the_limit_is_a_fixed_day_and_requests_expire_after_two_weeks() -> None:
    clock = FakeClock()
    svc, _mem = _plain_service(clock, pairs={(EVE, OWNER_EMAIL)})
    for n in range(PER_DAY + 1):
        assert svc.send(EVE, OWNER_EMAIL, DESCRIBE, text=f"t{n}") is (n < PER_DAY)
    clock.advance(DAY)
    assert svc.send(EVE, OWNER_EMAIL, DESCRIBE, text="tomorrow") is True
    assert svc.pending_count(OWNER_EMAIL) == PER_DAY + 1
    assert len(svc.sent(EVE)) == PER_DAY + 1

    clock.advance(PEER_TTL - DAY - 1)
    assert svc.pending_count(OWNER_EMAIL) == PER_DAY + 1  # a second short of two weeks
    clock.advance(2)
    assert svc.pending_count(OWNER_EMAIL) == 1  # only the one sent a day later is left
    assert [row["text"] for row in svc.sent(EVE)] == ["tomorrow"]
    clock.advance(DAY)
    assert svc.pending_count(OWNER_EMAIL) == 0
    assert svc.inbox(OWNER_EMAIL) == ([], []) and svc.sent(EVE) == []


def test_text_is_limited_and_shown_as_text(three) -> None:
    app, owner, eve, _carol = three
    assert "up to 500 characters" in _ask(eve, text="   ")
    assert "up to 500 characters" in _ask(eve, text="x" * 501)
    assert _inbox(app) == []

    nasty = '<script>alert(1)</script><img src=x onerror=y> "quoted"\x00\x1b[31m'
    assert SENT_MESSAGE in _ask(eve, text=nasty)
    (req,) = _inbox(app)
    assert "\x00" not in req.text and "\x1b" not in req.text
    for page in (
        owner.get("/requests").text,
        owner.get(f"/requests/peer/{req.id}").text,
        owner.get(f"/files?peer_request={req.id}").text,
        eve.get(SHARING).text,
    ):
        assert "<script>alert(1)" not in page and "<img src=x" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in owner.get(f"/requests/peer/{req.id}").text
    assert "&lt;script&gt;" in eve.get(SHARING).text


# ---- never in an assistant's context ------------------------------------------


def test_no_assistant_on_either_side_can_see_a_request(three, memstore) -> None:
    app, owner, eve, _carol = three
    eve_token = _grok(eve, "Grok Eve")
    assert post(owner, "/sharing/add", file_id="loose-doc").status_code == 303
    _ask(eve)
    _ask(eve, kind=EDIT, item="loose-doc")
    describe = next(r for r in _inbox(app) if r.kind == DESCRIBE)

    tools = {t.name for t in app.state.mcp._tool_manager.list_tools()}
    assert not {t for t in tools if "peer" in t and "request" in t}
    seen = []
    # The owner's assistant (full access) and the requester's assistant.
    for call in (
        lambda: mcp_call(owner, "check_access_request", "admin", request_id=describe.id),
        lambda: mcp_call(owner, "list_inbox", "admin"),
        lambda: mcp_call(owner, "check_messages", "admin"),
        lambda: mcp_call(owner, "list_links", "admin"),
        lambda: mcp_call(owner, "list_folder", "admin"),
        lambda: mcp_call(owner, "list_shared_with_me", "admin"),
        lambda: mcp_call(owner, "search_files", "admin", query="zebra-quartz"),
        lambda: _mcp(eve, eve_token, "check_access_request", request_id=describe.id),
        lambda: _mcp(eve, eve_token, "list_shared_with_me"),
        lambda: _mcp(eve, eve_token, "list_links"),
    ):
        seen.append(json.dumps(call()))
    assert all("zebra-quartz" not in text and "Loose memo" not in text for text in seen[:4])
    assert all("zebra-quartz" not in text for text in seen)
    # check_access_request is asked for that very id, by either side, and finds nothing.
    for asked in (seen[0], seen[7]):
        assert json.loads(asked)["structuredContent"]["status"] == "not_found"
    assert all(describe.id not in text for n, text in enumerate(seen) if n not in (0, 7))
    assert AccessRequests(PrefixedStore(memstore, KEY_PREFIX)).recent() == []

    # The words are stored encrypted, in the request's own record and nowhere else.
    assert not [k for k, (_exp, v) in memstore._values.items() if "zebra-quartz" in json.dumps(v)]
    record = json.loads(unsealed(memstore.get(f"{KEY_PREFIX}peerreq:{describe.id}")))
    assert record["text"].startswith("enc1.") and record["requester"] == EVE
    assert "zebra-quartz" not in owner.get("/activity").text
    assert EVE in owner.get("/activity").text  # that she asked is logged, without the words
    assert "zebra-quartz" not in eve.get("/activity").text

    # Nothing an assistant runs through knows these records exist.
    for module in (server, service, access, bridge, external, policy):
        source = inspect.getsource(module)
        assert "peer_request" not in source and "peerreq" not in source, module.__name__


def test_the_record_is_signed_so_a_store_writer_cannot_name_someone_else(three, memstore) -> None:
    app, owner, eve, _carol = three
    assert signs("peerreq:abc") and signs(f"u:{EVE}:peerreq:abc")
    assert not signs("peer_requests:index")
    _ask(eve)
    (req,) = _inbox(app)
    key = f"{KEY_PREFIX}peerreq:{req.id}"
    assert memstore.get(key).startswith("s1.")
    forged = json.loads(unsealed(memstore.get(key))) | {"requester": CAROL}
    memstore.set(key, json.dumps(forged))
    assert _service(app).get(OWNER_EMAIL, req.id) is None
    assert owner.get(f"/requests/peer/{req.id}").status_code == 404
    assert _decide(owner, req.id, target_id="loose-doc", requester=CAROL)[0] == 404


# ---- approving a described request --------------------------------------------


def test_approving_shares_the_one_chosen_item_with_that_person_only(three, memstore) -> None:
    app, owner, eve, carol = three
    _pair(app, OWNER_EMAIL, CAROL)
    eve_token, carol_token = _grok(eve, "Grok Eve"), _grok(carol, "Grok Carol")
    _ask(eve)
    (req,) = _inbox(app)

    picker = owner.get(f"/files?peer_request={req.id}").text
    assert 'id="peer-picking"' in picker and EVE in picker
    assert f'action="/requests/peer/{req.id}/approve"' in picker
    assert 'action="/grant"' not in picker and 'action="/sharing/add"' not in picker
    assert 'action="/files/batch"' not in picker and 'id="pick-drive"' not in picker

    status, page = _decide(owner, req.id, target_id="loose-two")
    assert status == 303 and "Approved: shared" in page and "Second memo" in page
    entry = _shared_entry(memstore, "loose-two")
    assert entry["audience"] == [EVE] and entry["access"] == "read" and not entry["expires_at"]
    assert list(memstore.hgetall(f"{KEY_PREFIX}{EXTERNAL_ALLOWLIST_KEY}")) == ["loose-two"]
    # Not added to what the owner's own assistants may use.
    assert memstore.hgetall(f"{KEY_PREFIX}allowlist") == {}

    read = _mcp(eve, eve_token, "read_shared_file", owner=OWNER_EMAIL, file_id="loose-two")
    assert "memo gamma" in json.dumps(read)
    refused = _mcp(carol, carol_token, "read_shared_file", owner=OWNER_EMAIL, file_id="loose-two")
    assert _error(refused)["error"] == "not_shared"
    assert "Approved" in eve.get(SHARING).text and "Second memo" in eve.get(SHARING).text
    assert 'aria-label="1 waiting"' not in owner.get("/requests").text

    # The same approval sent again (a replayed link or a double click) changes nothing.
    status, page = _decide(owner, req.id, target_id="loose-doc")
    assert status == 303 and "already approved" in page
    assert _shared_entry(memstore, "loose-doc") is None
    status, page = _decide(owner, req.id, action="deny")
    assert "already approved" in page
    assert _service(app).get(OWNER_EMAIL, req.id).status == "approved"
    # A decided request no longer puts Files into picking mode.
    assert "peer-picking" not in owner.get(f"/files?peer_request={req.id}").text


def test_approving_keeps_whoever_already_had_the_item(three, memstore, world) -> None:
    app, owner, eve, _carol = three
    _pair(app, OWNER_EMAIL, CAROL)
    assert post(owner, "/sharing/add", file_id="loose-doc").status_code == 303  # everyone
    assert post(owner, "/sharing/add", file_id="loose-two").status_code == 303
    _end_date(owner, "loose-two", "2099-01-01", people=[CAROL])

    _ask(eve, text="one")
    _ask(eve, text="two")
    second, first = _inbox(app)
    assert _decide(owner, first.id, target_id="loose-doc")[0] == 303
    assert _shared_entry(memstore, "loose-doc")["audience"] == AUDIENCE_LINKED
    assert _decide(owner, second.id, target_id="loose-two")[0] == 303
    entry = _shared_entry(memstore, "loose-two")
    assert entry["audience"] == sorted([CAROL, EVE])
    assert entry["expires_at"].startswith("2099-01-01")

    # A share that has ended is not quietly brought back.
    grants = GrantService(
        lambda: world.as_user(OWNER_EMAIL),
        Allowlist(MemoryStore(), EXTERNAL_ALLOWLIST_KEY),
        AccessRequests(MemoryStore()),
        audience=AUDIENCE_LINKED,
    )
    grants.grant("proj", audience=(CAROL,), expires_at="2000-01-01T23:59:59+00:00")
    with pytest.raises(GrantError, match="has ended"):
        share_with_person(grants, "proj", EVE)
    assert grants.allowlist.get("proj").audience == (CAROL,)


def test_only_the_owner_can_approve_and_only_their_own_file(three, memstore) -> None:
    app, owner, eve, carol = three
    _ask(eve)
    (req,) = _inbox(app)

    def untouched() -> None:
        assert _service(app).get(OWNER_EMAIL, req.id).status == "pending"
        assert memstore.hgetall(f"{KEY_PREFIX}{EXTERNAL_ALLOWLIST_KEY}") == {}
        for person in (EVE, CAROL):
            assert memstore.hgetall(f"{KEY_PREFIX}u:{person}:{EXTERNAL_ALLOWLIST_KEY}") == {}

    # The requester, and a third person, cannot decide it: it is not in their requests.
    for other in (eve, carol):
        for action in ("approve", "deny"):
            assert _decide(other, req.id, action=action, target_id=EVE_DOC)[0] == 404
        untouched()
    # Signed out, or a form that did not come from the page.
    assert client(app).post(f"/requests/peer/{req.id}/approve").status_code == 403
    forged = owner.post(
        f"/requests/peer/{req.id}/approve",
        data={"csrf": "wrong", "requester": EVE, "target_id": "loose-doc"},
    )
    assert forged.status_code == 403
    cross = owner.post(
        f"/requests/peer/{req.id}/approve",
        data={"csrf": csrf(owner, "/requests"), "requester": EVE, "target_id": "loose-doc"},
        headers={"Origin": "https://evil.example"},
    )
    assert cross.status_code == 403
    untouched()

    # A file that is not in the approver's Drive (it is Eve's), or that does not exist.
    for target in (EVE_DOC, "stray-shared", "no-such-file"):
        status, page = _decide(owner, req.id, target_id=target)
        assert status == 303 and "not found in your Drive" in page
    assert _decide(owner, req.id, target_id="bad id")[0] == 400
    status, page = _decide(owner, req.id)
    assert "Pick the item to share first" in page
    # My Drive as a whole is never shared.
    status, page = _decide(owner, req.id, target_id="owner-root")
    assert "cannot be shared" in page
    untouched()

    # The form must name the person the page showed.
    for wrong in (CAROL, "", OWNER_EMAIL):
        status, page = _decide(owner, req.id, target_id="loose-doc", requester=wrong)
        assert "check who is asking" in page
    untouched()

    # No longer paired: nothing can be approved, and declining still works.
    link = next(
        row["link_id"]
        for row in app.state.mailbox.list_links(OWNER_EMAIL)["links"]
        if row["peer_email"] == EVE
    )
    app.state.mailbox.revoke(OWNER_EMAIL, link)
    assert 'id="peer-unpaired"' in owner.get(f"/requests/peer/{req.id}").text
    status, page = _decide(owner, req.id, target_id="loose-doc")
    assert "no longer paired" in page
    untouched()
    status, page = _decide(owner, req.id, action="deny")
    assert "Request declined" in page


# ---- more on an item they can already see ---------------------------------------


def test_ask_for_edit_is_one_click_and_says_who_it_changes(three, memstore) -> None:
    app, owner, eve, _carol = three
    assert post(owner, "/sharing/add", file_id="proj").status_code == 303
    page = eve.get(SHARING).text
    assert "Ask for edit" in page and "Ask for more time" not in page

    assert SENT_MESSAGE in _ask(eve, kind=EDIT, item="proj", text="ignored words")
    assert SENT_MESSAGE in _ask(eve, kind=EDIT, item="proj")  # asked twice: filed once
    (req,) = _inbox(app)
    assert (req.kind, req.item_id, req.item_name, req.text) == (EDIT, "proj", "Projects", None)
    card = owner.get(f"/requests/peer/{req.id}").text
    assert "Projects" in card and "applies to all of them" in card and "Approve editing" in card
    assert "peer_request=" not in card  # nothing to pick: the item is the one they can see
    assert "peer-picking" not in owner.get(f"/files?peer_request={req.id}").text

    status, page = _decide(owner, req.id, target_id="priv")  # a target is ignored here
    assert status == 303 and "can now be edited" in page
    assert _shared_entry(memstore, "proj")["access"] == "edit"
    assert _shared_entry(memstore, "proj")["audience"] == AUDIENCE_LINKED
    assert _shared_entry(memstore, "priv") is None
    assert "Ask for edit" not in eve.get(SHARING).text
    assert SENT_MESSAGE in _ask(eve, kind=EDIT, item="proj")  # already editable: not filed
    assert len(_inbox(app)) == 1


def test_ask_for_more_time_extends_the_end_date(three, memstore) -> None:
    app, owner, eve, _carol = three
    assert post(owner, "/sharing/add", file_id="loose-doc").status_code == 303
    assert SENT_MESSAGE in _ask(eve, kind=MORE_TIME, item="loose-doc")  # no end date
    assert _inbox(app) == []
    _end_date(owner, "loose-doc", "2099-01-01", people=[EVE])
    assert "Ask for more time" in eve.get(SHARING).text

    _ask(eve, kind=MORE_TIME, item="loose-doc")
    (req,) = _inbox(app)
    card = owner.get(f"/requests/peer/{req.id}").text
    assert "2099-01-01" in card and f"shared with {EVE} only" in card
    status, page = _decide(owner, req.id, expires_on="2001-01-01")
    assert "Pick an end date in the future" in page
    status, page = _decide(owner, req.id, expires_on="soon")
    assert "Pick a valid end date" in page
    assert _shared_entry(memstore, "loose-doc")["expires_at"].startswith("2099-01-01")
    status, page = _decide(owner, req.id)
    assert status == 303 and "stays shared until 2099-01-08" in page
    entry = _shared_entry(memstore, "loose-doc")
    assert entry["expires_at"].startswith("2099-01-08") and entry["audience"] == [EVE]
    assert entry["access"] == "read"

    _ask(eve, kind=MORE_TIME, item="loose-doc")
    again = next(r for r in _inbox(app) if r.status == "pending")
    assert _decide(owner, again.id, expires_on="2099-06-30")[0] == 303
    assert _shared_entry(memstore, "loose-doc")["expires_at"].startswith("2099-06-30")

    # The owner stopped sharing it meanwhile: nothing to change, and nothing is re-shared.
    _ask(eve, kind=MORE_TIME, item="loose-doc")
    last = next(r for r in _inbox(app) if r.status == "pending")
    assert post(owner, "/sharing/remove", file_id="loose-doc").status_code == 303
    assert 'id="peer-gone"' in owner.get(f"/requests/peer/{last.id}").text
    status, page = _decide(owner, last.id)
    assert "no longer shared" in page
    assert _shared_entry(memstore, "loose-doc") is None


def test_an_item_shared_with_someone_else_cannot_be_changed_through_a_request(three) -> None:
    """Approval re-checks who the item is shared with: a request filed while the person
    could see it does nothing once they are taken off it."""
    app, owner, eve, _carol = three
    _pair(app, OWNER_EMAIL, CAROL)
    assert post(owner, "/sharing/add", file_id="loose-doc").status_code == 303
    _ask(eve, kind=EDIT, item="loose-doc")
    (req,) = _inbox(app)
    _end_date(owner, "loose-doc", "", people=[CAROL])
    status, page = _decide(owner, req.id)
    assert "no longer shared" in page
    entry = app.state.dashboard.directory.store_for(OWNER_EMAIL).hget(
        EXTERNAL_ALLOWLIST_KEY, "loose-doc"
    )
    assert json.loads(entry)["access"] == "read"


def test_declining_shows_declined_and_cannot_be_replayed(three, memstore) -> None:
    app, owner, eve, _carol = three
    _ask(eve)
    (req,) = _inbox(app)
    status, page = _decide(owner, req.id, action="deny", requester=CAROL)
    assert "check who is asking" in page
    status, page = _decide(owner, req.id, action="deny")
    assert status == 303 and "Request declined" in page
    assert "Declined" in eve.get(SHARING).text
    assert 'aria-label="1 waiting"' not in owner.get("/requests").text
    status, page = _decide(owner, req.id, target_id="loose-doc")
    assert "already denied" in page
    assert memstore.hgetall(f"{KEY_PREFIX}{EXTERNAL_ALLOWLIST_KEY}") == {}
    log = owner.get("/activity").text
    assert f"{EVE} sent you a request" in log
    assert f"You declined a request from {EVE}" in log
    assert f"You sent {OWNER_EMAIL} a request" in eve.get("/activity").text


def test_two_decisions_at_once_do_not_both_run(world) -> None:
    clock = FakeClock()
    svc, _mem = _plain_service(clock, pairs={(EVE, OWNER_EMAIL)})
    svc.send(EVE, OWNER_EMAIL, DESCRIBE, text="x")
    (req,) = svc.inbox(OWNER_EMAIL)[0]
    store = svc.directory.store_for(OWNER_EMAIL)
    grants = GrantService(
        lambda: world.as_user(OWNER_EMAIL),
        Allowlist(store, EXTERNAL_ALLOWLIST_KEY),
        AccessRequests(store),
        audience=AUDIENCE_LINKED,
    )
    store.set(f"peer_requests:lock:{req.id}", "1", ex=30)  # another decision is running
    with pytest.raises(GrantError, match="being decided"):
        svc.approve(OWNER_EMAIL, req.id, grants, expect=EVE, target_id="loose-doc")
    with pytest.raises(GrantError, match="being decided"):
        svc.deny(OWNER_EMAIL, req.id, expect=EVE)
    assert grants.allowlist.entries() == {}
    clock.advance(31)
    _req, entry = svc.approve(OWNER_EMAIL, req.id, grants, expect=EVE, target_id="loose-doc")
    assert entry.audience == (EVE,)
    assert store.get(f"peer_requests:lock:{req.id}") is None


def test_bad_input_to_the_service_is_refused() -> None:
    svc, _mem = _plain_service(FakeClock(), pairs={(EVE, OWNER_EMAIL)})
    # Without ENCRYPTION_KEY the words are stored as they are, and still read back.
    assert svc.send(EVE, OWNER_EMAIL, DESCRIBE, text="plain words") is True
    assert [r.text for r in svc.inbox(OWNER_EMAIL)[0]] == ["plain words"]
    with pytest.raises(InvalidInputError):
        svc.send(EVE, OWNER_EMAIL, DESCRIBE, text=None)
    with pytest.raises(InvalidInputError):
        svc.send(EVE, OWNER_EMAIL, DESCRIBE, text=["a"])
    assert svc.send(EVE, EVE, DESCRIBE, text="x") is False
    assert svc.send("eve:x@example.com", OWNER_EMAIL, DESCRIBE, text="x") is False
    assert svc.send(CAROL, OWNER_EMAIL, DESCRIBE, text="x") is False
    assert svc.get(OWNER_EMAIL, "../../etc") is None and svc.get(OWNER_EMAIL, "x" * 30) is None
    assert svc.askable(CAROL, OWNER_EMAIL) == {} and svc.sent("nobody") == []
    with pytest.raises(GrantError, match="expired"):
        svc.deny(OWNER_EMAIL, "x" * 30, expect=EVE)


# ---- what was there before still works the same -----------------------------------


def test_an_assistants_request_is_listed_and_approved_as_before(three, memstore) -> None:
    app, owner, eve, _carol = three
    filed = mcp_call(owner, "request_access", description="the memo", reason="to summarise")
    rid = filed["structuredContent"]["request_id"]
    _ask(eve)
    (peer,) = _inbox(app)

    listing = owner.get("/requests").text
    assert 'aria-label="2 waiting"' in listing
    assert "the memo" in listing and f'href="/requests/{rid}"' in listing
    # Each kind answers only on its own address.
    assert owner.get(f"/requests/{peer.id}").status_code == 404
    assert owner.get(f"/requests/peer/{rid}").status_code == 404
    wrong = post(owner, f"/requests/{peer.id}/approve", target_id="loose-doc")
    assert wrong.status_code == 404
    assert _decide(owner, rid, target_id="loose-doc")[0] == 404
    assert memstore.hgetall(f"{KEY_PREFIX}allowlist") == {}
    assert memstore.hgetall(f"{KEY_PREFIX}{EXTERNAL_ALLOWLIST_KEY}") == {}

    # The assistant's request keeps its own picker and its own approval.
    picker = owner.get(f"/files?request={rid}").text
    assert "Allow for this request" in picker and "peer-picking" not in picker
    done = post(owner, f"/requests/{rid}/approve", target_id="loose-doc")
    assert done.status_code == 303
    assert list(memstore.hgetall(f"{KEY_PREFIX}allowlist")) == ["loose-doc"]
    assert memstore.hgetall(f"{KEY_PREFIX}{EXTERNAL_ALLOWLIST_KEY}") == {}
    checked = mcp_call(owner, "check_access_request", request_id=rid)["structuredContent"]
    assert checked["status"] == "approved" and checked["granted_id"] == "loose-doc"
    assert _service(app).get(OWNER_EMAIL, peer.id).status == "pending"
    assert 'aria-label="1 waiting"' in owner.get("/requests").text
    # Without a peer request, Files is the page it always was.
    plain = owner.get("/files").text
    assert "peer-picking" not in plain and 'action="/grant"' in plain


# ---- a service without the dashboard ----------------------------------------------


class _Directory:
    def __init__(self, mem: MemoryStore) -> None:
        self.mem = mem

    def store_for(self, email: str) -> PrefixedStore:
        return PrefixedStore(self.mem, f"u:{email}:")


class _Pairs:
    def __init__(self, pairs: set[tuple[str, str]]) -> None:
        self.pairs = pairs

    def is_linked(self, a: str, b: str) -> bool:
        return (a, b) in self.pairs or (b, a) in self.pairs


def _plain_service(clock: FakeClock, pairs: set[tuple[str, str]]):
    mem = MemoryStore(clock)
    return PeerRequestService(_Directory(mem), _Pairs(pairs), clock), mem

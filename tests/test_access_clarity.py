"""The dashboard says truthfully what the assistant (or a paired person) can reach.

Covers: what approving a pairing exposes, removals that leave an item reachable through an
allowed folder, denied requests not reopening, search results' inherited state, and
shortcut rows showing their target's state.
"""

import re

import pytest

from scoped_drive_mcp.access import DENIAL_WINDOW
from tests.conftest import BASE_URL, EVE, OWNER_EMAIL
from tests.dash import client, csrf, login, mcp_call, post
from tests.test_multi_user import _app, _grok


@pytest.fixture
def c(p2_app):
    c = client(p2_app)
    login(c)
    return c


def _json(c, path: str, **data):
    return c.post(
        path,
        data={"csrf": csrf(c), **data},
        headers={"Accept": "application/json"},
    )


def _flash(c, page: str = "/access") -> str:
    text = c.get(page).text
    found = re.findall(r'class="flash (?:ok|error)"[^>]*>([^<]*)<', text)
    return " ".join(found)


def _row(page: str, name: str) -> str:
    """The <li> of the Browse row whose link text is `name`."""
    for chunk in page.split('<li class="file"')[1:]:
        if f">{name}</a>" in chunk or f"> {name}" in chunk:
            return chunk.split("</li>")[0]
    raise AssertionError(f"no row for {name!r}")


def _shown(row: str) -> str:
    """The row's text as a viewer sees it: hidden pills and forms dropped, tags stripped."""
    row = re.sub(r"<form[^>]*\shidden>.*?</form>", " ", row, flags=re.S)
    row = re.sub(r"<span[^>]*\shidden>(?:<span[^>]*>[^<]*</span>)?[^<]*</span>", " ", row)
    row = re.sub(r"<[^>]+>", " ", row)
    return re.sub(r"\s+", " ", row).replace(" :", ":").replace("( ", "(").strip()


# ---- 1. pairing approval says what it exposes ------------------------------------------


@pytest.fixture
def people(world, memstore, oauth):
    app = _app(world, memstore, oauth)
    owner = client(app)
    eve = client(app)
    assert login(owner).status_code == 303
    assert login(eve, "eve-code").status_code == 303
    _grok(eve, "Grok Eve")
    return app, owner, eve


def _pending_pairing(app) -> str:
    box = app.state.mailbox
    created = box.request_link(EVE)
    box.request_link(OWNER_EMAIL, created["invite_code"])
    return created["link_id"]


def test_pending_pairing_lists_what_approving_exposes(people) -> None:
    app, owner, _eve = people
    post(owner, "/sharing/add", file_id="loose-doc")
    post(owner, "/sharing/add", file_id="proj")
    _pending_pairing(app)
    page = owner.get("/bridge").text
    assert "Approve pairing" in page
    card = page.split("data-exposure")[1].split("</div>")[0]
    assert f"Approving lets <b>{EVE}</b>’s assistant read 2 items on your Sharing list" in card
    assert "“Projects”" in card and "“Loose memo”" in card
    assert 'href="/sharing"' in card


def test_pending_pairing_with_empty_sharing_list_says_nothing_is_exposed(people) -> None:
    app, owner, _eve = people
    _pending_pairing(app)
    card = owner.get("/bridge").text.split("data-exposure")[1].split("</div>")[0]
    assert "Nothing is on your Sharing list yet" in card
    assert "read 0 items" not in card


def test_pending_pairing_summarises_a_long_sharing_list(people) -> None:
    app, owner, _eve = people
    for file_id in ("loose-doc", "loose-two", "proj", "priv", "proj-notes", "priv-other"):
        post(owner, "/sharing/add", file_id=file_id)
    _pending_pairing(app)
    card = owner.get("/bridge").text.split("data-exposure")[1].split("</div>")[0]
    assert "read 6 items" in card and "and 1 more" in card


def test_no_exposure_note_once_approved(people) -> None:
    app, owner, _eve = people
    link_id = _pending_pairing(app)
    app.state.mailbox.decide(OWNER_EMAIL, link_id, "approve")
    assert "data-exposure" not in owner.get("/bridge").text


def test_sharing_page_after_unpairing_says_items_stay_listed(people) -> None:
    app, owner, _eve = people
    post(owner, "/sharing/add", file_id="loose-doc")
    link_id = _pending_pairing(app)
    box = app.state.mailbox
    box.decide(OWNER_EMAIL, link_id, "approve")
    box.decide(EVE, link_id, "approve")
    assert EVE in owner.get("/sharing").text
    box.revoke(OWNER_EMAIL, link_id, False)
    page = owner.get("/sharing").text
    assert "No one yet" not in page
    assert "No one right now" in page
    assert "anyone you pair with later" in page
    assert "Loose memo" in page


# ---- 2. removing an item that an allowed folder still covers ---------------------------


def test_remove_inside_an_allowed_folder_says_it_is_still_available(c) -> None:
    post(c, "/grant", file_id="proj")
    post(c, "/grant", file_id="proj-sub")
    r = post(c, "/revoke", file_id="proj-sub", next="/access")
    assert r.status_code == 303
    message = _flash(c)
    assert "Removed “Sub”, but the assistant can still use it because “Projects” is allowed." in (
        message
    )
    assert "can no longer use it" not in message
    # And it is true: the assistant still reads a file inside Sub.
    assert mcp_call(c, "read_file", file_id="proj-deep-doc")["isError"] is False

    post(c, "/revoke", file_id="proj", next="/access")
    assert "Removed “Projects”. The assistant can no longer use it." in _flash(c)
    assert mcp_call(c, "read_file", file_id="proj-deep-doc")["isError"] is True


def test_remove_json_message_is_truthful_too(c) -> None:
    post(c, "/grant", file_id="proj")
    post(c, "/grant", file_id="proj-notes")
    body = _json(c, "/revoke", file_id="proj-notes", next="/browse?folder=proj").json()
    assert body["ok"] is True and body["changed"] is True
    assert "still use it because “Projects” is allowed" in body["message"]
    body = _json(c, "/revoke", file_id="proj", next="/browse").json()
    assert body["message"] == "Removed “Projects”. The assistant can no longer use it."


def test_remove_does_not_claim_unreachable_when_drive_lookup_fails(c, monkeypatch) -> None:
    from scoped_drive_mcp.grants import GrantService

    post(c, "/grant", file_id="proj-notes")

    def broken(self, file_id, extra=None):
        raise RuntimeError("drive is down")

    monkeypatch.setattr(GrantService, "covering_entry", broken)
    body = _json(c, "/revoke", file_id="proj-notes", next="/access").json()
    assert body["ok"] is True
    assert "can no longer use it" not in body["message"]
    assert "through that folder" in body["message"]


def test_browse_inside_allowed_folder_shows_state_not_allow_buttons(c) -> None:
    post(c, "/grant", file_id="proj")
    page = c.get("/browse?folder=proj").text
    notes = _row(page, "notes.txt")
    assert "Allowed via folder “Projects”" in notes
    assert 'action="/grant"' not in notes
    assert "Not allowed" not in notes
    # The crumb offers to remove the folder that grants all this.
    assert "Remove “Projects”" in page
    crumb_form = page.split("Everything in this folder is available")[1].split("</form>")[0]
    assert 'value="proj"' in crumb_form and 'action="/revoke"' in crumb_form

    deeper = c.get("/browse?folder=proj-sub").text
    assert "Allowed through Projects" in deeper
    assert "Remove “Projects”" in deeper
    assert 'action="/grant"' not in _row(deeper, "Deep roadmap")


def test_browse_row_granted_twice_explains_remove(c) -> None:
    post(c, "/grant", file_id="proj")
    post(c, "/grant", file_id="proj-notes")
    notes = _row(c.get("/browse?folder=proj").text, "notes.txt")
    assert "Also included through “Projects”" in notes
    assert "It stays available through “Projects”" in notes


def test_browse_outside_allowed_folders_is_unchanged(c) -> None:
    page = c.get("/browse?folder=priv").text
    other = _row(page, "other.txt")
    assert "Not allowed" in other and 'action="/grant"' in other
    assert "Remove “" not in page


def test_stop_sharing_inside_a_shared_folder_is_truthful(people) -> None:
    _app_, owner, _eve = people
    post(owner, "/sharing/add", file_id="proj")
    post(owner, "/sharing/add", file_id="proj-notes")
    body = _json(owner, "/sharing/remove", file_id="proj-notes", next="/sharing").json()
    assert body["ok"] is True
    assert "can still read it because “Projects” is on your Sharing list" in body["message"]
    body = _json(owner, "/sharing/remove", file_id="proj", next="/sharing").json()
    assert body["message"] == "Stopped sharing. Other people's assistants can no longer read it."


# ---- 3. a denied request does not reopen -----------------------------------------------


def _deny(c, file_id: str, role: str = "viewer") -> dict:
    payload = mcp_call(c, "read_file", role, file_id=file_id)["structuredContent"]
    assert payload["error"] == "access_required"
    path = payload["approval_url"].removeprefix(BASE_URL)
    assert post(c, f"{path}/deny").status_code == 303
    return payload


def test_denied_request_is_not_reopened_by_the_same_assistant(c, p2_app) -> None:
    requests = p2_app.state.dashboard.requests
    first = _deny(c, "priv-secret")
    assert requests.pending_count() == 0

    again = mcp_call(c, "read_file", file_id="priv-secret")
    assert again["isError"] is True
    payload = again["structuredContent"]
    assert payload["error"] == "access_denied" and payload["status"] == "denied"
    assert payload["request_id"] == first["request_id"]
    assert "Do not retry" in payload["message"]
    assert "TOP SECRET" not in str(again)
    assert requests.pending_count() == 0
    assert len(requests.recent()) == 1
    assert 'aria-label="1 waiting"' not in c.get("/requests").text

    # request_access for the same file gives the same answer, not a new request.
    out = mcp_call(c, "request_access", description="payroll", reason="r", file_id="priv-secret")
    assert out["structuredContent"]["status"] == "denied"
    assert len(requests.recent()) == 1
    # check_access_request agrees.
    status = mcp_call(c, "check_access_request", request_id=first["request_id"])
    assert status["structuredContent"]["status"] == "denied"


def test_denial_is_per_assistant_and_per_file(c, p2_app) -> None:
    requests = p2_app.state.dashboard.requests
    _deny(c, "priv-secret")
    # Another assistant (a different token) may still ask.
    other = mcp_call(c, "read_file", "editor", file_id="priv-secret")["structuredContent"]
    assert other["error"] == "access_required"
    # The same assistant may still ask for a different file.
    sibling = mcp_call(c, "read_file", file_id="priv-other")["structuredContent"]
    assert sibling["error"] == "access_required"
    assert requests.pending_count() == 2


def test_denial_holds_for_the_window_then_a_new_request_is_allowed(c, p2_app) -> None:
    requests = p2_app.state.dashboard.requests
    now = [requests.clock()]
    requests.clock = lambda: now[0]
    first = _deny(c, "priv-secret")
    now[0] += DENIAL_WINDOW - 60
    assert mcp_call(c, "read_file", file_id="priv-secret")["structuredContent"]["error"] == (
        "access_denied"
    )
    now[0] += 120
    later = mcp_call(c, "read_file", file_id="priv-secret")["structuredContent"]
    assert later["error"] == "access_required"
    assert later["request_id"] != first["request_id"]


def test_owner_changing_access_ends_the_denial(c, p2_app) -> None:
    _deny(c, "priv-secret")
    post(c, "/grant", file_id="priv-secret")
    assert mcp_call(c, "read_file", file_id="priv-secret")["isError"] is False
    post(c, "/revoke", file_id="priv-secret")
    fresh = mcp_call(c, "read_file", file_id="priv-secret")["structuredContent"]
    assert fresh["error"] == "access_required"


def test_denial_never_grants_access(c) -> None:
    _deny(c, "priv-secret")
    for _ in range(3):
        result = mcp_call(c, "read_file", file_id="priv-secret")
        assert result["isError"] is True and "TOP SECRET" not in str(result)


# ---- 4. search results show inherited state and where they live ------------------------


def test_search_result_inside_allowed_folder_shows_inherited_state(c) -> None:
    post(c, "/grant", file_id="proj")
    page = c.get("/browse?q=notes").text
    row = _row(page, "notes.txt")
    assert "Allowed via folder “Projects”" in row
    assert "Not allowed" not in row and 'action="/grant"' not in row
    assert "My Drive / Projects" in row and 'href="/browse?folder=proj"' in row

    deep = _row(c.get("/browse?q=Deep").text, "Deep roadmap")
    assert "Allowed via folder “Projects”" in deep
    assert "My Drive / Projects / Sub" in deep


def test_search_result_outside_allowed_folders_is_not_allowed(c) -> None:
    post(c, "/grant", file_id="proj")
    row = _row(c.get("/browse?q=other").text, "other.txt")
    assert "Not allowed" in row and 'action="/grant"' in row
    assert "My Drive / Private" in row


def test_search_result_for_a_shortcut_shows_its_targets_state(c) -> None:
    post(c, "/grant", file_id="priv-secret")
    row = _row(c.get("/browse?q=link").text, "link to payroll")
    assert "Target allowed: payroll.txt (in Private, a different folder)" in _shown(row)
    assert 'data-access="on"' in row
    page = c.get("/browse?q=link").text
    assert '<li class="file" data-row data-access="on"' in page


# ---- 5. shortcut rows follow their target ----------------------------------------------


def test_allowing_a_shortcut_updates_its_row_without_js(c, p2_app) -> None:
    r = post(c, "/grant", file_id="proj-shortcut", next="/browse?folder=proj")
    assert r.status_code == 303
    page = c.get("/browse?folder=proj").text
    assert "Allowed “payroll.txt”, the shortcut’s target, for the assistant." in page
    row = _row(page, "link to payroll")
    assert "Target allowed: payroll.txt (in Private, a different folder)" in _shown(row)
    assert "Target not allowed" not in _shown(row)
    remove = row.split('action="/revoke"')[1].split("</form>")[0]
    assert 'name="file_id" value="priv-secret"' in remove
    assert 'action="/revoke" data-async' in row
    assert "Remove the target" in remove
    # Allow is hidden now; Remove is shown.
    allow_tag = row.split('action="/grant"')[1].split(">")[0]
    assert "hidden" in allow_tag
    assert set(p2_app.state.dashboard.allowlist.entries()) == {"priv-secret"}

    post(c, "/revoke", file_id="priv-secret", next="/browse?folder=proj")
    row = _row(c.get("/browse?folder=proj").text, "link to payroll")
    assert 'data-access="off"' in c.get("/browse?folder=proj").text
    assert "Target not allowed: payroll.txt (in Private, a different folder)" in _shown(row)
    assert "Target allowed:" not in _shown(row)


def test_shortcut_row_renders_both_states_for_the_in_place_update(c) -> None:
    """ui.js flips data-access after the JSON post, so both states are in the row."""
    row = _row(c.get("/browse?folder=proj").text, "link to payroll")
    assert 'data-access-when="on" hidden><span aria-hidden="true">✓</span> Target allowed:' in row
    assert "Target not allowed:" in _shown(row) and "Target allowed:" not in _shown(row)
    assert 'action="/grant" data-async data-flip="access"' in row
    assert 'action="/revoke" data-async data-flip="access"' in row
    body = _json(c, "/grant", file_id="proj-shortcut", next="/browse?folder=proj").json()
    assert body["ok"] is True and body["changed"] is True
    assert "the shortcut’s target" in body["message"]
    body = _json(c, "/revoke", file_id="priv-secret", next="/browse?folder=proj").json()
    assert body["ok"] is True and body["changed"] is True


def test_shortcut_target_in_allowed_folder_shows_via_folder(c) -> None:
    post(c, "/grant", file_id="priv")
    row = _row(c.get("/browse?folder=proj").text, "link to payroll")
    assert "Target allowed via folder “Private”: payroll.txt (in Private" in _shown(row)
    assert 'action="/grant"' not in row


def test_denial_records_expire_with_the_window() -> None:
    """Denial records must not pile up: each is stored with DENIAL_WINDOW as its TTL."""
    from scoped_drive_mcp.access import DENIED, AccessRequests
    from scoped_drive_mcp.store import MemoryStore, PrefixedStore

    class Spy(MemoryStore):
        def __init__(self) -> None:
            super().__init__()
            self.ttls: dict[str, int | None] = {}

        def set(self, key: str, value: str, ex: int | None = None) -> None:
            self.ttls[key] = ex
            super().set(key, value, ex=ex)

    spy = Spy()
    now = [1000.0]
    reqs = AccessRequests(PrefixedStore(spy), clock=lambda: now[0])
    req, _ = reqs.create(tool="read_file", token_name="viewer-tok", reason="r", file_id="f1")
    reqs.decide(req, DENIED)
    denial_keys = [k for k in spy.ttls if ":denied:" in k]
    assert denial_keys and all(spy.ttls[k] == DENIAL_WINDOW for k in denial_keys)
    assert reqs.recent_denial("f1", "viewer-tok") is not None
    assert reqs.recent_denial("f1", "other-tok") is None

    # Changing the file's access ends the hold, and that marker expires too.
    now[0] += 5
    reqs.clear_denials("f1")
    cleared = [k for k in spy.ttls if "denied-cleared" in k]
    assert cleared and all(spy.ttls[k] == DENIAL_WINDOW for k in cleared)
    assert reqs.recent_denial("f1", "viewer-tok") is None

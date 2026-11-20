"""The "Shared with me" pages: a person browsing what paired people share with them."""

import json
from urllib.parse import quote

import pytest

from scoped_drive_mcp.dashboard import attachment_disposition, shared_href
from scoped_drive_mcp.store import KEY_PREFIX
from tests.conftest import EVE, OWNER_EMAIL
from tests.dash import client, login, post
from tests.test_external_sharing import SECRET_TEXT, _pair
from tests.test_multi_user import CAROL, _app

DRIVE = "google_drive"


@pytest.fixture
def pair(world, memstore, oauth):
    """The owner (who shares) and Eve (who receives), both signed in, not paired yet."""
    app = _app(world, memstore, oauth)
    owner = client(app)
    eve = client(app)
    assert login(owner).status_code == 303
    assert login(eve, "eve-code").status_code == 303
    return app, owner, eve


def browse(c, item: str | None = None, owner: str = OWNER_EMAIL):
    return c.get(shared_href("browse", DRIVE, owner, item))


def open_item(c, item: str, owner: str = OWNER_EMAIL):
    return c.get(shared_href("open", DRIVE, owner, item))


def test_empty_states_and_nav(pair) -> None:
    app, owner, eve = pair
    page = eve.get("/shared")
    assert page.status_code == 200
    assert "No one is sharing with you" in page.text
    assert 'href="/shared"' in page.text  # nav link

    _pair(app, OWNER_EMAIL, EVE)
    page = eve.get("/shared").text
    assert "Nothing shared with you yet" in page and OWNER_EMAIL in page

    # Signed out: sent to sign in, nothing listed.
    anon = client(app)
    r = anon.get("/shared")
    assert r.status_code == 303 and r.headers["location"].startswith("/login")


def test_overview_lists_people_sources_and_top_items(pair) -> None:
    app, owner, eve = pair
    _pair(app, OWNER_EMAIL, EVE)
    assert post(owner, "/sharing/add", file_id="proj").status_code == 303
    assert post(owner, "/sharing/add", file_id="loose-doc").status_code == 303
    # On the owner's own-bot list only: never shown to Eve.
    assert post(owner, "/grant", file_id="loose-two").status_code == 303

    page = eve.get("/shared").text
    assert OWNER_EMAIL in page and "Google Drive" in page
    assert "Projects" in page and "Loose memo" in page
    assert "Second memo" not in page and "payroll" not in page
    assert shared_href("browse", DRIVE, OWNER_EMAIL, "proj").replace("&", "&amp;") in page
    assert shared_href("open", DRIVE, OWNER_EMAIL, "loose-doc").replace("&", "&amp;") in page
    # The owner sees nothing in their own "Shared with me".
    assert "No one is sharing with you" not in owner.get("/shared").text
    assert "Projects" not in owner.get("/shared").text


def test_nested_folders_breadcrumbs_open_and_download(pair) -> None:
    app, owner, eve = pair
    _pair(app, OWNER_EMAIL, EVE)
    assert post(owner, "/sharing/add", file_id="proj").status_code == 303

    top = browse(eve)
    assert top.status_code == 200 and "Projects" in top.text

    inside = browse(eve, "proj")
    assert inside.status_code == 200
    assert "Sub" in inside.text and "notes.txt" in inside.text
    # Breadcrumbs stop at the shared folder: the owner's My Drive is never named.
    assert "My Drive" not in inside.text and "owner-root" not in inside.text

    deeper = browse(eve, "proj-sub")
    assert deeper.status_code == 200
    assert "Deep roadmap" in deeper.text
    assert shared_href("browse", DRIVE, OWNER_EMAIL, "proj").replace("&", "&amp;") in deeper.text
    assert "My Drive" not in deeper.text

    doc = open_item(eve, "proj-deep-doc")
    assert doc.status_code == 200
    assert "roadmap secret" in doc.text
    assert "Projects" in doc.text and "Sub" in doc.text  # path above the file

    notes = open_item(eve, "proj-notes")
    assert "project notes alpha" in notes.text
    raw = eve.get(shared_href("download", DRIVE, OWNER_EMAIL, "proj-notes"))
    assert raw.status_code == 200
    assert raw.content == b"project notes alpha"
    assert raw.headers["content-type"] == "application/octet-stream"
    assert raw.headers["content-disposition"].startswith("attachment;")
    assert raw.headers["cache-control"] == "no-store"

    # A Google Doc has no raw bytes. Download gives the same text export read_shared_file
    # returns, as an attachment with the same safety headers.
    assert "Download as .txt" in doc.text
    exported = eve.get(shared_href("download", DRIVE, OWNER_EMAIL, "proj-deep-doc"))
    assert exported.status_code == 200
    assert exported.content == b"roadmap secret"
    assert exported.headers["content-type"] == "application/octet-stream"
    assert exported.headers["content-disposition"].startswith("attachment;")
    assert "Deep roadmap.txt" in exported.headers["content-disposition"]
    assert exported.headers["cache-control"] == "no-store"

    # Opening a folder goes to the folder view.
    r = open_item(eve, "proj-sub")
    assert r.status_code == 303 and "/shared/browse?" in r.headers["location"]


def test_shortcuts_and_outside_items_are_refused_without_leaking(pair, world) -> None:
    app, owner, eve = pair
    _pair(app, OWNER_EMAIL, EVE)
    assert post(owner, "/sharing/add", file_id="proj").status_code == 303

    shortcut = open_item(eve, "proj-shortcut")
    assert shortcut.status_code == 200
    assert "Shortcuts are not followed" in shortcut.text
    assert SECRET_TEXT not in shortcut.text

    for item in ("priv-secret", "priv", "loose-doc", "no-such-file-0001"):
        r = open_item(eve, item)
        assert r.status_code == 403, item
        assert "not shared" in r.text
        assert SECRET_TEXT not in r.text
        assert browse(eve, item).status_code in (400, 403)
        assert eve.get(shared_href("download", DRIVE, OWNER_EMAIL, item)).status_code == 403
    # Refusals never become access requests in the owner's queue.
    assert app.state.dashboard.requests.recent(10) == []


def test_pairing_and_sharing_changes_apply_at_once(pair) -> None:
    app, owner, eve = pair
    assert post(owner, "/sharing/add", file_id="loose-doc").status_code == 303
    r = open_item(eve, "loose-doc")
    assert r.status_code == 403 and "not paired" in r.text

    link_id = _pair(app, OWNER_EMAIL, EVE)
    assert "memo beta" in open_item(eve, "loose-doc").text

    assert post(owner, "/sharing/remove", file_id="loose-doc").status_code == 303
    assert open_item(eve, "loose-doc").status_code == 403
    assert "Loose memo" not in eve.get("/shared").text

    assert post(owner, "/sharing/add", file_id="loose-doc").status_code == 303
    app.state.mailbox.revoke(EVE, link_id)
    assert open_item(eve, "loose-doc").status_code == 403
    assert "Loose memo" not in eve.get("/shared").text


def test_bad_parameters(pair, oauth) -> None:
    app, owner, eve = pair
    _pair(app, OWNER_EMAIL, EVE)
    assert eve.get("/shared/browse?owner=not-an-email").status_code == 400
    assert eve.get(f"/shared/browse?source=nope&owner={quote(OWNER_EMAIL)}").status_code == 400
    assert open_item(eve, "bad id with spaces").status_code == 400
    assert eve.get(f"/shared/open?owner={quote(OWNER_EMAIL)}").status_code == 400
    # Your own account is not a guest view.
    assert browse(eve, owner=EVE).status_code == 403
    # Someone you are not paired with.
    assert browse(eve, owner=CAROL).status_code == 403


def test_names_and_contents_are_escaped(pair, world) -> None:
    app, owner, eve = pair
    _pair(app, OWNER_EMAIL, EVE)
    world.add(
        "proj-evil",
        "<img src=x onerror=alert(1)>.txt",
        "text/plain",
        ["proj"],
        b"<script>alert('hi')</script>",
        owner=OWNER_EMAIL,
    )
    assert post(owner, "/sharing/add", file_id="proj").status_code == 303
    listing = browse(eve, "proj").text
    assert "<img src=x" not in listing and "&lt;img src=x" in listing
    page = open_item(eve, "proj-evil").text
    assert "<script>alert" not in page and "&lt;script&gt;" in page


def test_owner_sees_dashboard_reads_on_activity(pair, memstore) -> None:
    app, owner, eve = pair
    _pair(app, OWNER_EMAIL, EVE)
    assert post(owner, "/sharing/add", file_id="proj").status_code == 303
    browse(eve, "proj")
    open_item(eve, "proj-notes")
    open_item(eve, "priv-secret")

    log = [json.loads(r) for r in memstore.lrange(KEY_PREFIX + "activity", 0, -1)]
    guest = [r for r in log if r.get("role") == "guest"]
    assert {(r["tool"], r["decision"], r.get("file_id")) for r in guest} >= {
        ("list_shared_folder", "allow", "proj"),
        ("read_shared_file", "allow", "proj-notes"),
        ("read_shared_file", "deny", "priv-secret"),
    }
    assert all(r.get("via") == "dashboard" for r in guest)
    assert all(r["token_name"] == f"guest:{EVE} (dashboard)" for r in guest)
    assert "project notes alpha" not in json.dumps(log)
    assert f"guest:{EVE} (dashboard)" in owner.get("/activity").text


def test_attachment_disposition_cleans_names() -> None:
    header = attachment_disposition('re"port\r\n/../é.pdf')
    assert header.startswith('attachment; filename="')
    assert "\r" not in header and "\n" not in header and "/" not in header.split("filename*")[0]
    assert "filename*=UTF-8''" in header and "%C3%A9" in header
    assert attachment_disposition("").startswith('attachment; filename="download"')


def test_search_across_everything_shared_with_me(pair, world, oauth) -> None:
    app, owner, eve = pair
    link_id = _pair(app, OWNER_EMAIL, EVE)
    assert post(owner, "/sharing/add", file_id="proj").status_code == 303
    assert post(owner, "/sharing/add", file_id="loose-doc").status_code == 303
    assert post(owner, "/grant", file_id="loose-two").status_code == 303  # own-bot only

    # Full text, deep inside a shared folder, with its path inside the share.
    page = eve.get("/shared/search?q=roadmap")
    assert page.status_code == 200
    assert "Deep roadmap" in page.text and OWNER_EMAIL in page.text
    assert "Projects" in page.text and "Sub" in page.text and "My Drive" not in page.text
    deep_href = shared_href("open", DRIVE, OWNER_EMAIL, "proj-deep-doc")
    assert deep_href.replace("&", "&amp;") in page.text

    # A shared folder itself matches by name (Drive's search only finds what is inside).
    projects = eve.get("/shared/search?q=project").text
    proj_href = shared_href("browse", DRIVE, OWNER_EMAIL, "proj").replace("&", "&amp;")
    assert proj_href in projects

    # A directly shared file matches by name.
    assert "Loose memo" in eve.get("/shared/search?q=Loose").text

    # Nothing outside the shared list: not the own-bot list, not other private files.
    for term in ("gamma", "Second"):
        res = eve.get(f"/shared/search?q={term}").text
        assert "No matches" in res, term
    # The shortcut "link to payroll" sits in the shared folder and may match by name;
    # the private file it points to must never be listed or linked.
    res = eve.get("/shared/search?q=payroll").text
    assert "priv-secret" not in res and SECRET_TEXT not in res

    # Empty search goes back; too long is refused.
    r = eve.get("/shared/search?q=")
    assert r.status_code == 303 and r.headers["location"] == "/shared"
    assert eve.get("/shared/search?q=" + "x" * 201).status_code == 400

    # Search box shows once something is shared; unpairing empties results.
    assert 'action="/shared/search"' in eve.get("/shared").text
    app.state.mailbox.revoke(EVE, link_id)
    assert "No matches" in eve.get("/shared/search?q=roadmap").text


def _carol_shares(app, world, eve_pair: bool = True):
    """Carol signs in, shares one file of hers, and is paired with Eve."""
    world.add(
        "carol-doc", "Carol roadmap", "text/plain", ["carol-root"], b"carol roadmap", owner=CAROL
    )
    carol = client(app)
    assert login(carol, "carol-code").status_code == 303
    assert post(carol, "/sharing/add", file_id="carol-doc").status_code == 303
    if eve_pair:
        _pair(app, CAROL, EVE)
    return carol


def test_search_skips_a_sharer_whose_drive_fails(pair, world, monkeypatch) -> None:
    from scoped_drive_mcp.auth import current_actor
    from scoped_drive_mcp.service import DriveService

    app, owner, eve = pair
    _pair(app, OWNER_EMAIL, EVE)
    assert post(owner, "/sharing/add", file_id="proj").status_code == 303
    _carol_shares(app, world)
    assert "Carol roadmap" in eve.get("/shared/search?q=roadmap").text

    real = DriveService.search_files

    def flaky(self, query, max_results=10):
        if current_actor.get() == CAROL:
            raise RuntimeError("Google said 503")
        return real(self, query, max_results)

    monkeypatch.setattr(DriveService, "search_files", flaky)
    page = eve.get("/shared/search?q=roadmap")
    assert page.status_code == 200
    assert "Deep roadmap" in page.text  # the owner's results survive
    assert "Carol roadmap" not in page.text
    assert "Not searched: " + CAROL in page.text


def test_shared_search_is_rate_limited(pair, monkeypatch) -> None:
    import scoped_drive_mcp.dashboard as dash

    app, owner, eve = pair
    _pair(app, OWNER_EMAIL, EVE)
    assert post(owner, "/sharing/add", file_id="proj").status_code == 303
    monkeypatch.setattr(dash, "SHARED_SEARCH_LIMIT", 2)
    assert eve.get("/shared/search?q=roadmap").status_code == 200
    assert eve.get("/shared/search?q=roadmap").status_code == 200
    limited = eve.get("/shared/search?q=roadmap")
    assert limited.status_code == 429 and "Too many searches" in limited.text
    # Per person: the owner is not limited by Eve's searches.
    assert owner.get("/shared/search?q=roadmap").status_code == 200


def test_failed_downloads_are_audited_and_explained(pair, memstore) -> None:
    app, owner, eve = pair
    _pair(app, OWNER_EMAIL, EVE)
    assert post(owner, "/sharing/add", file_id="proj").status_code == 303

    shortcut = eve.get(shared_href("download", DRIVE, OWNER_EMAIL, "proj-shortcut"))
    assert shortcut.status_code == 404 and "no file to download" in shortcut.text
    folder = eve.get(shared_href("download", DRIVE, OWNER_EMAIL, "proj-sub"))
    assert folder.status_code == 400
    assert "_shared_" not in folder.text and "open it from the list" in folder.text

    log = [json.loads(r) for r in memstore.lrange(KEY_PREFIX + "activity", 0, -1)]
    errors = {
        (r["tool"], r.get("file_id"), r["reason"])
        for r in log
        if r.get("role") == "guest" and r["decision"] == "error"
    }
    assert ("download_shared_file", "proj-shortcut", "no_bytes") in errors
    assert ("download_shared_file", "proj-sub", "invalid_input") in errors


def test_breadcrumbs_stop_at_a_shared_subfolder(pair) -> None:
    app, owner, eve = pair
    _pair(app, OWNER_EMAIL, EVE)
    assert post(owner, "/sharing/add", file_id="proj-sub").status_code == 303
    page = browse(eve, "proj-sub").text
    assert "Deep roadmap" in page
    assert "Projects" not in page  # the unshared parent is never named
    assert browse(eve, "proj").status_code == 403
    assert open_item(eve, "root").status_code in (400, 403)

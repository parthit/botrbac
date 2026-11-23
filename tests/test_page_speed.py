"""Dashboard pages make as few Drive and store round trips as they can.

Each round trip is a network call in production (Drive API, Upstash REST), so these pin the
number of lookups, not timings."""

from scoped_drive_mcp.access import AccessRequests
from scoped_drive_mcp.dashboard import fetch_parents
from scoped_drive_mcp.grants import GrantService
from scoped_drive_mcp.store import Allowlist, MemoryStore, PrefixedStore
from tests.conftest import OWNER_EMAIL
from tests.dash import client, login, post


def _grants(world, ids):
    owner = world.as_user(OWNER_EMAIL)
    kv = PrefixedStore(MemoryStore())
    grants = GrantService(lambda: owner, Allowlist(kv), AccessRequests(kv), None)
    for fid in ids:
        grants.grant(fid)
    return owner, grants


def test_entry_status_matches_covering_entry(world) -> None:
    allowed = ["proj", "proj-sub", "proj-deep-doc", "proj-notes", "loose-doc", "priv-secret"]
    owner, grants = _grants(world, allowed)
    ids = [*allowed, "no-such-file"]
    covers, not_found = grants.entry_status(ids, lambda batch: fetch_parents(owner, batch))
    for fid in allowed:
        assert covers.get(fid) == grants.covering_entry(fid), fid
    # The nearest allowed folder wins, as in covering_entry.
    assert covers["proj-deep-doc"] == ("proj-sub", "Sub")
    assert covers["proj-sub"] == ("proj", "Projects")
    assert "proj" not in covers and "loose-doc" not in covers
    assert not_found == {"no-such-file"}


def test_entry_status_looks_up_each_folder_once(world) -> None:
    owner, grants = _grants(world, ["proj-deep-doc", "proj-notes", "loose-doc"])
    batches: list[list[str]] = []

    def fetch(batch):
        batches.append(sorted(batch))
        return fetch_parents(owner, batch)

    grants.entry_status(["proj-deep-doc", "proj-notes", "loose-doc"], fetch)
    looked_up = [fid for batch in batches for fid in batch]
    assert len(looked_up) == len(set(looked_up))
    # One batch per folder level, not one call per item per level.
    assert batches[0] == ["loose-doc", "proj-deep-doc", "proj-notes"]
    assert len(batches) <= 4


def test_entry_status_failed_lookup_gives_no_answer(world) -> None:
    owner, grants = _grants(world, ["proj", "proj-notes"])

    def fetch(batch):
        out = fetch_parents(owner, batch)
        if "proj-notes" in out:
            out["proj-notes"] = RuntimeError("drive is down")
        return out

    covers, not_found = grants.entry_status(["proj", "proj-notes"], fetch)
    assert covers == {} and not_found == set()


def _counting(world):
    calls: list[tuple[str, str]] = []
    original = type(world).get_file

    def get_file(self, file_id, fields):
        calls.append((file_id, fields))
        return original(self, file_id, fields)

    return calls, get_file


def test_allowed_tab_notes_covered_items(p2_app) -> None:
    c = client(p2_app)
    login(c)
    for fid in ("proj", "proj-sub", "loose-doc"):
        post(c, "/grant", file_id=fid)
    page = c.get("/files?tab=allowed").text
    assert "Also covered by “Projects”" in page
    assert page.count("Also covered by") == 1
    assert 'id="needs-pick"' not in page


def test_allowed_tab_reads_each_item_once(p2_app, world, monkeypatch) -> None:
    c = client(p2_app)
    login(c)
    for fid in ("proj-notes", "proj-deep-doc", "loose-doc", "loose-two"):
        post(c, "/grant", file_id=fid)
    calls, get_file = _counting(world)
    monkeypatch.setattr(type(world), "get_file", get_file)
    assert c.get("/files?tab=allowed").status_code == 200
    ids = [fid for fid, _ in calls]
    assert len(ids) == len(set(ids)), ids


def test_files_asks_for_my_drive_once(p2_app, world, monkeypatch) -> None:
    c = client(p2_app)
    login(c)
    calls, get_file = _counting(world)
    monkeypatch.setattr(type(world), "get_file", get_file)
    for _ in range(3):
        assert c.get("/files").status_code == 200
    assert [fid for fid, _ in calls].count("root") == 1
    assert "owner-root" not in [fid for fid, _ in calls]


def test_files_by_my_drive_id_matches_the_top(p2_app, world, monkeypatch) -> None:
    c = client(p2_app)
    login(c)
    top = c.get("/files")
    assert top.status_code == 200
    calls, get_file = _counting(world)
    monkeypatch.setattr(type(world), "get_file", get_file)
    by_id = c.get("/files?folder=owner-root")
    assert by_id.status_code == 200
    # My Drive by its real id: no lookup of the folder itself, and the same breadcrumb.
    assert "owner-root" not in [fid for fid, _ in calls]
    assert "My Drive" in by_id.text
    for name in ("Projects", "Private", "Loose memo"):
        assert (name in by_id.text) == (name in top.text), name


def test_allowed_tab_logs_failed_lookups(p2_app, world, monkeypatch, caplog) -> None:
    c = client(p2_app)
    login(c)
    for fid in ("proj", "proj-notes"):
        post(c, "/grant", file_id=fid)
    original = type(world).get_file

    def flaky(self, file_id, fields):
        if file_id == "proj-notes" and fields == "id,parents":
            raise RuntimeError("rate limited")
        return original(self, file_id, fields)

    monkeypatch.setattr(type(world), "get_file", flaky)
    with caplog.at_level("WARNING", logger="scoped_drive_mcp.dashboard"):
        page = c.get("/files?tab=allowed")
    assert page.status_code == 200
    # No guess for the item whose lookup failed: neither covered nor "needs pick".
    assert "Also covered by" not in page.text
    assert 'id="needs-pick"' not in page.text
    assert any("1 Drive lookups failed" in r.getMessage() for r in caplog.records)


def _counting_grant(monkeypatch, delay: float = 0.0) -> list[str]:
    import datetime
    import time

    calls: list[str] = []

    def fake_refresh_grant(request, token_uri, refresh_token, client_id, client_secret, **kw):
        calls.append(refresh_token)
        time.sleep(delay)
        expiry = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
        token = f"at-{len(calls)}"
        response = {"access_token": token, "scope": "https://www.googleapis.com/auth/drive.file"}
        return token, refresh_token, expiry + datetime.timedelta(hours=1), response, None

    monkeypatch.setattr("google.oauth2.reauth.refresh_grant", fake_refresh_grant)
    return calls


def test_parallel_lookups_refresh_an_expired_token_once(monkeypatch) -> None:
    """The Allowed tab's parallel lookups all find the token missing or expired. One
    thread asks Google; the others wait and use its (already checked) token."""
    import threading

    from scoped_drive_mcp.drive_client import oauth_credentials
    from tests.conftest import make_settings

    calls = _counting_grant(monkeypatch, delay=0.05)
    creds = oauth_credentials(make_settings(), "rt-owner")
    start = threading.Barrier(8)

    def lookup() -> None:
        start.wait()
        creds.before_request(None, "GET", "https://www.googleapis.com/drive/v3/files", {})

    threads = [threading.Thread(target=lookup) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(calls) == 1
    assert creds.valid and creds.token == "at-1"


def test_refresh_after_a_rejected_token_still_asks_google(monkeypatch) -> None:
    """A 401 makes the HTTP layer call refresh() on a token that still looks valid. That
    must not be mistaken for "another thread just refreshed"."""
    from scoped_drive_mcp.drive_client import oauth_credentials
    from tests.conftest import make_settings

    calls = _counting_grant(monkeypatch)
    creds = oauth_credentials(make_settings(), "rt-owner")
    creds.refresh(None)
    assert creds.valid and creds.token == "at-1"
    creds.refresh(None)
    assert len(calls) == 2 and creds.token == "at-2"


def test_entry_status_reads_every_level_it_fetches(world, monkeypatch) -> None:
    from scoped_drive_mcp import grants as grants_module

    monkeypatch.setattr(grants_module, "MAX_COVER_DEPTH", 1)
    owner, grants = _grants(world, ["proj-notes"])
    fetched: list[str] = []

    def fetch(batch):
        fetched.extend(batch)
        return fetch_parents(owner, batch)

    # One level allowed: proj-notes itself, then its parent "proj" is read in that level.
    # Nothing above it may be fetched only to be thrown away.
    grants.entry_status(["proj-notes"], fetch)
    assert fetched == ["proj-notes"]

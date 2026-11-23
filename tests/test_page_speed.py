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


def _counting(app, world):
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
    calls, get_file = _counting(p2_app, world)
    monkeypatch.setattr(type(world), "get_file", get_file)
    assert c.get("/files?tab=allowed").status_code == 200
    ids = [fid for fid, _ in calls]
    assert len(ids) == len(set(ids)), ids


def test_files_asks_for_my_drive_once(p2_app, world, monkeypatch) -> None:
    c = client(p2_app)
    login(c)
    calls, get_file = _counting(p2_app, world)
    monkeypatch.setattr(type(world), "get_file", get_file)
    for _ in range(3):
        assert c.get("/files").status_code == 200
    assert [fid for fid, _ in calls].count("root") == 1
    assert "owner-root" not in [fid for fid, _ in calls]

"""Allowlist scope, grant/revoke through the owner's Drive, and revocation timing."""

import pytest

from scoped_drive_mcp.access import AccessRequests
from scoped_drive_mcp.drive_client import FOLDER_MIME, DriveNotFoundError
from scoped_drive_mcp.grants import GrantError, GrantService
from scoped_drive_mcp.scope import ForbiddenError, InvalidInputError, OutOfScopeError, ScopeGuard
from scoped_drive_mcp.service import DriveService
from scoped_drive_mcp.store import AllowEntry, Allowlist, MemoryStore, PrefixedStore
from tests.conftest import OWNER_EMAIL, ROOT, FakeClock, make_settings


@pytest.fixture
def kv():
    return PrefixedStore(MemoryStore())


@pytest.fixture
def allowlist(kv) -> Allowlist:
    return Allowlist(kv)


@pytest.fixture
def owner(world):
    return world.as_user(OWNER_EMAIL)


@pytest.fixture
def p2_guard(owner, allowlist, clock) -> ScopeGuard:
    return ScopeGuard(
        owner, None, ttl=60, allowlist=allowlist.mime_map, allowlist_ttl=0, clock=clock
    )


@pytest.fixture
def grants(owner, allowlist, kv, p2_guard) -> GrantService:
    return GrantService(
        lambda: owner,
        allowlist,
        AccessRequests(kv),
        on_change=p2_guard.invalidate_allowlist,
    )


@pytest.fixture
def p2_service(owner, p2_guard) -> DriveService:
    return DriveService(owner, p2_guard, make_settings(root_folder_id=None))


def test_grant_updates_the_allowlist_without_sharing(world, owner, grants, allowlist) -> None:
    entry = grants.grant("proj")
    assert owner.permission_calls == []
    assert world.files["proj"].permissions == []
    assert entry.permission_id is None and entry.shared_with is None
    assert allowlist.get("proj") == entry
    assert entry.mime_type == FOLDER_MIME and entry.name == "Projects"
    assert grants.grant("proj") == entry
    assert owner.permission_calls == []
    linked = grants.grant("proj", request_id="req-already-allowed")
    assert linked.request_id == "req-already-allowed"
    assert allowlist.get("proj").request_id == "req-already-allowed"
    assert grants.grant("proj", request_id="other-request") == linked


def test_revoke_removes_the_entry_and_an_old_share(world, owner, grants, allowlist) -> None:
    """Entries from the old bot-account mode carry a Drive share; revoke removes it too."""
    pid = world.share("proj", "old-bot@example.com")
    allowlist.add(AllowEntry("proj", "Projects", FOLDER_MIME, pid))
    grants.revoke("proj")
    assert owner.permission_calls[-1] == ("delete", "proj", pid)
    assert world.files["proj"].permissions == []
    assert allowlist.get("proj") is None
    with pytest.raises(GrantError):
        grants.revoke("proj")
    # The share is already gone in Drive: the entry still goes, quietly.
    allowlist.add(AllowEntry("proj", "Projects", FOLDER_MIME, "gone-perm"))
    grants.revoke("proj")
    assert allowlist.get("proj") is None


def test_revoke_says_when_google_keeps_an_old_share(world, owner, grants, allowlist) -> None:
    pid = world.share("loose-doc", "old-bot@example.com")
    allowlist.add(AllowEntry("loose-doc", "Loose memo", "text/plain", pid))

    def refuse(file_id: str, permission_id: str) -> None:
        raise RuntimeError("drive 500")

    owner.delete_permission = refuse
    with pytest.raises(GrantError, match="Share dialog"):
        grants.revoke("loose-doc")
    # The assistant loses access either way; only the old share is left for the person.
    assert allowlist.get("loose-doc") is None


def test_grant_refuses_missing_and_unowned(grants, allowlist) -> None:
    with pytest.raises(GrantError):
        grants.grant("does-not-exist")
    # the owner cannot see eve's file, so it cannot be granted
    with pytest.raises(GrantError):
        grants.grant("stray-shared")
    assert allowlist.entries() == {}


def test_grant_shortcut_grants_target(grants, allowlist) -> None:
    entry = grants.grant("proj-shortcut")
    assert entry.id == "priv-secret"
    assert allowlist.get("proj-shortcut") is None


@pytest.mark.parametrize(
    ("granted", "inside", "outside"),
    [
        (
            "proj",
            ("proj", "proj-sub", "proj-deep-doc", "proj-notes"),
            ("priv", "priv-secret", "loose-doc", "owner-root", "stray-shared"),
        ),
        # A subfolder grant does not expose its parent or siblings.
        ("proj-sub", ("proj-deep-doc",), ("proj-notes", "proj")),
        ("loose-doc", ("loose-doc",), ("loose-two",)),
    ],
)
def test_grant_scope(grants, p2_guard, granted, inside, outside) -> None:
    assert not any(p2_guard.is_in_scope(fid) for fid in inside)
    grants.grant(granted)
    for fid in inside:
        assert p2_guard.is_in_scope(fid), fid
    for fid in outside:
        assert not p2_guard.is_in_scope(fid), fid


def test_file_outside_this_drive_is_refused(owner, p2_guard) -> None:
    with pytest.raises(DriveNotFoundError):
        owner.get_file("stray-shared", "id")
    with pytest.raises(OutOfScopeError) as exc:
        p2_guard.assert_in_scope("stray-shared")
    assert exc.value.file_id == "stray-shared"


def test_revocation_takes_effect(grants, p2_service, owner) -> None:
    grants.grant("proj")
    assert p2_service.read_file("proj-notes")["content"] == "project notes alpha"
    created = p2_service.create_doc("note", "hi", parent_id="proj")
    assert p2_service.read_file(created["id"])["content"] == "hi"
    grants.revoke("proj")
    with pytest.raises(OutOfScopeError):
        p2_service.read_file("proj-notes")
    # A file the assistant itself made in the folder goes with it.
    assert owner.get_file(created["id"], "id")
    with pytest.raises(OutOfScopeError):
        p2_service.read_file(created["id"])


def test_revocation_on_other_instance_within_allowlist_ttl(owner, allowlist, grants) -> None:
    clock = FakeClock()
    other = ScopeGuard(owner, None, allowlist=allowlist.mime_map, allowlist_ttl=2, clock=clock)
    grants.grant("loose-doc")
    assert other.is_in_scope("loose-doc")
    allowlist.remove("loose-doc")  # revoke recorded by another instance; share still present
    assert other.is_in_scope("loose-doc")  # cached for at most allowlist_ttl
    clock.advance(2.5)
    assert not other.is_in_scope("loose-doc")


def test_allowlisted_items_cannot_be_renamed_or_trashed(grants, p2_service, world) -> None:
    grants.grant("proj")
    grants.grant("loose-doc")
    for fid in ("proj", "loose-doc"):
        with pytest.raises(ForbiddenError) as exc:
            p2_service.rename_file(fid, "hijacked")
        assert not isinstance(exc.value, OutOfScopeError)
        with pytest.raises(ForbiddenError):
            p2_service.trash_file(fid)
    assert world.files["proj"].name == "Projects" and not world.files["proj"].trashed
    # a granted file's content may still be edited; children of a granted folder can be renamed
    p2_service.update_file_content("loose-doc", "new memo")
    assert world.files["loose-doc"].content == b"new memo"
    p2_service.rename_file("proj-notes", "renamed.txt")
    assert world.files["proj-notes"].name == "renamed.txt"


def test_list_folder_without_id_lists_allowlisted_items(grants, p2_service) -> None:
    assert p2_service.list_folder()["files"] == []
    grants.grant("proj")
    grants.grant("loose-doc")
    result = p2_service.list_folder()
    assert [f["id"] for f in result["files"]] == ["proj", "loose-doc"]
    assert result["folder"] is None
    inside = {f["id"] for f in p2_service.list_folder("proj")["files"]}
    assert inside == {"proj-sub", "proj-notes", "proj-shortcut"}


def test_ticked_items_do_not_reveal_their_parents(grants, p2_service, world) -> None:
    world.add("two-homes", "two homes.txt", "text/plain", ["proj", "priv"], b"x", owner=OWNER_EMAIL)
    grants.grant("proj")
    grants.grant("loose-doc")
    top = p2_service.list_folder()["files"]
    assert all("parents" not in f for f in top)  # both live in the owner's My Drive root
    assert "parents" not in p2_service.get_metadata("proj")
    assert p2_service.get_metadata("two-homes")["parents"] == ["proj"]
    grants.grant("priv")
    assert p2_service.get_metadata("two-homes")["parents"] == ["proj", "priv"]
    assert "owner-root" not in str(p2_service.search_files("memo"))


def test_default_create_parent(grants, p2_service) -> None:
    with pytest.raises(InvalidInputError):
        p2_service.create_folder("x")
    grants.grant("proj")
    grants.grant("loose-doc")
    assert p2_service.create_folder("x")["parents"] == ["proj"]
    grants.grant("priv")
    with pytest.raises(InvalidInputError, match="parent_id is required"):
        p2_service.create_folder("y")


def test_search_allowlisted_folders_and_files(grants, p2_service) -> None:
    grants.grant("proj")
    grants.grant("loose-doc")
    ids = {f["id"] for f in p2_service.search_files("secret", 50)["files"]}
    assert ids == {"proj-deep-doc"}  # not stray-shared, not priv-secret
    ids = {f["id"] for f in p2_service.search_files("memo", 50)["files"]}
    assert ids == {"loose-doc"}  # loose-two is not granted
    p2_service.drive.ignore_parent_filter = True
    ids = {f["id"] for f in p2_service.search_files("secret", 50)["files"]}
    assert ids == {"proj-deep-doc"}


def test_grant_and_revoke_change_search_without_sharing(world, grants, p2_service) -> None:
    assert p2_service.search_files("roadmap", 10)["count"] == 0
    assert grants.grant("proj").permission_id is None
    assert world.files["proj"].permissions == []
    assert p2_service.search_files("roadmap", 10)["count"] == 1
    grants.revoke("proj")
    assert p2_service.search_files("roadmap", 10)["count"] == 0


def test_root_folder_id_is_an_extra_root(drive, clock, allowlist) -> None:
    allowlist.add(AllowEntry("outside-folder", "Private", FOLDER_MIME, None))
    guard = ScopeGuard(drive, ROOT, allowlist=allowlist.mime_map, allowlist_ttl=0, clock=clock)
    assert guard.is_in_scope("notes-txt")  # via ROOT_FOLDER_ID
    assert guard.is_in_scope("outside-file")  # via the allowlist
    assert set(guard.folders_in_scope()) >= {ROOT, "outside-folder"}
    with pytest.raises(ForbiddenError):
        guard.assert_in_scope("outside-folder", allow_root=False)


def test_multi_parent_rule(drive, clock) -> None:
    """Documented rule: in scope if ANY parent chain reaches an allowlisted id."""
    guard = ScopeGuard(drive, None, allowlist=lambda: {"sub-a": FOLDER_MIME}, clock=clock)
    assert guard.is_in_scope("multi-parent")  # parents: outside-folder, sub-a
    guard = ScopeGuard(drive, None, allowlist=lambda: {"outside-folder": FOLDER_MIME}, clock=clock)
    assert guard.is_in_scope("multi-parent")
    guard = ScopeGuard(drive, None, allowlist=lambda: {"sub-a-deep": FOLDER_MIME}, clock=clock)
    assert not guard.is_in_scope("multi-parent")


def test_approving_a_shortcut_shows_what_it_points_to(world, owner, grants) -> None:
    # A shortcut can carry any name. Approving it allows its target, so the approval
    # option names the target (here a folder), not the shortcut.
    world.add(
        "sc-notes",
        "notes.txt",
        "application/vnd.google-apps.shortcut",
        ["owner-root"],
        shortcut_target="proj",
    )
    req, _ = grants.requests.create(
        tool="read_file", token_name="app", reason="r", file_id="sc-notes"
    )
    first = grants.approval_options(req)[0]
    assert (first.id, first.name, first.mime_type) == ("proj", "Projects", FOLDER_MIME)
    assert grants.approve(req, "proj").id == "proj"

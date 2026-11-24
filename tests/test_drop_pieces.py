"""Larger files sent to a paired person: held in Vercel Blob, sent and downloaded in pieces
under Vercel's 4.5 MB request limit, inside the free Blob tier (drop_storage.py)."""

import json
from datetime import UTC, datetime, timedelta

import pytest

from scoped_drive_mcp import drop_storage
from scoped_drive_mcp.drive_client import FOLDER_MIME
from scoped_drive_mcp.drop_storage import BlobBudget, BlobParts, KvParts
from scoped_drive_mcp.external import acting_as
from scoped_drive_mcp.store import MemoryStore
from tests.conftest import EVE, OWNER_EMAIL
from tests.dash import client, csrf, login, mcp_call
from tests.test_drops import PDF_BYTES, _drop_folders, _held, _send
from tests.test_external_sharing import _error, _pair
from tests.test_multi_user import _app
from tests.test_peer_edit import _editor_app

# Small pieces so tests move a few bytes, not megabytes.
PIECE = 8


class FakeBlob:
    def __init__(self) -> None:
        self.blobs: dict[str, bytes] = {}
        self.lists = 0

    def put(self, pathname: str, data: bytes) -> None:
        self.blobs[pathname] = data

    def get(self, pathname: str) -> bytes | None:
        return self.blobs.get(pathname)

    def delete(self, pathnames) -> None:
        for p in pathnames:
            self.blobs.pop(p, None)

    def list(self, prefix: str):
        self.lists += 1
        return [p for p in self.blobs if p.startswith(prefix)]


@pytest.fixture
def blob(monkeypatch) -> FakeBlob:
    monkeypatch.setattr(drop_storage, "PIECE_BYTES", PIECE)
    return FakeBlob()


@pytest.fixture
def setup(world, memstore, oauth, blob):
    app = _app(world, memstore, oauth, blob_api=blob)
    owner, eve = client(app), client(app)
    login(owner)
    login(eve, "eve-code")
    eve_token = _editor_app(eve, "Grok Eve")
    _pair(app, OWNER_EMAIL, EVE)
    return app, owner, (eve, eve_token)


def _start(c, size: int, to: str = OWNER_EMAIL, name: str = "big.pdf"):
    token = csrf(c, "/sharing?tab=with-me")
    r = c.post(
        "/shared/send/start",
        data={"csrf": token, "to": to, "name": name, "type": "application/pdf", "size": size},
        headers={"Accept": "application/json"},
    )
    return token, r


def _upload(c, data: bytes) -> dict:
    token, r = _start(c, len(data))
    assert r.status_code == 200, r.text
    begun = r.json()
    assert begun["pieces"] == -(-len(data) // PIECE)
    base = f"/shared/send/{begun['upload_id']}"
    for n in range(begun["pieces"]):
        piece = data[n * PIECE : (n + 1) * PIECE]
        r = c.post(f"{base}/piece/{n}", data={"csrf": token}, files={"piece": ("piece", piece)})
        assert r.status_code == 200, r.text
    return c.post(f"{base}/finish", data={"csrf": token}).json()


def test_a_file_sent_in_pieces_is_held_in_blob_encrypted(setup, blob) -> None:
    app, owner, (eve, _token) = setup
    data = b"0123456789abcdefghijklmnopqrstu"  # 31 bytes: 4 pieces
    done = _upload(eve, data)
    assert done["ok"] is True, done
    [row] = _held(app)
    assert row["store"] == "blob" and row["parts"] == 4 and row["size"] == len(data)
    assert len(blob.blobs) == 4
    # Encrypted, and named so a sweep knows when it expires.
    for path, raw in blob.blobs.items():
        assert path.startswith(f"drops/{row['exp']}/{row['id']}/")
        assert raw[:1] == b"\x01" and data[:8] not in raw
    # The recipient's browser fetches it piece by piece.
    pieces = [owner.get(f"/drops/{row['id']}/piece/{n}") for n in range(4)]
    assert all(p.status_code == 200 for p in pieces)
    assert b"".join(p.content for p in pieces) == data
    assert owner.get(f"/drops/{row['id']}/piece/4").status_code == 400
    # The sender cannot fetch it back.
    assert eve.get(f"/drops/{row['id']}/piece/0").status_code == 400


def test_saving_a_blob_file_writes_it_to_drive_and_deletes_the_pieces(setup, blob, world) -> None:
    app, owner, (eve, _token) = setup
    data = b"x" * 20
    _upload(eve, data)
    [row] = _held(app)
    saved = mcp_call(owner, "save_drop", role="editor", drop_id=row["id"])
    assert saved["isError"] is False, saved
    assert blob.blobs == {}
    [folder] = _drop_folders(world)
    [copy] = [f for f in world.files.values() if f.parents == [folder]]
    assert copy.content == data


def test_a_send_larger_than_the_limit_is_refused_before_any_bytes(setup, blob) -> None:
    app, _owner, (eve, _token) = setup
    _token_, r = _start(eve, app.state.drops.max_bytes + 1)
    assert r.status_code == 400 and r.json()["error"] == "too_large"
    _token_, r = _start(eve, 0)
    assert r.json()["error"] == "invalid_input"
    assert blob.blobs == {}


def test_pieces_must_be_the_expected_size(setup, blob) -> None:
    _app_, _owner, (eve, _token) = setup
    token, r = _start(eve, 20)
    upload = r.json()["upload_id"]
    r = eve.post(
        f"/shared/send/{upload}/piece/0", data={"csrf": token}, files={"piece": ("p", b"short")}
    )
    assert r.json()["error"] == "invalid_input"
    # Finishing before every piece arrived is refused, and nothing is listed.
    r = eve.post(f"/shared/send/{upload}/finish", data={"csrf": token})
    assert r.status_code == 400


def test_only_the_sender_can_add_pieces(setup, world, memstore, oauth) -> None:
    app, owner, (eve, _token) = setup
    token, r = _start(eve, 8)
    upload = r.json()["upload_id"]
    other = csrf(owner, "/sharing?tab=with-me")
    r = owner.post(
        f"/shared/send/{upload}/piece/0", data={"csrf": other}, files={"piece": ("p", b"8bytes!!")}
    )
    assert r.status_code == 400 and r.json()["error"] == "not_found"


def test_piece_requests_need_the_csrf_token(setup) -> None:
    _app_, _owner, (eve, _token) = setup
    _token_, r = _start(eve, 8)
    upload = r.json()["upload_id"]
    r = eve.post(f"/shared/send/{upload}/piece/0", files={"piece": ("p", b"8bytes!!")})
    assert r.status_code == 403


def test_a_send_needs_an_active_pairing(world, memstore, oauth, blob) -> None:
    app = _app(world, memstore, oauth, blob_api=blob)
    eve = client(app)
    login(eve, "eve-code")
    _token_, r = _start(eve, 8)
    assert r.json()["error"] == "not_linked"


def test_unpairing_during_an_upload_stops_it(setup, blob, monkeypatch) -> None:
    app, _owner, (eve, _token) = setup
    token, r = _start(eve, 8)
    upload = r.json()["upload_id"]
    piece = {"piece": ("p", b"x" * 8)}
    eve.post(f"/shared/send/{upload}/piece/0", data={"csrf": token}, files=piece)
    monkeypatch.setattr(app.state.drops, "is_linked", lambda _a, _b: False)
    r = eve.post(f"/shared/send/{upload}/finish", data={"csrf": token})
    assert r.json()["error"] == "not_linked"
    assert _held(app) == []


def test_an_assistant_send_is_stored_in_blob_too(setup, blob) -> None:
    app, owner, eve = setup
    assert _send(eve)["isError"] is False
    [row] = _held(app)
    assert row["store"] == "blob"
    read = mcp_call(owner, "download_drop", role="viewer", drop_id=row["id"])
    assert read["isError"] is False, read


def test_old_rows_in_the_key_value_store_still_read(setup, memstore, blob) -> None:
    """A file held before Blob was connected is read from where it was put."""
    app, owner, _eve = setup
    box = app.state.drops
    with acting_as(OWNER_EMAIL):
        box.blob, saved = None, box.blob
        _send(_eve)
        box.blob = saved
        [row] = box.received()
        assert row["store"] == "kv"
        assert box.download(row["id"])[1] == PDF_BYTES


def _piece(c, token: str, upload: str, n: int, data: bytes):
    return c.post(
        f"/shared/send/{upload}/piece/{n}", data={"csrf": token}, files={"piece": ("p", data)}
    )


def _month_uploads(app) -> int:
    return app.state.drops.budget.usage()["month_uploads"]


def test_uploads_are_counted_as_pieces_arrive_not_at_start(setup, blob) -> None:
    """An upload that is started and never sent costs the Blob budget nothing."""
    app, _owner, (eve, _token) = setup
    _token_, r = _start(eve, 24)
    assert r.status_code == 200
    swept = _month_uploads(app)  # the first send's sweep counts one list call
    for _ in range(3):
        _start(eve, 24)
    assert _month_uploads(app) == swept
    token, r = _start(eve, 8)
    assert _piece(eve, token, r.json()["upload_id"], 0, b"x" * 8).status_code == 200
    assert _month_uploads(app) == swept + 1


def test_a_piece_cannot_be_uploaded_twice(setup, blob) -> None:
    app, _owner, (eve, _token) = setup
    token, r = _start(eve, 16)
    upload = r.json()["upload_id"]
    assert _piece(eve, token, upload, 0, b"a" * 8).status_code == 200
    used = _month_uploads(app)
    again = _piece(eve, token, upload, 0, b"b" * 8)
    assert again.status_code == 400 and again.json()["error"] == "invalid_input"
    assert _month_uploads(app) == used
    assert b"b" * 8 not in b"".join(blob.blobs.values())


def test_the_budget_refuses_uploads_past_the_monthly_cap(setup, blob) -> None:
    app, _owner, (eve, _token) = setup
    budget = app.state.drops.budget
    token, r = _start(eve, 16)  # 2 pieces; the first sweep counts one
    upload = r.json()["upload_id"]
    budget.monthly_uploads = _month_uploads(app) + 1
    assert _piece(eve, token, upload, 0, b"x" * 8).status_code == 200
    full = _piece(eve, token, upload, 1, b"y" * 8)
    assert full.json()["error"] == "storage_full"
    # A send that cannot fit is refused at start, and does not use up the hourly limit.
    _token_, r = _start(eve, 8)
    assert r.json()["error"] == "storage_full"
    with acting_as(OWNER_EMAIL):
        assert int(app.state.drops.store.get(f"drops:sent:{EVE}") or 0) == 1


def test_uploads_in_progress_count_toward_the_waiting_cap(setup, blob, monkeypatch) -> None:
    from scoped_drive_mcp import drops

    _app_, _owner, (eve, _token) = setup
    monkeypatch.setattr(drops, "MAX_HELD_BYTES", 20)
    assert _start(eve, 16)[1].status_code == 200
    _token_, r = _start(eve, 8)
    assert r.json()["error"] == "inbox_full"


def test_the_hold_starts_when_the_upload_finishes(setup, blob) -> None:
    app, _owner, (eve, _token) = setup
    box = app.state.drops
    start = box.clock()
    _upload(eve, b"z" * 8)
    [row] = _held(app)
    expires = datetime.strptime(row["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    assert expires >= start + box.hold - timedelta(seconds=1)
    # The stored pieces outlive the hold by the longest an upload may take.
    assert row["exp"] >= int((start + box.hold).timestamp()) + 3500


def test_a_failed_delete_does_not_break_the_list(setup, blob, monkeypatch) -> None:
    app, owner, (eve, _token) = setup
    box = app.state.drops
    _upload(eve, b"q" * 8)
    with acting_as(OWNER_EMAIL):
        [row] = box.received()
        box.store.hset(
            "drops:index", row["id"], json.dumps({**row, "expires_at": "2000-01-01T00:00:00Z"})
        )

    def broken(_row) -> None:
        raise RuntimeError("blob down")

    monkeypatch.setattr(box, "_drop_parts", broken)
    assert owner.get("/sharing?tab=with-me").status_code == 200
    assert _held(app) == []


def test_a_plain_piece_is_refused_when_a_key_is_set(blob) -> None:
    keyed, plain = BlobParts(blob, "k" * 44), BlobParts(blob, None)
    plain.put_piece("d", 5, 0, b"forged")
    assert plain.get_piece({"id": "d", "exp": 5, "parts": 1}, 0) == b"forged"
    assert keyed.get_piece({"id": "d", "exp": 5, "parts": 1}, 0) is None


def test_the_budget_counts_storage_over_the_hold() -> None:
    store = MemoryStore()
    now = [datetime(2026, 11, 24, tzinfo=UTC)]
    budget = BlobBudget(
        store,
        BlobParts(FakeBlob(), None),
        monthly_uploads=1000,
        held_bytes=10 * drop_storage.PIECE_BYTES,
        hold_hours=24,
        clock=lambda: now[0],
    )
    assert budget.reserve(6)
    assert not budget.reserve(5)  # 11 pieces in the window
    now[0] += timedelta(days=budget.window_days)
    assert budget.reserve(5)  # the first 6 have been deleted by now


def test_the_sweep_deletes_expired_pieces_and_runs_rarely(blob) -> None:
    store = MemoryStore()
    parts = BlobParts(blob, "k" * 44)
    now = datetime(2026, 11, 24, tzinfo=UTC)
    past, future = int(now.timestamp()) - 10, int(now.timestamp()) + 3600
    parts.put_piece("old", past, 0, b"a")
    parts.put_piece("new", future, 0, b"b")
    blob.blobs["drops/garbage"] = b"?"
    budget = BlobBudget(
        store, parts, monthly_uploads=100, held_bytes=10**9, hold_hours=24, clock=lambda: now
    )
    budget.maybe_sweep()
    assert list(blob.blobs) == [BlobParts.path("new", future, 0)]
    budget.maybe_sweep()
    assert blob.lists == 1


def test_a_piece_cannot_be_moved_to_another_drop(blob) -> None:
    parts = BlobParts(blob, "k" * 44)
    parts.put_piece("a", 5, 0, b"secret")
    blob.blobs[BlobParts.path("b", 5, 0)] = blob.blobs[BlobParts.path("a", 5, 0)]
    assert parts.get_piece({"id": "b", "exp": 5, "parts": 1}, 0) is None
    assert parts.get_piece({"id": "a", "exp": 5, "parts": 1}, 0) == b"secret"


def test_kv_pieces_split_into_store_sized_parts(blob, monkeypatch) -> None:
    monkeypatch.setattr(drop_storage, "KV_PART_BYTES", 4)
    store = MemoryStore()
    parts = KvParts(store, None)
    exp = int(datetime.now(UTC).timestamp()) + 3600
    parts.put_piece("d", exp, 0, b"abcdefgh")
    parts.put_piece("d", exp, 1, b"ij")
    row = {"id": "d", "parts": KvParts.parts_for(10)}
    assert row["parts"] == 3
    assert parts.get_piece(row, 0) == b"abcdefgh" and parts.get_piece(row, 1) == b"ij"


def test_the_send_form_offers_the_larger_limit(setup) -> None:
    _app_, _owner, (eve, _token) = setup
    page = " ".join(eve.get("/sharing?tab=with-me").text.split())
    assert "Up to 20 MB" in page and "data-drop-send" in page


def test_a_large_drive_upload_is_resumable() -> None:
    from scoped_drive_mcp.drive_client import GoogleDriveClient

    small = GoogleDriveClient._media(b"x" * 10, "application/pdf")
    big = GoogleDriveClient._media(b"x" * (5 * 1024 * 1024 + 1), "application/pdf")
    assert not small.resumable() and big.resumable()


def test_saved_folder_is_a_folder(setup, world) -> None:
    app, owner, (eve, _token) = setup
    _upload(eve, b"y" * 9)
    [row] = _held(app)
    mcp_call(owner, "save_drop", role="editor", drop_id=row["id"])
    [folder] = _drop_folders(world)
    assert world.files[folder].mime_type == FOLDER_MIME
    again = mcp_call(owner, "save_drop", role="editor", drop_id=row["id"])
    assert _error(again)["error"] == "saved"


def test_a_piece_counts_only_once_it_is_stored(setup, blob, monkeypatch) -> None:
    """If storing a piece fails, finish does not list a file with that piece missing, and
    the piece can be sent again."""
    app, _owner, (eve, _token) = setup
    token, r = _start(eve, 8)
    upload = r.json()["upload_id"]

    def down(*_args) -> None:
        raise RuntimeError("blob down")

    monkeypatch.setattr(blob, "put", down)
    assert _piece(eve, token, upload, 0, b"x" * 8).json()["error"] == "unavailable"
    assert eve.post(f"/shared/send/{upload}/finish", data={"csrf": token}).status_code == 400
    assert _held(app) == []
    monkeypatch.undo()
    assert _piece(eve, token, upload, 0, b"x" * 8).status_code == 200
    assert eve.post(f"/shared/send/{upload}/finish", data={"csrf": token}).json()["ok"]


def test_a_piece_being_stored_is_not_stored_twice_at_once(setup, blob) -> None:
    app, _owner, (eve, _token) = setup
    token, r = _start(eve, 8)
    upload = r.json()["upload_id"]
    with acting_as(OWNER_EMAIL):
        assert app.state.drops.store.set_if_absent(f"drops:upload:{upload}:0:claim", "1", ex=60)
    busy = _piece(eve, token, upload, 0, b"x" * 8)
    assert busy.json()["error"] == "busy"
    assert blob.blobs == {}


def test_finish_lists_and_logs_a_file_once(setup, blob) -> None:
    app, owner, (eve, _token) = setup
    token, r = _start(eve, 8)
    upload = r.json()["upload_id"]
    _piece(eve, token, upload, 0, b"x" * 8)
    with acting_as(OWNER_EMAIL):
        store = app.state.drops.store
        assert store.set_if_absent(f"drops:upload:{upload}:finishing", "1", ex=60)
    busy = eve.post(f"/shared/send/{upload}/finish", data={"csrf": token})
    assert busy.json()["error"] == "busy"
    with acting_as(OWNER_EMAIL):
        store.delete(f"drops:upload:{upload}:finishing")
    assert eve.post(f"/shared/send/{upload}/finish", data={"csrf": token}).json()["ok"]
    again = eve.post(f"/shared/send/{upload}/finish", data={"csrf": token})
    assert again.status_code == 400 and again.json()["error"] == "not_found"
    assert len(_held(app)) == 1

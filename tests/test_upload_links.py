"""Upload links: start_upload / onedrive_start_upload with direct=true hand the assistant a
presigned Blob PUT URL, and finish_upload reads the file back from Blob (uploads.py)."""

import base64
import hashlib

import pytest

from scoped_drive_mcp import drop_storage
from scoped_drive_mcp.drop_storage import BlobParts
from scoped_drive_mcp.server import build_app
from scoped_drive_mcp.store import MemoryStore
from scoped_drive_mcp.uploads import DirectUploads, UploadError, UploadSessions, blob_path
from tests.conftest import OWNER_EMAIL
from tests.dash import client, login
from tests.test_drop_direct import FakeSigner
from tests.test_drop_pieces import FakeBlob
from tests.test_onedrive import SCHOOL, allow, connect, error_of, write

ME = {"email": OWNER_EMAIL, "token_name": "editor-tok", "grant_id": None}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Budget:
    def __init__(self, room: int = 100) -> None:
        self.room = room
        self.reserved: list[int] = []

    def allows(self, pieces: int) -> bool:
        return pieces <= self.room

    def reserve(self, pieces: int) -> bool:
        if pieces > self.room:
            return False
        self.room -= pieces
        self.reserved.append(pieces)
        return True


@pytest.fixture
def blob() -> FakeBlob:
    return FakeBlob()


@pytest.fixture
def signer() -> FakeSigner:
    return FakeSigner()


@pytest.fixture
def budget() -> Budget:
    return Budget()


@pytest.fixture
def sessions(clock, blob, signer, budget) -> UploadSessions:
    return UploadSessions(
        MemoryStore(clock),
        max_bytes=64 * 1024,
        clock=clock,
        direct=DirectUploads(blob, signer, budget),  # type: ignore[arg-type]
    )


def _start(sessions: UploadSessions, data: bytes, who=ME, **kw) -> dict:
    args = {
        "name": "report.pdf",
        "mime_type": "application/pdf",
        "parent_id": "sub-a",
        "size": len(data),
        "sha256": sha(data),
        "chunk_size": 1024,
        "direct": True,
    }
    args.update(kw)
    return sessions.start(who, **args)


def test_a_link_is_for_one_pathname_at_the_declared_size(sessions, signer, budget, clock):
    data = b"%PDF" + bytes(3000)
    started = _start(sessions, data)
    [(path, max_bytes, valid_for, ttl_days)] = signer.puts
    assert path == blob_path(started["upload_id"], clock() + valid_for)
    assert path.startswith("uploads/") and path.endswith(started["upload_id"])
    assert max_bytes == len(data) and valid_for == started["expires_in_seconds"] and ttl_days == 1
    assert budget.reserved == [1]
    assert started["upload_url"].startswith("https://vercel.com/api/blob/?pathname=uploads/")
    command = started["upload_command"]
    assert command.startswith("curl ") and "-X PUT" in command and "--data-binary @FILE" in command
    assert "-H 'x-vercel-blob-access: private'" in command
    assert command.endswith(f"'{started['upload_url']}'")
    # The pathname must match what the Node signer accepts.
    assert drop_storage._UPLOAD_PATH.fullmatch(path)


def test_finish_reads_the_upload_back_checks_it_and_deletes_it(sessions, blob, signer):
    data = bytes(range(256)) * 12
    started = _start(sessions, data)
    path = signer.puts[0][0]
    blob.put(path, data)  # what upload_command does
    meta, got = sessions.take(ME, started["upload_id"])
    assert got == data and meta["blob_path"] == path
    sessions.discard(started["upload_id"], meta)
    assert path not in blob.blobs


def test_nothing_uploaded_says_so_and_pieces_still_work(sessions):
    data = bytes(2500)
    started = _start(sessions, data)
    with pytest.raises(UploadError) as err:
        sessions.take(ME, started["upload_id"])
    assert err.value.code == "upload_not_received"
    # The same session takes pieces when the sandbox can't reach Blob.
    for i in range(started["chunk_count"]):
        sessions.append(
            ME, started["upload_id"], i, base64.b64encode(data[i * 1024 : (i + 1) * 1024]).decode()
        )
    _, got = sessions.take(ME, started["upload_id"])
    assert got == data


def test_a_wrong_upload_is_refused_and_removed(sessions, blob, signer):
    data = bytes(2000)
    started = _start(sessions, data)
    path = signer.puts[0][0]
    blob.put(path, b"someone else's bytes")
    with pytest.raises(UploadError) as err:
        sessions.take(ME, started["upload_id"])
    assert err.value.code == "integrity_mismatch"
    assert path not in blob.blobs
    with pytest.raises(UploadError) as err:
        sessions.take(ME, started["upload_id"])
    assert err.value.code == "upload_not_found"


def test_only_the_sign_in_that_started_it_can_finish_or_cancel(sessions, blob, signer):
    data = bytes(2000)
    started = _start(sessions, data)
    blob.put(signer.puts[0][0], data)
    other = {**ME, "token_name": "another-tok"}
    for call in (sessions.take, sessions.cancel):
        with pytest.raises(UploadError) as err:
            call(other, started["upload_id"])
        assert err.value.code == "upload_not_found"


def test_cancel_deletes_the_upload(sessions, blob, signer):
    data = bytes(2000)
    started = _start(sessions, data)
    path = signer.puts[0][0]
    blob.put(path, data)
    sessions.cancel(ME, started["upload_id"])
    assert blob.blobs == {}


def test_no_link_without_blob_when_the_budget_is_spent_or_the_signer_fails(clock, blob, signer):
    plain = UploadSessions(MemoryStore(clock), max_bytes=64 * 1024, clock=clock)
    with pytest.raises(UploadError) as err:
        _start(plain, bytes(2000))
    assert err.value.code == "direct_unavailable"
    assert "append_chunk" in err.value.message

    spent = UploadSessions(
        MemoryStore(clock),
        max_bytes=64 * 1024,
        clock=clock,
        direct=DirectUploads(blob, signer, Budget(room=0)),  # type: ignore[arg-type]
    )
    with pytest.raises(UploadError) as err:
        _start(spent, bytes(2000))
    assert err.value.code == "direct_unavailable"

    signer.fail = True
    failing = UploadSessions(
        MemoryStore(clock),
        max_bytes=64 * 1024,
        clock=clock,
        direct=DirectUploads(blob, signer, Budget()),  # type: ignore[arg-type]
    )
    with pytest.raises(UploadError) as err:
        _start(failing, bytes(2000))
    assert err.value.code == "direct_unavailable"
    # Nothing was left open by the refused starts.
    assert failing._open_uploads(OWNER_EMAIL) == 0
    assert plain.start(ME, **{**_args(bytes(2000)), "direct": False})["upload_id"]


def _args(data: bytes) -> dict:
    return {
        "name": "a.pdf",
        "mime_type": "application/pdf",
        "parent_id": "sub-a",
        "size": len(data),
        "sha256": sha(data),
    }


def test_a_link_with_unsafe_header_values_is_refused_not_trimmed(sessions, signer, monkeypatch):
    def odd(pathname, max_bytes, valid_for, ttl_days):
        return {
            "url": f"https://vercel.com/api/blob/?pathname={pathname}",
            "headers": {"x-api-version": "13", "x-content-type": "a'; rm -rf / #"},
        }

    monkeypatch.setattr(signer, "sign_put", odd)
    with pytest.raises(UploadError) as err:
        _start(sessions, bytes(2000))
    assert err.value.code == "direct_unavailable"


@pytest.mark.parametrize(
    "answer",
    [
        {"url": "https://vercel.com/api/blob/?pathname=x"},  # no headers at all: fine
        {"url": "https://vercel.com/api/blob/?pathname=x", "headers": {"x-a; rm -rf /": "1"}},
        {"headers": {}},
    ],
)
def test_odd_signer_answers_are_handled(sessions, signer, monkeypatch, answer):
    monkeypatch.setattr(signer, "sign_put", lambda *a: answer)
    if "url" in answer and not answer.get("headers"):
        assert _start(sessions, bytes(2000))["upload_headers"] == {}
        return
    with pytest.raises(UploadError) as err:
        _start(sessions, bytes(2000))
    assert err.value.code == "direct_unavailable"


def test_a_failed_signing_costs_no_budget(clock, blob, signer):
    budget = Budget()
    signer.fail = True
    failing = UploadSessions(
        MemoryStore(clock),
        max_bytes=64 * 1024,
        clock=clock,
        direct=DirectUploads(blob, signer, budget),  # type: ignore[arg-type]
    )
    for _ in range(3):
        with pytest.raises(UploadError):
            _start(failing, bytes(2000))
    assert budget.reserved == [] and budget.room == 100


def test_the_sweep_deletes_expired_uploads_only(clock):
    blob = FakeBlob()
    now = int(clock())
    old = f"uploads/{now - 1}/AbCdEfGhIjKlMnOp"
    live = f"uploads/{now + 900}/AbCdEfGhIjKlMnOp"
    stray = "uploads/not-a-path"
    for p in (old, live, stray):
        blob.put(p, b"x")
    BlobParts(blob, None).sweep(now)  # type: ignore[arg-type]
    assert set(blob.blobs) == {live}


# ---- through the app, into OneDrive -------------------------------------------------


@pytest.fixture
def od_app(world, p2_settings, memstore, oauth, blob, signer):
    from tests.test_onedrive import FakeOneDrive, FakeOneDriveOAuth

    drive = FakeOneDrive()
    app = build_app(
        p2_settings,
        world.as_user(OWNER_EMAIL),
        store=memstore,
        owner_drive_factory=lambda token: world.as_user(OWNER_EMAIL),
        oauth=oauth,
        onedrive_api_factory=drive.factory,
        onedrive_oauth=FakeOneDriveOAuth(drive),
        blob_api=blob,
        blob_signer=signer,
    )
    c = client(app)
    login(c)
    connect(c)
    allow(c, SCHOOL)
    return c, drive


def test_an_assistant_uploads_to_onedrive_through_a_link(od_app, blob, signer):
    c, drive = od_app
    data = b"%PDF-1.4 " + bytes(range(256)) * 15
    out = write(
        c,
        "onedrive_start_upload",
        name="resume.pdf",
        size=len(data),
        sha256=sha(data),
        direct=True,
    )
    started = out["structuredContent"]
    assert not out["isError"] and "upload_command" in started
    assert "upload_command" in started["next"]
    [(path, max_bytes, _, _)] = signer.puts
    assert max_bytes == len(data) and drive.writes() == []

    blob.put(path, data)
    done = write(c, "finish_upload", upload_id=started["upload_id"])
    made = done["structuredContent"]
    assert not done["isError"] and made["name"] == "resume.pdf"
    assert drive.content[made["id"]] == data
    assert path not in blob.blobs


def test_a_viewer_gets_no_link(od_app, signer):
    c, _ = od_app
    out = write(
        c,
        "onedrive_start_upload",
        role="viewer",
        name="a.pdf",
        size=2000,
        sha256="0" * 64,
        direct=True,
    )
    assert out["isError"] and signer.puts == []


def test_a_folder_removed_before_finish_gets_nothing_from_a_link(od_app, blob, signer):
    from tests.dash import csrf

    c, drive = od_app
    data = bytes(3000)
    started = write(
        c, "onedrive_start_upload", name="a.bin", size=len(data), sha256=sha(data), direct=True
    )["structuredContent"]
    blob.put(signer.puts[0][0], data)
    token = csrf(c, "/files?tab=onedrive")
    c.post("/onedrive/remove", data={"csrf": token, "file_id": SCHOOL})
    out = write(c, "finish_upload", upload_id=started["upload_id"])
    assert error_of(out) == "onedrive_not_allowed"
    assert drive.writes() == []

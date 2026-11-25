"""Chunked uploads (start_upload / append_chunk / finish_upload) and Drive exports."""

import base64
import hashlib
import json
import os

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from scoped_drive_mcp.auth import Principal, current_principal
from scoped_drive_mcp.config import Role
from scoped_drive_mcp.drive_client import DriveExportTooLargeError
from scoped_drive_mcp.scope import InvalidInputError, OutOfScopeError, ScopeGuard
from scoped_drive_mcp.server import create_mcp
from scoped_drive_mcp.service import DOC_MIME, PDF_MIME, DriveService
from scoped_drive_mcp.store import ActivityLog, MemoryStore
from scoped_drive_mcp.uploads import MAX_STARTS, UPLOAD_TTL, UploadError, UploadSessions
from tests.conftest import OWNER_EMAIL, ROOT, make_settings
from tests.dash import mcp_call  # noqa: F401  (keeps the shared helpers importable)
from tests.test_external_sharing import _error
from tests.test_multi_user import _mcp
from tests.test_peer_edit import _set, setup  # noqa: F401  (fixture)

ME = {"email": OWNER_EMAIL, "token_name": "editor-tok", "grant_id": None}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def pieces(data: bytes, size: int) -> list[str]:
    return [b64(data[i : i + size]) for i in range(0, len(data), size)]


@pytest.fixture
def sessions(clock) -> UploadSessions:
    return UploadSessions(MemoryStore(clock), max_bytes=64 * 1024, clock=clock)


def _start(sessions: UploadSessions, data: bytes, chunk_size: int = 1024, who=ME, **kw):
    args = {
        "name": "report.pdf",
        "mime_type": "application/pdf",
        "parent_id": "sub-a",
        "size": len(data),
        "sha256": sha(data),
        "chunk_size": chunk_size,
    }
    args.update(kw)
    return sessions.start(who, **args)


def _code(exc_info) -> str:
    return exc_info.value.code


# ---- the session store ----------------------------------------------------------------


def test_pieces_in_any_order_assemble_to_the_file(sessions) -> None:
    data = os.urandom(3000)
    started = _start(sessions, data)
    assert started["chunk_count"] == 3 and started["last_chunk_size"] == 3000 - 2048
    uid = started["upload_id"]
    for index in (2, 0, 1):
        sessions.append(ME, uid, index, pieces(data, 1024)[index])
    meta, assembled = sessions.take(ME, uid)
    assert assembled == data
    assert meta["parent_id"] == "sub-a" and meta["name"] == "report.pdf"


def test_missing_pieces_are_listed_and_the_upload_stays_open(sessions) -> None:
    data = os.urandom(5000)
    uid = _start(sessions, data)["upload_id"]
    sessions.append(ME, uid, 1, pieces(data, 1024)[1])
    with pytest.raises(UploadError) as exc:
        sessions.take(ME, uid)
    assert _code(exc) == "missing_chunks"
    assert exc.value.details["missing"] == [0, 2, 3, 4]
    for index in (0, 2, 3, 4):
        sessions.append(ME, uid, index, pieces(data, 1024)[index])
    assert sessions.take(ME, uid)[1] == data


def test_a_repeated_piece_is_harmless_but_a_different_one_is_refused(sessions) -> None:
    data = os.urandom(2048)
    uid = _start(sessions, data)["upload_id"]
    first = pieces(data, 1024)[0]
    assert sessions.append(ME, uid, 0, first)["duplicate"] is False
    assert sessions.append(ME, uid, 0, first)["duplicate"] is True
    with pytest.raises(UploadError) as exc:
        sessions.append(ME, uid, 0, b64(bytes(1024)))
    assert _code(exc) == "chunk_conflict"


@pytest.mark.parametrize(
    ("index", "content", "code"),
    [
        (3, b64(bytes(1024)), "invalid_chunk"),  # past the last piece
        (-1, b64(bytes(1024)), "invalid_chunk"),
        (0, b64(bytes(1000)), "invalid_chunk"),  # not chunk_size bytes
        (2, b64(bytes(1024)), "invalid_chunk"),  # the last piece is shorter
        (0, "not base64!!", "invalid_chunk"),
        (0, b64(bytes(4096)), "invalid_chunk"),  # far too long, refused before decoding
        ("0", b64(bytes(1024)), "invalid_input"),
        (True, b64(bytes(1024)), "invalid_input"),
    ],
)
def test_bad_pieces_are_refused(sessions, index, content, code) -> None:
    uid = _start(sessions, os.urandom(2500))["upload_id"]
    with pytest.raises(UploadError) as exc:
        sessions.append(ME, uid, index, content)
    assert _code(exc) == code


def test_a_hash_mismatch_writes_nothing_and_discards_the_upload(sessions) -> None:
    data = os.urandom(2048)
    uid = _start(sessions, data, sha256=sha(b"something else"))["upload_id"]
    for index, piece in enumerate(pieces(data, 1024)):
        sessions.append(ME, uid, index, piece)
    with pytest.raises(UploadError) as exc:
        sessions.take(ME, uid)
    assert _code(exc) == "integrity_mismatch"
    assert exc.value.details["received_sha256"] == sha(data)
    assert not [k for k in sessions.store._values if k.startswith("upload:") and ":c:" in k]
    with pytest.raises(UploadError) as again:
        sessions.take(ME, uid)
    assert _code(again) == "upload_not_found"


def test_uploads_expire(sessions, clock) -> None:
    data = os.urandom(2048)
    uid = _start(sessions, data)["upload_id"]
    sessions.append(ME, uid, 0, pieces(data, 1024)[0])
    clock.advance(UPLOAD_TTL + 1)
    for call in (
        lambda: sessions.append(ME, uid, 1, pieces(data, 1024)[1]),
        lambda: sessions.take(ME, uid),
        lambda: sessions.cancel(ME, uid),
    ):
        with pytest.raises(UploadError) as exc:
            call()
        assert _code(exc) == "upload_not_found"


@pytest.mark.parametrize(
    "other",
    [
        {**ME, "email": "eve@example.com"},
        {**ME, "token_name": "other-tok"},
        {**ME, "grant_id": "another-app"},
    ],
)
def test_an_upload_belongs_to_the_sign_in_that_started_it(sessions, other) -> None:
    data = os.urandom(1024)
    uid = _start(sessions, data)["upload_id"]
    for call in (
        lambda: sessions.append(other, uid, 0, b64(data)),
        lambda: sessions.take(other, uid),
        lambda: sessions.cancel(other, uid),
    ):
        with pytest.raises(UploadError) as exc:
            call()
        assert _code(exc) == "upload_not_found"
    sessions.append(ME, uid, 0, b64(data))
    assert sessions.take(ME, uid)[1] == data


@pytest.mark.parametrize("upload_id", ["", "../x", "a" * 200, None, 5])
def test_malformed_ids_are_not_found(sessions, upload_id) -> None:
    with pytest.raises(UploadError) as exc:
        sessions.append(ME, upload_id, 0, "")
    assert _code(exc) == "upload_not_found"


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"size": 64 * 1024 + 1}, "too_large"),
        ({"size": 0}, "invalid_input"),
        ({"chunk_size": 512}, "invalid_input"),
        ({"chunk_size": 1024 * 1024}, "invalid_input"),
        ({"sha256": "abc"}, "invalid_input"),
        ({"sha256": "g" * 64}, "invalid_input"),
    ],
)
def test_start_checks_its_input(sessions, overrides, code) -> None:
    with pytest.raises(UploadError) as exc:
        _start(sessions, os.urandom(2048), **overrides)
    assert _code(exc) == code


def test_starts_are_limited_per_account(sessions, clock) -> None:
    for _ in range(MAX_STARTS):
        _start(sessions, b"x" * 10)
    with pytest.raises(UploadError) as exc:
        _start(sessions, b"x" * 10)
    assert _code(exc) == "too_many_uploads"
    # Someone else is not affected, and the window passes.
    _start(sessions, b"x" * 10, who={**ME, "email": "eve@example.com"})
    clock.advance(UPLOAD_TTL + 1)
    _start(sessions, b"x" * 10)


def test_a_finish_in_progress_blocks_a_second_one(sessions) -> None:
    data = os.urandom(1024)
    uid = _start(sessions, data)["upload_id"]
    sessions.append(ME, uid, 0, b64(data))
    sessions.take(ME, uid)
    with pytest.raises(UploadError) as exc:
        sessions.take(ME, uid)
    assert _code(exc) == "upload_busy"
    sessions.release(uid)
    assert sessions.take(ME, uid)[1] == data


def test_cancel_removes_every_piece(sessions) -> None:
    data = os.urandom(2048)
    uid = _start(sessions, data)["upload_id"]
    sessions.append(ME, uid, 0, pieces(data, 1024)[0])
    assert sessions.cancel(ME, uid)["cancelled"] is True
    assert not [k for k in sessions.store._values if k.startswith(f"upload:{uid}")]


def test_accepted_pieces_stay_out_of_the_activity_list() -> None:
    store = MemoryStore()
    log = ActivityLog(store)
    row = {"event": "tool_call", "tool": "append_chunk", "decision": "allow", "reason": "ok"}
    log(row)
    log({**row, "decision": "error", "reason": "invalid_chunk"})
    log({**row, "tool": "finish_upload"})
    kept = [json.loads(r) for r in store.lrange("activity", 0, -1)]
    assert [(r["tool"], r["decision"]) for r in kept] == [
        ("finish_upload", "allow"),
        ("append_chunk", "error"),
    ]


# ---- the tools ------------------------------------------------------------------------


def _mcp_for(drive, clock, access=None, max_bytes: int = 4096):
    settings = make_settings(bot_email=None, max_bytes=max_bytes)
    service = DriveService(drive, ScopeGuard(drive, ROOT, ttl=60, clock=clock), settings)
    sessions = UploadSessions(MemoryStore(clock), max_bytes, clock=clock)
    return create_mcp(service, access, uploads=sessions), sessions


async def _call(mcp, tool: str, role: Role = Role.EDITOR, **args) -> dict:
    token = current_principal.set(Principal(token_name=f"{role}-tok", role=role, email=OWNER_EMAIL))
    try:
        result = await mcp.call_tool(tool, args)
    finally:
        current_principal.reset(token)
    if isinstance(result, tuple):
        return result[1]
    return result.structuredContent | {"isError": result.isError}


async def _upload(mcp, data: bytes, chunk_size: int, **start) -> dict:
    started = await _call(
        mcp,
        "start_upload",
        name=start.pop("name", "resume.pdf"),
        mime_type="application/pdf",
        size=len(data),
        sha256=start.pop("sha256", sha(data)),
        chunk_size=chunk_size,
        **start,
    )
    uid = started["upload_id"]
    for index, piece in reversed(list(enumerate(pieces(data, chunk_size)))):
        await _call(mcp, "append_chunk", upload_id=uid, index=index, content_base64=piece)
    return await _call(mcp, "finish_upload", upload_id=uid)


@pytest.mark.anyio
async def test_a_megabyte_pdf_reaches_drive_in_pieces(drive, clock, capsys) -> None:
    data = b"%PDF-1.7\n" + os.urandom(1536 * 1024)
    mcp, _ = _mcp_for(drive, clock, max_bytes=2 * 1024 * 1024)
    created = await _upload(mcp, data, 256 * 1024, parent_id="sub-a")
    f = drive.files[created["id"]]
    assert f.content == data and f.parents == ["sub-a"] and f.mime_type == "application/pdf"
    assert created["byte_count"] == len(data) and created["sha256"] == sha(data)

    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.strip()]
    tools = [r["tool"] for r in rows]
    assert tools[0] == "start_upload" and tools[-1] == "finish_upload"
    assert {r["upload_id"] for r in rows} == {created["upload_id"]}
    assert rows[0]["parent_id"] == "sub-a" and rows[-1]["file_id"] == created["id"]
    assert all(r["decision"] == "allow" and r["token_name"] == "editor-tok" for r in rows)


@pytest.mark.anyio
async def test_the_default_parent_is_used_when_there_is_one(drive, clock) -> None:
    mcp, _ = _mcp_for(drive, clock)
    created = await _upload(mcp, os.urandom(3000), 1024)
    assert drive.files[created["id"]].parents == [ROOT]


@pytest.mark.anyio
async def test_a_hash_mismatch_leaves_nothing_in_drive(drive, clock) -> None:
    mcp, _ = _mcp_for(drive, clock)
    before = set(drive.files)
    result = await _upload(mcp, os.urandom(3000), 1024, sha256="0" * 64)
    assert result["isError"] is True and result["error"] == "integrity_mismatch"
    assert set(drive.files) == before


@pytest.mark.anyio
async def test_an_unshared_folder_is_refused_before_any_bytes(drive, clock, access) -> None:
    mcp, sessions = _mcp_for(drive, clock, access)
    result = await _call(
        mcp,
        "start_upload",
        name="x.pdf",
        mime_type="application/pdf",
        size=10,
        sha256="0" * 64,
        parent_id="outside-folder",
    )
    assert result["isError"] is True and result["error"] == "access_required"
    assert not sessions.store._values


@pytest.mark.anyio
async def test_a_file_is_not_a_parent(drive, clock) -> None:
    mcp, _ = _mcp_for(drive, clock)
    with pytest.raises(ToolError, match="parent_id must be a folder"):
        await _call(
            mcp,
            "start_upload",
            name="x.pdf",
            mime_type="application/pdf",
            size=10,
            sha256="0" * 64,
            parent_id="notes-txt",
        )


@pytest.mark.anyio
async def test_the_folder_is_checked_again_at_finish(drive, clock) -> None:
    mcp, _ = _mcp_for(drive, clock)
    data = os.urandom(1024)
    started = await _call(
        mcp,
        "start_upload",
        name="x.bin",
        mime_type="application/octet-stream",
        size=len(data),
        sha256=sha(data),
        parent_id="sub-a",
    )
    uid = started["upload_id"]
    await _call(mcp, "append_chunk", upload_id=uid, index=0, content_base64=b64(data))
    drive.files["sub-a"].parents = ["outside-folder"]  # moved out of the share meanwhile
    with pytest.raises(ToolError, match="Forbidden"):
        await _call(mcp, "finish_upload", upload_id=uid)
    assert not [f for f in drive.files.values() if f.content == data]


@pytest.mark.anyio
async def test_a_failed_drive_write_can_be_retried(drive, clock, monkeypatch) -> None:
    mcp, _ = _mcp_for(drive, clock)
    data = os.urandom(1024)
    started = await _call(
        mcp,
        "start_upload",
        name="x.bin",
        mime_type="application/octet-stream",
        size=len(data),
        sha256=sha(data),
    )
    uid = started["upload_id"]
    await _call(mcp, "append_chunk", upload_id=uid, index=0, content_base64=b64(data))
    real = drive.create

    def flaky(*args, **kwargs):
        monkeypatch.setattr(drive, "create", real)
        raise RuntimeError("Drive 503")

    monkeypatch.setattr(drive, "create", flaky)
    with pytest.raises(ToolError, match="Drive request failed"):
        await _call(mcp, "finish_upload", upload_id=uid)
    created = await _call(mcp, "finish_upload", upload_id=uid)
    assert drive.files[created["id"]].content == data


@pytest.mark.anyio
async def test_viewers_cannot_upload(drive, clock) -> None:
    mcp, _ = _mcp_for(drive, clock)
    uid = "x" * 24
    calls = {
        "start_upload": {"name": "a.pdf", "mime_type": PDF_MIME, "size": 5, "sha256": "0" * 64},
        "append_chunk": {"upload_id": uid, "index": 0, "content_base64": ""},
        "finish_upload": {"upload_id": uid},
        "cancel_upload": {"upload_id": uid},
    }
    for tool, args in calls.items():
        with pytest.raises(ToolError, match="Permission denied"):
            await _call(mcp, tool, role=Role.VIEWER, **args)


@pytest.mark.anyio
async def test_google_types_cannot_be_uploaded(drive, clock) -> None:
    mcp, _ = _mcp_for(drive, clock)
    with pytest.raises(ToolError, match="create_doc"):
        await _call(mcp, "start_upload", name="d", mime_type=DOC_MIME, size=5, sha256="0" * 64)


def test_a_paired_person_can_upload_into_a_folder_they_may_edit(setup, world) -> None:  # noqa: F811
    _app_, owner, eve, carol = setup
    c, token = eve
    data = os.urandom(3000)

    def start(who=eve, parent="proj"):
        return _mcp(
            who[0],
            who[1],
            "start_upload",
            owner=OWNER_EMAIL,
            name="eve.pdf",
            mime_type="application/pdf",
            size=len(data),
            sha256=sha(data),
            chunk_size=1024,
            parent_id=parent,
        )

    # Read-only until the owner marks the folder editable.
    assert _error(start())["error"] == "not_shared"
    _set(owner, "proj")
    assert _error(start(parent="priv"))["error"] == "not_shared"

    started = start()
    assert started["isError"] is False, started
    uid = started["structuredContent"]["upload_id"]
    for index, piece in enumerate(pieces(data, 1024)):
        sent = _mcp(c, token, "append_chunk", upload_id=uid, index=index, content_base64=piece)
        assert sent["isError"] is False, sent
    # Another person's assistant cannot use or finish Eve's upload.
    stolen = _mcp(carol[0], carol[1], "finish_upload", upload_id=uid)
    assert _error(stolen)["error"] == "upload_not_found"
    done = _mcp(c, token, "finish_upload", upload_id=uid)
    assert done["isError"] is False, done
    f = world.files[done["structuredContent"]["id"]]
    assert f.content == data and f.parents == ["proj"]
    assert f.app_properties["botrbac_writer"] == "guest:eve@example.com"


# ---- exports --------------------------------------------------------------------------

PDF = b"%PDF-1.7 the deep secret plan"


@pytest.fixture
def exportable(drive):
    drive.files["doc-deep"].exports[PDF_MIME] = PDF
    return drive


def test_export_a_doc_as_pdf(exportable, service: DriveService) -> None:
    result = service.export_file("doc-deep", "PDF")
    assert base64.b64decode(result["content_base64"]) == PDF
    assert result["mime_type"] == PDF_MIME and result["format"] == "pdf"
    assert result["byte_count"] == len(PDF)


def test_a_large_export_returns_no_partial_file(exportable, service: DriveService) -> None:
    exportable.files["doc-deep"].exports[PDF_MIME] = b"%PDF" + bytes(service.max_bytes)
    result = service.export_file("doc-deep", "pdf")
    assert result["content_base64"] is None and result["too_large"] is True
    assert "save_export" in result["note"]


@pytest.mark.parametrize(
    ("file_id", "fmt", "match"),
    [
        ("notes-txt", "pdf", "only Google Docs"),
        ("sub-a", "pdf", "folder"),
        ("doc-deep", "xlsx", "format must be one of"),
        ("sheet-1", "docx", "format must be one of"),
        ("doc-deep", None, "format must be one of"),
    ],
)
def test_export_refuses_what_it_cannot_do(exportable, service, file_id, fmt, match) -> None:
    with pytest.raises(InvalidInputError, match=match):
        service.export_file(file_id, fmt)


def test_export_is_scope_checked(exportable, service: DriveService) -> None:
    with pytest.raises(OutOfScopeError):
        service.export_file("outside-file", "pdf")
    with pytest.raises(OutOfScopeError):
        service.save_export("doc-deep", "pdf", parent_id="outside-folder")


def test_save_export_goes_next_to_the_original(exportable, service: DriveService) -> None:
    created = service.save_export("doc-deep", "pdf")
    f = exportable.files[created["id"]]
    assert f.name == "Deep plan.pdf" and f.parents == ["sub-a-deep"]
    assert f.content == PDF and f.mime_type == PDF_MIME
    assert created["exported_from"] == "doc-deep"


def test_save_export_takes_a_folder_and_a_name(exportable, service: DriveService) -> None:
    created = service.save_export("doc-deep", "pdf", parent_id="sub-a", name="Plan v2.pdf")
    f = exportable.files[created["id"]]
    assert f.name == "Plan v2.pdf" and f.parents == ["sub-a"]


def test_export_over_drives_limit(exportable, service: DriveService) -> None:
    exportable.files["doc-deep"].exports[PDF_MIME] = DriveExportTooLargeError(PDF_MIME)
    with pytest.raises(InvalidInputError, match="10 MB"):
        service.export_file("doc-deep", "pdf")
    before = set(exportable.files)
    with pytest.raises(InvalidInputError, match="10 MB"):
        service.save_export("doc-deep", "pdf")
    assert set(exportable.files) == before


@pytest.mark.anyio
async def test_viewers_can_export_but_not_save(exportable, clock) -> None:
    mcp, _ = _mcp_for(exportable, clock)
    got = await _call(mcp, "export_file", role=Role.VIEWER, file_id="doc-deep")
    assert base64.b64decode(got["content_base64"]) == PDF
    with pytest.raises(ToolError, match="Permission denied"):
        await _call(mcp, "save_export", role=Role.VIEWER, file_id="doc-deep")
    saved = await _call(mcp, "save_export", file_id="doc-deep")
    assert exportable.files[saved["id"]].content == PDF

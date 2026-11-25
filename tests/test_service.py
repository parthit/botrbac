import base64
import json

import pytest

from scoped_drive_mcp.drive_client import FOLDER_MIME, DriveExportTooLargeError
from scoped_drive_mcp.extract import Extracted
from scoped_drive_mcp.extract_worker import ExtractBusy
from scoped_drive_mcp.scope import ForbiddenError, InvalidInputError
from scoped_drive_mcp.service import (
    DOC_MIME,
    DOWNLOAD_BYTE_CAP,
    SHEET_MIME,
    XLSX_MIME,
    DriveService,
    is_text_like,
)
from tests.conftest import ROOT, make_settings
from tests.office_files import (
    minimal_doc,
    minimal_docx,
    minimal_pdf,
    minimal_pptx,
    minimal_rtf,
    minimal_xlsx,
)

PDF_MIME = "application/pdf"
DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def test_read_google_doc_exports_text(service: DriveService) -> None:
    result = service.read_file("doc-deep")
    assert result["content"] == "the deep secret plan"
    assert result["exported_as"] == "text/plain"
    assert result["file"]["id"] == "doc-deep"


def test_read_sheet_exports_csv(service: DriveService) -> None:
    # This fake Sheet has no workbook export, so read_file falls back to the first tab.
    result = service.read_file("sheet-1")
    assert result["exported_as"] == "text/csv"
    assert result["content"].startswith("a,b")
    assert "first tab" in result["note"]


def _booking_sheet(drive, **exports) -> None:
    sheet = drive.add("sheet-tabs", "Maui-Oahu-Booking", SHEET_MIME, [ROOT], b"Day,Place\n1,Maui\n")
    sheet.exports.update(exports)


def test_read_sheet_returns_every_tab(drive, guard) -> None:
    service = DriveService(drive, guard, make_settings(max_bytes=100_000))
    workbook = minimal_xlsx(
        [["Day", "Place"], [1, "Maui"]],
        sheet="Itinerary",
        more=[("Reservations Confirmed", [["Hotel", "Conf #"], ["Andaz", "A123"]])],
    )
    _booking_sheet(drive, **{XLSX_MIME: workbook})
    result = service.read_file("sheet-tabs")
    assert result["exported_as"] == XLSX_MIME
    assert "# Itinerary" in result["content"]
    assert "# Reservations Confirmed" in result["content"]
    assert "Andaz\tA123" in result["content"]
    assert result["truncated"] is False
    assert "note" not in result


def test_read_sheet_over_export_limit_falls_back_to_first_tab(drive, service) -> None:
    _booking_sheet(drive, **{XLSX_MIME: DriveExportTooLargeError(XLSX_MIME)})
    result = service.read_file("sheet-tabs")
    assert result["exported_as"] == "text/csv"
    assert result["content"].startswith("Day,Place")
    assert "too large" in result["note"]


def test_read_sheet_over_byte_cap_falls_back_to_first_tab(drive, service) -> None:
    workbook = minimal_xlsx([["Day"]], more=[("Reservations Confirmed", [["Andaz"]])])
    assert len(workbook) > 4096  # the test byte cap
    _booking_sheet(drive, **{XLSX_MIME: workbook})
    result = service.read_file("sheet-tabs")
    assert result["exported_as"] == "text/csv"
    assert "too large" in result["note"]


def test_sheet_workbook_download_respects_download_byte_cap(drive, guard) -> None:
    # Readable (under max_bytes) but too big to send back as a response body.
    wide = DriveService(drive, guard, make_settings(max_bytes=5 * 1024 * 1024))
    _booking_sheet(drive, **{XLSX_MIME: b"PK" + b"x" * DOWNLOAD_BYTE_CAP})
    assert wide.export_sheet_workbook("sheet-tabs") is None
    drive.files["sheet-tabs"].exports[XLSX_MIME] = b"PK small"
    assert wide.export_sheet_workbook("sheet-tabs") == b"PK small"


def test_read_doc_over_export_limit_returns_a_note(drive, service) -> None:
    doc = drive.add("doc-huge", "Huge", DOC_MIME, [ROOT], b"never read")
    doc.exports["text/plain"] = DriveExportTooLargeError("text/plain")
    result = service.read_file("doc-huge")
    assert result["content"] is None
    assert "10 MB" in result["note"]


def test_read_sheet_csv_fallback_over_export_limit_returns_a_note(drive, service) -> None:
    _booking_sheet(
        drive,
        **{
            XLSX_MIME: DriveExportTooLargeError(XLSX_MIME),
            "text/csv": DriveExportTooLargeError("text/csv"),
        },
    )
    result = service.read_file("sheet-tabs")
    assert result["content"] is None
    assert "10 MB" in result["note"]


def test_read_sheet_truncation_ignores_cells_that_look_like_tab_headers(drive, guard) -> None:
    # The cut lands in the middle tab, after a cell that reads like a tab header.
    workbook = minimal_xlsx(
        [["short"]],
        sheet="First",
        more=[
            ("Second", [["# of guests"]] + [["x" * 50] for _ in range(40)]),
            ("Third", [["never shown"]]),
        ],
    )
    _booking_sheet(drive, **{XLSX_MIME: workbook})
    small = DriveService(drive, guard, make_settings(max_bytes=100_000, max_chars=1000))
    result = small.read_file("sheet-tabs")
    assert result["truncated"] is True
    assert len(result["content"]) == 1000
    assert "'Second'" in result["note"]
    assert "never shown" not in result["content"]


def test_read_single_tab_sheet_truncation_names_the_tab(drive, guard) -> None:
    workbook = minimal_xlsx([["x" * 50] for _ in range(40)], sheet="Only")
    _booking_sheet(drive, **{XLSX_MIME: workbook})
    small = DriveService(drive, guard, make_settings(max_bytes=100_000, max_chars=1000))
    result = small.read_file("sheet-tabs")
    assert result["truncated"] is True
    assert "# Only" not in result["content"]  # one tab: no header line
    assert "'Only'" in result["note"]


def test_read_sheet_cut_short_by_the_work_allowance_says_rows_are_missing(drive, guard) -> None:
    _booking_sheet(drive, **{XLSX_MIME: b"PK workbook"})
    service = DriveService(drive, guard, make_settings(max_bytes=100_000))
    service._workbook_tabs = lambda data: ([("Itinerary", "Day\tPlace")], True)
    result = service.read_file("sheet-tabs")
    assert result["content"] == "Day\tPlace"
    assert result["truncated"] is True
    assert "later rows are missing" in result["note"]


def test_read_sheet_whose_workbook_fails_falls_back_to_first_tab(drive, guard) -> None:
    _booking_sheet(drive, **{XLSX_MIME: b"PK not really a workbook"})
    service = DriveService(drive, guard, make_settings(max_bytes=100_000))
    result = service.read_file("sheet-tabs")
    assert result["exported_as"] == "text/csv"
    assert result["content"].startswith("Day,Place")
    assert "could not be read whole" in result["note"]


def test_google_file_without_a_text_export_returns_a_note(drive, service) -> None:
    drive.add("form-1", "Survey", "application/vnd.google-apps.form", [ROOT])
    result = service.read_file("form-1")
    assert result["content"] is None
    assert "cannot be exported as text" in result["note"]
    assert drive.content_calls == []


def test_read_text_file(service: DriveService) -> None:
    result = service.read_file("notes-txt")
    assert result["content"] == "plan notes inside"
    assert result["truncated"] is False


def test_read_binary_not_returned(service: DriveService) -> None:
    result = service.read_file("image-png")
    assert result["content"] is None
    assert "binary" in result["note"]
    assert "download_file" in result["note"]


def test_read_documents_nested_in_shared_folder(drive, guard) -> None:
    # In process: the child gives the same text (test_extract checks that), and a child
    # per file would make this the slowest test here.
    service = DriveService(drive, guard, make_settings(max_bytes=100_000, extract_isolation=False))
    name = "Parthit Patel Resume - AI Labs (1 page).docx"
    files = [
        ("resume-pdf", f"{name} (1).pdf", PDF_MIME, "sub-a-deep", minimal_pdf("AI Labs resume")),
        ("resume-docx", name, DOCX_MIME, "sub-a", minimal_docx("AI Labs docx")),
        ("slides", "deck.pptx", "application/octet-stream", "sub-a-deep", minimal_pptx("Roadmap")),
        ("sheet", "budget.xlsx", XLSX_MIME, "sub-a", minimal_xlsx([["Item", "Cost"], ["GPU", 12]])),
        ("notes-md", "README.md", "text/markdown", "sub-a", b"# Hello markdown"),
        ("payload", "data.json", "application/json", "sub-a", b'{"ok": true}'),
        ("legacy", "old.doc", "application/msword", "sub-a-deep", minimal_doc("legacy body")),
        ("letter", "letter.rtf", "application/rtf", "sub-a", minimal_rtf("rtf body")),
        ("table", "rows.csv", "text/csv", "sub-a", b"a,b\n1,2\n"),
    ]
    for file_id, file_name, mime, parent, content in files:
        drive.add(file_id, file_name, mime, [parent], content)
    read = {file_id: service.read_file(file_id) for file_id, *_ in files}
    assert read["resume-pdf"]["content"] == "AI Labs resume"
    assert read["resume-pdf"]["extracted_as"] == "text/plain"
    assert read["resume-docx"]["content"] == "AI Labs docx\ncell text"
    assert read["slides"]["content"] == "Roadmap"
    assert read["sheet"]["content"] == "Item\tCost\nGPU\t12"  # one tab: no header line
    assert read["notes-md"]["content"] == "# Hello markdown"
    assert read["payload"]["content"] == '{"ok": true}'
    assert read["legacy"]["content"] == "legacy body"
    assert read["letter"]["content"] == "rtf body\n"
    assert read["table"]["content"] == "a,b\n1,2\n"


def test_read_and_download_outside_share_are_refused(drive, service: DriveService) -> None:
    secret = "outside resume text"
    drive.add(
        "outside-pdf",
        "secret.pdf",
        PDF_MIME,
        ["outside-folder"],
        minimal_pdf(secret),
    )
    drive.add(
        "outside-docx",
        "secret.docx",
        DOCX_MIME,
        ["outside-folder"],
        minimal_docx(secret),
    )
    drive.add(
        "outside-bin", "secret.bin", "application/octet-stream", ["outside-folder"], b"secret-bytes"
    )
    for file_id in ("outside-pdf", "outside-docx", "outside-bin", "outside-file"):
        with pytest.raises(ForbiddenError):
            service.read_file(file_id)
        with pytest.raises(ForbiddenError):
            service.download_file(file_id)
    assert "outside-pdf" not in drive.content_calls
    assert "outside-docx" not in drive.content_calls
    assert "outside-bin" not in drive.content_calls
    assert secret not in " ".join(drive.content_calls)


def test_download_file_returns_bytes_and_caps_them(drive, service: DriveService) -> None:
    image = service.download_file("image-png")
    assert base64.b64decode(image["content_base64"]) == drive.files["image-png"].content
    assert image["truncated"] is False
    pdf = minimal_pdf("kept for bytes")
    drive.add("resume-pdf", "resume.pdf", PDF_MIME, ["sub-a-deep"], pdf)
    downloaded = service.download_file("resume-pdf")
    assert base64.b64decode(downloaded["content_base64"]) == pdf

    drive.add("fat", "archive.bin", "application/zip", [ROOT], b"z" * 5000)
    capped = service.download_file("fat")
    assert capped["truncated"] is True
    assert capped["byte_count"] == 4096  # test settings max_bytes
    assert base64.b64decode(capped["content_base64"]) == b"z" * 4096


def test_download_file_hard_cap_is_independent_of_a_large_max_bytes(drive, guard) -> None:
    wide = DriveService(drive, guard, make_settings(max_bytes=5 * 1024 * 1024))
    payload = b"q" * (DOWNLOAD_BYTE_CAP + 10)
    drive.add("fat", "blob.bin", "application/octet-stream", [ROOT], payload)
    capped = wide.download_file("fat")
    assert capped["truncated"] is True
    assert capped["byte_count"] == DOWNLOAD_BYTE_CAP


# ---- document text ----------------------------------------------------------------


def test_read_file_reads_a_pdf_in_the_child_process(drive, service) -> None:
    assert service.extract_isolation  # the default
    drive.add("plain-pdf", "plain.pdf", PDF_MIME, [ROOT], minimal_pdf("from the child"))
    result = service.read_file("plain-pdf")
    assert result["content"] == "from the child"
    assert result["truncated"] is False


def test_service_reads_in_process_when_isolation_is_off(monkeypatch) -> None:
    from scoped_drive_mcp import service as service_module

    def no_child(*args: object, **kwargs: object) -> None:
        raise AssertionError("isolation is off")

    monkeypatch.setattr(service_module, "extract_isolated", no_child)
    off = DriveService(None, None, make_settings(extract_isolation=False))  # type: ignore[arg-type]
    assert off._extract(minimal_pdf("in process"), "pdf").text == "in process"
    on = DriveService(None, None, make_settings())  # type: ignore[arg-type]
    with pytest.raises(AssertionError, match="isolation is off"):
        on._extract(minimal_pdf("x"), "pdf")


def test_extracted_text_respects_max_chars(drive, guard) -> None:
    service = DriveService(drive, guard, make_settings(max_bytes=100_000, max_chars=2000))
    drive.add("long-docx", "long.docx", DOCX_MIME, [ROOT], minimal_docx("x" * 3000))
    result = service.read_file("long-docx")
    assert result["truncated"] is True
    assert len(result["content"]) == 2000


def test_read_file_marks_text_cut_short_by_the_work_allowance(drive, service) -> None:
    drive.add("busy-pdf", "busy.pdf", PDF_MIME, [ROOT], minimal_pdf("start"))
    service._extract = lambda data, kind: Extracted("start", truncated=True)
    result = service.read_file("busy-pdf")
    assert result["content"] == "start"
    assert result["truncated"] is True
    assert "too large or complex" in result["note"]


def test_read_file_returns_rtf_with_unicode_escapes_that_are_surrogates(drive, service) -> None:
    """RTF's \\u-10240? is a lone surrogate; read_file then failed whole with
    "surrogates not allowed" when the reply was encoded."""
    rtf = rb"{\rtf1\ansi lone \u-10240? pair \u-10179?\u-8704? end\par}"
    drive.add("rtf-surrogate", "notes.rtf", "application/rtf", [ROOT], rtf)
    result = service.read_file("rtf-surrogate")
    assert result["content"] == "lone � pair \U0001f600 end\n"
    json.dumps(result, ensure_ascii=False).encode("utf-8")


def test_document_over_max_bytes_is_read_only_up_to_the_cap(drive, service) -> None:
    """Only max_bytes + 1 bytes are fetched; a cut-off document says why it has no text."""
    asked: list[int] = []
    download = drive.download

    def counting(file_id: str, max_bytes: int) -> bytes:
        asked.append(max_bytes)
        return download(file_id, max_bytes)

    drive.download = counting
    data = minimal_docx("x" * 5000)
    assert len(data) > 4096  # the test byte cap
    drive.add("big-docx", "big.docx", DOCX_MIME, [ROOT], data)
    result = service.read_file("big-docx")
    assert asked == [4097]
    assert result["content"] is None
    assert result["truncated"] is True
    assert "exceeds the 4096-byte limit" in result["note"]


@pytest.mark.parametrize(
    ("data", "outcome", "note"),
    [
        (b"%PDF-1.4 nope", None, "Use download_file for the bytes"),
        (minimal_pdf(""), None, "no extractable text"),
        (b"", ExtractBusy("the server is busy; try again"), "try again"),
        # An unexpected failure must not show its message (it may quote the file).
        (b"", RuntimeError("secret detail"), "text could not be extracted"),
    ],
    ids=["unreadable", "image-only", "busy", "crashed"],
)
def test_document_without_text_returns_a_note(drive, service, data, outcome, note) -> None:
    if outcome is not None:

        def fail(data: bytes, kind: str) -> Extracted:
            raise outcome

        service._extract = fail
    drive.add("doc-pdf", "doc.pdf", PDF_MIME, [ROOT], data or minimal_pdf("x"))
    result = service.read_file("doc-pdf")
    assert result["content"] is None
    assert note in result["note"]
    assert "secret detail" not in json.dumps(result)


def test_text_from_bytes_reads_what_read_file_would(service: DriveService) -> None:
    """read_drop's text for a held file, which is not in Drive."""
    docx = service.text_from_bytes(minimal_docx("held"), DOCX_MIME, "held.docx")
    assert docx["content"] == "held\ncell text"
    text = service.text_from_bytes(b"y" * 5000, "text/plain", "long.txt")
    assert text["content"] == "y" * 2000 and text["truncated"] is True
    assert service.text_from_bytes(b"a\x00b", "text/plain", "nul.txt")["content"] is None
    binary = service.text_from_bytes(b"\x89PNG", "image/png", "photo.png")
    assert binary["content"] is None and "binary" in binary["note"]


def test_download_skips_google_files_shortcuts_and_folders(service: DriveService, drive) -> None:
    doc = service.download_file("doc-deep")
    assert doc["content_base64"] is None
    assert "read_file" in doc["note"]
    shortcut = service.download_file("shortcut-1")
    assert shortcut["content_base64"] is None
    assert "not followed" in shortcut["note"]
    with pytest.raises(InvalidInputError):
        service.download_file("sub-a")
    assert drive.content_calls == []


def test_read_skips_shortcuts_and_rejects_folders(service: DriveService, drive) -> None:
    shortcut = service.read_file("shortcut-1")
    assert shortcut["content"] is None
    assert "not followed" in shortcut["note"]
    with pytest.raises(InvalidInputError):
        service.read_file("sub-a")
    assert drive.content_calls == []


def test_read_respects_max_bytes_and_chars(drive, service: DriveService) -> None:
    drive.add("big-txt", "big.txt", "text/plain", [ROOT], b"x" * 10_000)
    result = service.read_file("big-txt")
    assert result["truncated"] is True
    assert len(result["content"]) == 2000  # max_chars in test settings
    drive.add("nul-txt", "nul.txt", "text/plain", [ROOT], b"abc\x00def")
    assert service.read_file("nul-txt")["content"] is None


@pytest.mark.parametrize("file_id", ["outside-file", "cycle-file", "trashed-txt", "orphan-file"])
def test_read_outside_forbidden(service: DriveService, file_id: str) -> None:
    with pytest.raises(ForbiddenError):
        service.read_file(file_id)
    with pytest.raises(ForbiddenError):
        service.get_metadata(file_id)


def test_list_folder_without_id_lists_allowed_items(service: DriveService) -> None:
    result = service.list_folder()
    assert [f["id"] for f in result["files"]] == [ROOT]
    assert result["folder"] is None


def test_list_root_folder(service: DriveService) -> None:
    result = service.list_folder(ROOT)
    ids = {f["id"] for f in result["files"]}
    assert ids == {"sub-a", "sheet-1", "image-png", "shortcut-1"}
    assert result["folder"]["id"] == ROOT


def test_list_folder_pagination_and_limit(drive, service: DriveService) -> None:
    for i in range(15):
        drive.add(f"many-{i:03d}", f"m{i}", "text/plain", ["sub-a-deep"])
    drive.page_size_cap = 4
    result = service.list_folder("sub-a-deep", max_results=10)
    assert len(result["files"]) == 10 and result["truncated"] is True
    result = service.list_folder("sub-a-deep", max_results=100)
    assert len(result["files"]) == 16 and result["truncated"] is False


def test_list_outside_folder_forbidden(service: DriveService) -> None:
    with pytest.raises(ForbiddenError):
        service.list_folder("outside-folder")


def test_search_tool(service: DriveService) -> None:
    ids = {f["id"] for f in service.search_files("plan", 50)["files"]}
    assert ids == {"doc-deep", "notes-txt", "multi-parent"}
    with pytest.raises(InvalidInputError):
        service.search_files("   ")
    with pytest.raises(InvalidInputError):
        service.search_files("x" * 500)


def test_create_folder_and_doc(drive, service: DriveService) -> None:
    folder = service.create_folder("Reports")
    assert folder["parents"] == [ROOT]
    doc = service.create_doc("Q1", "hello", parent_id=folder["id"])
    assert drive.files[doc["id"]].mime_type == DOC_MIME
    assert drive.files[doc["id"]].parents == [folder["id"]]
    # new folder is immediately usable for search
    assert folder["id"] in service.guard.folders_in_scope()


@pytest.mark.parametrize("parent", ["outside-folder", "cycle-a", "bot-my-drive-root", "nope-nope"])
def test_create_into_outside_parent_denied(drive, service: DriveService, parent: str) -> None:
    before = set(drive.files)
    with pytest.raises(ForbiddenError):
        service.create_folder("x", parent_id=parent)
    with pytest.raises(ForbiddenError):
        service.create_doc("x", "y", parent_id=parent)
    with pytest.raises(ForbiddenError):
        service.upload_file("x.txt", "text/plain", content_text="y", parent_id=parent)
    assert set(drive.files) == before


def test_create_into_file_parent_rejected(service: DriveService) -> None:
    with pytest.raises(InvalidInputError):
        service.create_folder("x", parent_id="notes-txt")


def test_upload_file_variants(drive, service: DriveService) -> None:
    r = service.upload_file(
        "a.bin", "application/octet-stream", content_base64=base64.b64encode(b"\x00\x01").decode()
    )
    assert drive.files[r["id"]].content == b"\x00\x01"
    r = service.upload_file("b.txt", "text/plain", content_text="hi", parent_id="sub-a")
    assert drive.files[r["id"]].parents == ["sub-a"]


_TOO_BIG_B64 = base64.b64encode(b"x" * 4097).decode()  # within the length check, 1 byte over


@pytest.mark.parametrize(
    ("name", "mime", "content", "error"),
    [
        ("c.txt", "text/plain", {}, "exactly one"),
        ("c.txt", "text/plain", {"content_text": "a", "content_base64": "YQ=="}, "exactly one"),
        ("c.txt", "text/plain", {"content_base64": "not base64!!"}, "not valid base64"),
        ("c.txt", "text/plain", {"content_base64": 5}, "must be a string"),
        ("c", "application/vnd.google-apps.shortcut", {"content_text": "x"}, "create_doc"),
        ("c", "not a mime", {"content_text": "x"}, "type/subtype"),
        (5, "text/plain", {"content_text": "x"}, "must be a string"),
        ("n" * 256, "text/plain", {"content_text": "x"}, "at most 255"),
        # The byte cap holds whichever way the content comes.
        ("c.txt", "text/plain", {"content_text": "x" * 5000}, "4096-byte limit"),
        ("c.txt", "text/plain", {"content_base64": "A" * 6000}, "4096-byte limit"),
        ("c.txt", "text/plain", {"content_base64": _TOO_BIG_B64}, "4096-byte limit"),
    ],
)
def test_upload_file_refuses_bad_input(drive, service, name, mime, content, error) -> None:
    before = set(drive.files)
    with pytest.raises(InvalidInputError, match=error):
        service.upload_file(name, mime, **content)
    assert set(drive.files) == before


def test_update_file_content(drive, service: DriveService) -> None:
    service.update_file_content("notes-txt", "new body")
    assert drive.files["notes-txt"].content == b"new body"
    service.update_file_content("doc-deep", "new doc body")
    assert drive.files["doc-deep"].content == b"new doc body"
    with pytest.raises(InvalidInputError):
        service.update_file_content("image-png", "x")
    with pytest.raises(InvalidInputError):
        service.update_file_content("sheet-1", "x")
    with pytest.raises(ForbiddenError):
        service.update_file_content("outside-file", "x")
    with pytest.raises(ForbiddenError):
        service.update_file_content(ROOT, "x")


def test_rename(drive, service: DriveService) -> None:
    service.rename_file("notes-txt", "renamed.txt")
    assert drive.files["notes-txt"].name == "renamed.txt"
    with pytest.raises(ForbiddenError):
        service.rename_file("outside-file", "x")
    with pytest.raises(InvalidInputError):
        service.rename_file("notes-txt", "   ")
    with pytest.raises(InvalidInputError):
        service.rename_file("notes-txt", "bad\nname")


def test_root_cannot_be_trashed_or_renamed(drive, service: DriveService) -> None:
    with pytest.raises(ForbiddenError):
        service.trash_file(ROOT)
    with pytest.raises(ForbiddenError):
        service.rename_file(ROOT, "hijacked")
    assert drive.files[ROOT].trashed is False
    assert drive.files[ROOT].name == "Shared With Grok"


def test_trash(drive, service: DriveService) -> None:
    result = service.trash_file("sub-a-deep")
    assert result["trashed"] is True and drive.files["sub-a-deep"].trashed
    assert "sub-a-deep" not in service.guard.folders_in_scope()
    with pytest.raises(ForbiddenError):
        service.trash_file("outside-file")
    assert drive.files["outside-file"].trashed is False


def test_writes_never_touch_parents(drive, service: DriveService) -> None:
    # FakeDrive.update asserts that only name/trashed metadata is ever sent.
    service.rename_file("sub-a", "Projects 2")
    service.trash_file("notes-txt")
    assert drive.files["sub-a"].parents == [ROOT]


@pytest.mark.parametrize(
    ("mime", "name", "expected"),
    [
        ("text/plain", "", True),
        ("text/markdown", "", True),
        ("application/json", "", True),
        ("application/ld+json", "", True),
        ("application/octet-stream", "readme.md", True),
        ("application/octet-stream", "photo.jpg", False),
        ("image/png", "x.txt", False),
        ("application/pdf", "", False),
        (FOLDER_MIME, "", False),
    ],
)
def test_is_text_like(mime: str, name: str, expected: bool) -> None:
    assert is_text_like(mime, name) is expected


# ---- parents are cut down to in-scope ids ---------------------------------------------


def test_root_folder_parent_is_not_shown(service: DriveService) -> None:
    meta = service.get_metadata(ROOT)
    assert "parents" not in meta  # its parent is the owner's My Drive
    assert service.list_folder(ROOT)["folder"].get("parents") is None
    assert service.get_metadata("sub-a")["parents"] == [ROOT]


def test_outside_parent_of_multi_parent_file_is_removed(service: DriveService) -> None:
    assert service.get_metadata("multi-parent")["parents"] == ["sub-a"]
    assert service.read_file("multi-parent")["file"]["parents"] == ["sub-a"]
    listed = {f["id"]: f for f in service.list_folder("sub-a")["files"]}
    assert listed["multi-parent"]["parents"] == ["sub-a"]
    found = service.search_files("plan both")["files"]
    assert [f["parents"] for f in found] == [["sub-a"]]


def test_write_results_only_show_in_scope_parents(service: DriveService) -> None:
    assert service.rename_file("multi-parent", "renamed.txt")["parents"] == ["sub-a"]
    assert service.update_file_content("multi-parent", "x")["parents"] == ["sub-a"]
    assert service.create_folder("new", parent_id="sub-a")["parents"] == ["sub-a"]
    assert service.trash_file("multi-parent")["parents"] == ["sub-a"]


def test_no_output_mentions_outside_ids(service: DriveService) -> None:
    outputs = [
        service.list_folder(ROOT),
        service.list_folder("sub-a"),
        service.get_metadata(ROOT),
        service.search_files("plan"),
        service.read_file("multi-parent"),
    ]
    text = str(outputs)
    assert "outside-folder" not in text and "bot-my-drive-root" not in text


def test_read_sheet_when_the_server_is_busy_says_so(drive, guard, monkeypatch) -> None:
    """A busy reader is not a broken workbook: say "try again", don't fall back quietly."""
    from scoped_drive_mcp import service as service_module
    from scoped_drive_mcp.extract_worker import ExtractBusy

    service = DriveService(drive, guard, make_settings(max_bytes=100_000))
    workbook = minimal_xlsx([["Day", "Place"], [1, "Maui"]], sheet="Itinerary")
    _booking_sheet(drive, **{XLSX_MIME: workbook})

    def busy(*args, **kwargs):
        raise ExtractBusy("the server is busy reading other files; try again in a few seconds")

    monkeypatch.setattr(service_module, "xlsx_tabs_isolated", busy)
    monkeypatch.setattr(service_module, "read_xlsx_tabs", busy, raising=False)
    result = service.read_file("sheet-tabs")
    assert "busy" in result["note"]
    assert "content" not in result or not result["content"]

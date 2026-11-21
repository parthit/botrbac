import base64

import pytest

from scoped_drive_mcp.drive_client import FOLDER_MIME, DriveExportTooLargeError
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


def test_read_sheet_truncation_names_the_cut_tab(drive, guard) -> None:
    workbook = minimal_xlsx(
        [["short"]], sheet="First", more=[("Second", [["x" * 50] for _ in range(40)])]
    )
    _booking_sheet(drive, **{XLSX_MIME: workbook})
    small = DriveService(drive, guard, make_settings(max_bytes=100_000, max_chars=1000))
    result = small.read_file("sheet-tabs")
    assert result["truncated"] is True
    assert len(result["content"]) == 1000
    assert "'Second'" in result["note"]


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
    service = DriveService(drive, guard, make_settings(max_bytes=100_000))
    drive.add(
        "resume-pdf",
        "Parthit Patel Resume - AI Labs (1 page).docx (1).pdf",
        "application/pdf",
        ["sub-a-deep"],
        minimal_pdf("AI Labs resume"),
    )
    drive.add(
        "resume-docx",
        "Parthit Patel Resume - AI Labs (1 page).docx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ["sub-a"],
        minimal_docx("AI Labs docx"),
    )
    drive.add(
        "slides",
        "deck.pptx",
        "application/octet-stream",
        ["sub-a-deep"],
        minimal_pptx("Roadmap"),
    )
    drive.add(
        "sheet",
        "budget.xlsx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ["sub-a"],
        minimal_xlsx([["Item", "Cost"], ["GPU", 12]]),
    )
    drive.add("notes-md", "README.md", "text/markdown", ["sub-a"], b"# Hello markdown")
    drive.add("payload", "data.json", "application/json", ["sub-a"], b'{"ok": true}')
    drive.add("legacy", "old.doc", "application/msword", ["sub-a-deep"], minimal_doc("legacy body"))
    drive.add("letter", "letter.rtf", "application/rtf", ["sub-a"], minimal_rtf("rtf body"))
    drive.add("table", "rows.csv", "text/csv", ["sub-a"], b"a,b\n1,2\n")

    assert "AI Labs resume" in service.read_file("resume-pdf")["content"]
    assert service.read_file("resume-pdf")["extracted_as"] == "text/plain"
    assert "AI Labs docx" in service.read_file("resume-docx")["content"]
    assert "Roadmap" in service.read_file("slides")["content"]
    assert "GPU" in service.read_file("sheet")["content"]
    assert service.read_file("notes-md")["content"] == "# Hello markdown"
    assert service.read_file("payload")["content"] == '{"ok": true}'
    assert service.read_file("legacy")["content"] == "legacy body"
    assert "rtf body" in service.read_file("letter")["content"]
    assert service.read_file("table")["content"] == "a,b\n1,2\n"


def test_read_and_download_outside_share_are_refused(drive, service: DriveService) -> None:
    secret = "outside resume text"
    drive.add(
        "outside-pdf",
        "secret.pdf",
        "application/pdf",
        ["outside-folder"],
        minimal_pdf(secret),
    )
    drive.add(
        "outside-docx",
        "secret.docx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
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
    drive.add("resume-pdf", "resume.pdf", "application/pdf", ["sub-a-deep"], pdf)
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


def test_extracted_text_respects_max_chars(drive, guard) -> None:
    service = DriveService(drive, guard, make_settings(max_bytes=100_000, max_chars=2000))
    drive.add(
        "long-docx",
        "long.docx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        [ROOT],
        minimal_docx("x" * 3000),
    )
    result = service.read_file("long-docx")
    assert result["truncated"] is True
    assert len(result["content"]) == 2000


def test_unreadable_pdf_returns_a_note(drive, service: DriveService) -> None:
    drive.add("bad-pdf", "bad.pdf", "application/pdf", [ROOT], b"%PDF-1.4 nope")
    result = service.read_file("bad-pdf")
    assert result["content"] is None
    assert "download_file" in result["note"]


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


def test_read_shortcut_not_followed(service: DriveService) -> None:
    result = service.read_file("shortcut-1")
    assert result["content"] is None


def test_read_folder_rejected(service: DriveService) -> None:
    with pytest.raises(InvalidInputError):
        service.read_file("sub-a")


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
    with pytest.raises(InvalidInputError):
        service.upload_file("c.txt", "text/plain")
    with pytest.raises(InvalidInputError):
        service.upload_file("c.txt", "text/plain", content_text="a", content_base64="YQ==")
    with pytest.raises(InvalidInputError):
        service.upload_file("c.txt", "text/plain", content_base64="not base64!!")
    with pytest.raises(InvalidInputError):
        service.upload_file("c", "application/vnd.google-apps.shortcut", content_text="x")
    with pytest.raises(InvalidInputError):
        service.upload_file("c", "not a mime", content_text="x")
    with pytest.raises(InvalidInputError):
        service.upload_file("c.txt", "text/plain", content_text="x" * 5000)


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

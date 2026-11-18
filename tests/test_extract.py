import pytest

from scoped_drive_mcp.extract import ExtractError, document_kind, extract_text
from tests.office_files import (
    minimal_doc,
    minimal_docx,
    minimal_pdf,
    minimal_pptx,
    minimal_rtf,
    minimal_xlsx,
)

PDF = "application/pdf"
DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
DOC = "application/msword"
PPTX = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def test_kind_prefers_mime_and_falls_back_to_extension() -> None:
    assert document_kind(PDF, "resume.docx") == "pdf"
    assert document_kind("application/octet-stream", "notes.md") is None
    assert document_kind("application/octet-stream", "Resume.DOCX") == "docx"
    assert document_kind("", "sheet.xlsx") == "xlsx"
    assert document_kind("text/rtf", "x.bin") == "rtf"
    assert document_kind("image/png", "photo.png") is None


def test_pdf_text() -> None:
    text = extract_text(minimal_pdf("Hello PDF"), "pdf", char_limit=1000)
    assert "Hello PDF" in text


def test_docx_includes_body_table_and_header() -> None:
    data = minimal_docx("Quarter plan", header="Confidential")
    text = extract_text(data, "docx", char_limit=1000)
    assert "Quarter plan" in text
    assert "cell text" in text
    assert "Confidential" in text


def test_mislabeled_doc_that_is_really_a_zip_is_read_as_docx() -> None:
    text = extract_text(minimal_docx("zipped word"), "doc", char_limit=1000)
    assert "zipped word" in text


def test_pptx_slides_stay_in_order() -> None:
    text = extract_text(minimal_pptx("First slide", "Second slide"), "pptx", char_limit=1000)
    assert text.index("First slide") < text.index("Second slide")


def test_xlsx_cells() -> None:
    data = minimal_xlsx([["Name", "Role"], ["Ada", "Labs"]])
    text = extract_text(data, "xlsx", char_limit=1000)
    assert "Name\tRole" in text
    assert "Ada\tLabs" in text


def test_rtf_and_legacy_doc() -> None:
    assert "plain words" in extract_text(minimal_rtf("plain words"), "rtf", char_limit=1000)
    assert extract_text(minimal_doc("legacy resume"), "doc", char_limit=1000) == "legacy resume"


def test_doc_paragraph_marks_become_newlines() -> None:
    assert extract_text(minimal_doc("one\ntwo"), "doc", char_limit=1000) == "one\ntwo"


def test_doc_compressed_pieces() -> None:
    # Word stores plain ASCII in compressed pieces (bit 30 of fc, offset = fc/2).
    text = extract_text(minimal_doc("compressed resume", compressed=True), "doc", char_limit=1000)
    assert text == "compressed resume"


def test_char_limit_stops_the_result() -> None:
    text = extract_text(minimal_docx("abcdefghij"), "docx", char_limit=4)
    assert text.startswith("abcd")
    assert len(text) <= 5


def test_password_note_and_garbage_do_not_raise_past_extract_error() -> None:
    with pytest.raises(ExtractError):
        extract_text(b"%PDF-1.4 garbage", "pdf", char_limit=100)
    with pytest.raises(ExtractError):
        extract_text(b"not a document", "docx", char_limit=100)


def test_empty_pdf_has_no_text() -> None:
    assert extract_text(minimal_pdf(""), "pdf", char_limit=100).strip() == ""

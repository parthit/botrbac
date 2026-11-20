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
    assert "cell text\nConfidential" in text


def test_mislabeled_doc_that_is_really_a_zip_is_read_as_docx() -> None:
    text = extract_text(minimal_docx("zipped word"), "doc", char_limit=1000)
    assert "zipped word" in text


def test_pptx_slides_stay_in_order() -> None:
    text = extract_text(minimal_pptx("First slide", "Second slide"), "pptx", char_limit=1000)
    assert "First slide\nSecond slide" in text


def test_xlsx_cells() -> None:
    data = minimal_xlsx([["Name", "Role"], ["Ada", "Labs"]], more=[("Costs", [["GPU"]])])
    text = extract_text(data, "xlsx", char_limit=1000)
    assert "Name\tRole" in text
    assert "Ada\tLabs\n# Costs\nGPU" in text


def test_pdf_pages_are_separated() -> None:
    text = extract_text(minimal_pdf("Page one", "Page two"), "pdf", char_limit=1000)
    assert "Page one" in text and "Page two" in text
    assert "onePage" not in text.replace(" ", "")


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


def test_doc_overlapping_pieces_stop_at_the_character_limit() -> None:
    """Pieces may point at the same bytes; the output must not grow to pieces x stream size."""
    import struct

    from scoped_drive_mcp.extract import _doc_text

    pieces = 5000
    body = b"A" * 4000
    word = bytearray(0x200) + body
    count = len(body)
    cps = [i * count for i in range(pieces + 1)]
    plc = struct.pack(f"<{pieces + 1}I", *cps)
    # Compressed pieces: fc holds byte offset * 2 with bit 30 set.
    fc = (0x200 * 2) | 0x40000000
    plc += b"".join(struct.pack("<HIH", 0, fc, 0) for _ in range(pieces))
    clx = b"\x02" + struct.pack("<I", len(plc)) + plc
    struct.pack_into("<II", word, 0x1A2, 0, len(clx))

    text = _doc_text(bytes(word), clx, char_limit=10_000)
    assert text.startswith("AAAA")
    assert len(text) <= 10_000 + count

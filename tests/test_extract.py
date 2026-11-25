"""Text extraction from Office files, PDF and RTF, in process and in the isolated child.

Most cases below are small crafted files that, before the shared work budget, made
read_file spend seconds to minutes (or hundreds of megabytes): a part listed many
times, a million empty rows, a regex that backtracks, a form drawn again and again.
Their timing limits guard against denial of service; do not loosen them.
"""

import datetime
import io
import json
import struct
import subprocess
import sys
import threading
import time
import tracemalloc
import zipfile
import zlib
from pathlib import Path

import pytest

from scoped_drive_mcp import extract as extract_module
from scoped_drive_mcp import extract_worker
from scoped_drive_mcp.extract import (
    Extracted,
    ExtractError,
    _doc_text,
    clean_text,
    document_kind,
    extract,
    extract_text,
    xlsx_tabs,
)
from scoped_drive_mcp.extract_worker import extract_isolated, xlsx_tabs_isolated
from tests.office_files import (
    minimal_doc,
    minimal_docx,
    minimal_pdf,
    minimal_pptx,
    minimal_rtf,
    minimal_xlsx,
)

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
A = "http://schemas.openxmlformats.org/drawingml/2006/main"
P = "http://schemas.openxmlformats.org/presentationml/2006/main"
REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG = "http://schemas.openxmlformats.org/package/2006/relationships"
SHEET = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
PDF = "application/pdf"
_MB = 1024 * 1024


def _zip(files: dict[str, str | bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, body in files.items():
            archive.writestr(name, body)
    return buf.getvalue()


def _word(body: str) -> bytes:
    return _zip(
        {"word/document.xml": f'<w:document xmlns:w="{W}"><w:body>{body}</w:body></w:document>'}
    )


class _Timer:
    def __enter__(self) -> "_Timer":
        self.start = time.monotonic()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.seconds = time.monotonic() - self.start


def _peak_bytes(run) -> tuple[object, int]:
    """run() and the most memory Python allocated while it ran."""
    tracemalloc.start()
    try:
        result = run()
        return result, tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


# ---- normal files ----


def test_kind_prefers_mime_and_falls_back_to_extension() -> None:
    assert document_kind(PDF, "resume.docx") == "pdf"
    assert document_kind("application/octet-stream", "notes.md") is None
    assert document_kind("application/octet-stream", "Resume.DOCX") == "docx"
    assert document_kind("", "sheet.xlsx") == "xlsx"
    assert document_kind("text/rtf", "x.bin") == "rtf"
    assert document_kind("image/png", "photo.png") is None


@pytest.mark.parametrize(
    ("kind", "data", "expected"),
    [
        ("pdf", minimal_pdf("Page one", "Page two"), "Page one\nPage two"),
        ("pdf", minimal_pdf(""), ""),
        ("pptx", minimal_pptx("First slide", "Second slide"), "First slide\nSecond slide"),
        (
            "xlsx",
            minimal_xlsx([["Name", "Role"], ["Ada", "Labs"]], more=[("Costs", [["GPU", 3]])]),
            "# Resume\nName\tRole\nAda\tLabs\n# Costs\nGPU\t3",
        ),
        ("rtf", minimal_rtf("plain words"), "plain words\n"),
        ("doc", minimal_doc("legacy resume"), "legacy resume"),
        ("doc", minimal_doc("one\ntwo"), "one\ntwo"),  # paragraph marks become newlines
        # Word stores plain ASCII in compressed pieces (bit 30 of fc, offset = fc/2).
        ("doc", minimal_doc("compressed resume", compressed=True), "compressed resume"),
        ("doc", minimal_docx("zipped word"), "zipped word\ncell text"),  # mislabeled .docx
    ],
    ids=[
        "pdf-pages",
        "pdf-empty",
        "pptx",
        "xlsx",
        "rtf",
        "doc",
        "doc-lines",
        "doc-8bit",
        "doc-zip",
    ],
)
def test_reads_each_format(kind: str, data: bytes, expected: str) -> None:
    assert extract(data, kind, char_limit=1000) == Extracted(expected)


def test_garbage_is_an_extract_error() -> None:
    with pytest.raises(ExtractError):
        extract_text(b"%PDF-1.4 garbage", "pdf", char_limit=100)
    with pytest.raises(ExtractError):
        extract_text(b"not a document", "docx", char_limit=100)


def test_word_text_is_cut_at_the_limit_and_marked_truncated() -> None:
    """Body paragraphs, then the table, then the header; every cut is marked."""
    full = "one\ntwo\ncell text\nHead"
    data = minimal_docx("one", "two", header="Head")
    for limit in range(1, len(full) + 3):
        result = extract(data, "docx", char_limit=limit)
        assert result.text == full[: limit + 1]
        assert result.truncated == (len(full) > limit), limit


def test_word_newlines_are_counted_only_between_blocks() -> None:
    """The first paragraph of each part counted a newline too, so the budget filled up
    early: the header was dropped and the text not marked truncated."""
    limit = 50
    body = "x" * (limit - 1)
    result = extract(minimal_docx(body, header="Head"), "docx", char_limit=limit)
    assert result.text == (body + "\ncell text\nHead")[: limit + 1]
    assert result.truncated
    exact = extract(minimal_docx("a" * 20, "b" * 19), "docx", char_limit=60)
    assert exact == Extracted("a" * 20 + "\n" + "b" * 19 + "\ncell text")


def test_a_text_box_paragraph_is_its_own_line_not_repeated() -> None:
    body = (
        "<w:p><w:r><w:t>before </w:t></w:r>"
        "<w:r><w:txbxContent><w:p><w:r><w:t>in the box</w:t></w:r></w:p></w:txbxContent></w:r>"
        "<w:r><w:t>after</w:t></w:r></w:p>"
        "<w:p><w:r><w:t>next</w:t><w:tab/><w:t>tabbed</w:t><w:br/><w:t>broken</w:t></w:r></w:p>"
    )
    text = extract_text(_word(body), "docx", char_limit=1000)
    assert text == "before after\nin the box\nnext\ttabbed\nbroken"


def test_workbook_tabs_and_dates() -> None:
    data = minimal_xlsx([["Name", "Role"], ["Ada", "Labs"]], more=[("Costs", [["GPU", 3]])])
    assert xlsx_tabs(data, 1000) == [
        ("Resume", "# Resume\nName\tRole\nAda\tLabs"),
        ("Costs", "# Costs\nGPU\t3"),
    ]
    # Named styles are stripped before openpyxl reads the workbook; dates must survive.
    dated = minimal_xlsx([["when", datetime.datetime(2024, 5, 6, 7, 8)]])
    assert xlsx_tabs(dated, 1000) == [("Resume", "when\t2024-05-06 07:08:00")]


def test_rtf_keeps_fonts_unicode_and_escapes() -> None:
    data = (
        b"{\\rtf1\\ansi\\ansicpg1252\\deff0{\\fonttbl{\\f0\\fswiss\\fcharset0 Arial;}"
        b"{\\f1\\fnil\\fcharset204 Times;}}{\\colortbl;\\red0\\green0\\blue0;}"
        b"\\f0 Hello \\b bold\\b0  world\\par Second\\tab tabbed\\par "
        b"{\\f1 \\'cf\\'f0\\'e8} caf\\'e9 \\u8364?euro{\\*\\unknown hidden}\\line end}"
    )
    text = extract_text(data, "rtf", char_limit=1000)
    assert text == "Hello bold world\nSecond\ttabbed\nПри café €euro\nend"


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (
            b'{\\rtf1 See {\\field{\\*\\fldinst{HYPERLINK "http://example.com"}}'
            b"{\\fldrslt{\\ul Example link}}} now.\\par}",
            'See Example link("http://example.com") now.\n',  # as striprtf did
        ),
        (b"{\\rtf1 Page {\\field{\\*\\fldinst{ PAGE }}{\\fldrslt 3}}.\\par}", "Page 3.\n"),
    ],
    ids=["hyperlink-keeps-target", "other-field-adds-nothing"],
)
def test_rtf_fields(data: bytes, expected: str) -> None:
    assert extract_text(data, "rtf", char_limit=1000) == expected


def test_clean_text_joins_surrogate_pairs_and_replaces_lone_halves() -> None:
    assert clean_text("plain") == "plain"
    assert clean_text("a😀b") == "a\U0001f600b"
    assert clean_text("a\ud800b\udfff") == "a�b�"


# ---- PowerPoint ----


def _pptx_one_slide_listed(times: int, text: str) -> bytes:
    slide = f'<p:sld xmlns:p="{P}" xmlns:a="{A}"><a:p><a:r><a:t>{text}</a:t></a:r></a:p></p:sld>'
    presentation = (
        f'<p:presentation xmlns:p="{P}" xmlns:r="{REL}"><p:sldIdLst>'
        + '<p:sldId r:id="rId1"/>' * times
        + "</p:sldIdLst></p:presentation>"
    )
    rels = (
        f'<Relationships xmlns="{PKG}"><Relationship Id="rId1" Type="{REL}/slide" '
        'Target="slides/slide1.xml"/></Relationships>'
    )
    return _zip(
        {
            "ppt/presentation.xml": presentation,
            "ppt/_rels/presentation.xml.rels": rels,
            "ppt/slides/slide1.xml": slide,
        }
    )


def test_a_slide_listed_many_times_is_read_once() -> None:
    data = _pptx_one_slide_listed(200_000, "x" * 2000)
    assert len(data) < 20_000
    with _Timer() as timer:
        text = extract_text(data, "pptx", char_limit=100_000)
    assert text == "x" * 2000
    assert timer.seconds < 2


def test_slide_text_stops_at_the_character_limit() -> None:
    data = minimal_pptx(*(f"slide {i} " + "y" * 500 for i in range(400)))
    with _Timer() as timer:
        text = extract_text(data, "pptx", char_limit=5000)
    assert text.startswith("slide 0 ")
    assert len(text) == 5001
    assert "slide 399" not in text
    assert timer.seconds < 2


# ---- Word ----


def test_a_million_empty_paragraphs_stop_at_the_character_limit() -> None:
    data = _word("<w:p/>" * 5_000_000)
    assert len(data) < 100_000
    with _Timer() as timer:
        text = extract_text(data, "docx", char_limit=1000)
    assert len(text) <= 1001
    assert timer.seconds < 2


def test_flat_elements_without_paragraphs_are_refused_quickly() -> None:
    with _Timer() as timer, pytest.raises(ExtractError, match="too complex"):
        extract_text(_word("<w:x/>" * 3_000_000), "docx", char_limit=1000)
    assert timer.seconds < 4


def test_the_work_budget_is_shared_by_every_part() -> None:
    """Each header is under the element cap; together they are not."""
    header = f'<w:hdr xmlns:w="{W}">' + "<w:x/>" * 300_000 + "</w:hdr>"
    files: dict[str, str | bytes] = {"word/document.xml": f'<w:document xmlns:w="{W}"/>'}
    for index in range(1, 6):
        files[f"word/header{index}.xml"] = header
    with _Timer() as timer, pytest.raises(ExtractError, match="too complex"):
        extract_text(_zip(files), "docx", char_limit=1000)
    assert timer.seconds < 4


def test_too_many_header_parts_are_refused() -> None:
    files: dict[str, str | bytes] = {"word/document.xml": f'<w:document xmlns:w="{W}"/>'}
    for index in range(1100):
        files[f"word/header{index}.xml"] = f'<w:hdr xmlns:w="{W}"/>'
    with pytest.raises(ExtractError, match="too many parts"):
        extract_text(_zip(files), "docx", char_limit=1000)


def test_word_attributes_count_as_work(monkeypatch: pytest.MonkeyPatch) -> None:
    """One element with 600 000 attributes took hundreds of MB and counted as one node.
    (The memory side is test_isolated_extraction_stops_at_the_memory_limit.)"""
    monkeypatch.setattr(extract_module, "_NODE_VISIT_CAP", 5000)
    attributes = " ".join(f'a{i}=""' for i in range(6000))
    with pytest.raises(ExtractError, match="too complex"):
        extract_text(_word(f"<w:p {attributes}/>"), "docx", char_limit=1000)


def test_word_work_allowance_grows_with_the_character_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Short paragraphs over the fixed allowance: a larger MAX_CHARS used to get a
    refusal instead of the text."""
    monkeypatch.setattr(extract_module, "_NODE_VISIT_CAP", 5000)
    body = "<w:p><w:r><w:t>abc</w:t></w:r></w:p>" * 1800  # 5400 elements
    text = extract_text(_word(body), "docx", char_limit=20_000)
    assert text == "\n".join(["abc"] * 1800)


def test_word_text_before_the_work_allowance_ran_out_is_returned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(extract_module, "_NODE_VISIT_CAP", 5000)
    body = "<w:p><w:r><w:t>hello</w:t></w:r></w:p>" * 100 + "<w:x/>" * 6000
    result = extract(_word(body), "docx", char_limit=1000)
    assert result == Extracted("\n".join(["hello"] * 100), truncated=True)


# ---- Excel ----


def _xlsx(
    sheet_body: str, sheets: int = 1, *, strings: str | None = None, styles: str | None = None
) -> bytes:
    sheet_list = "".join(
        f'<sheet name="s{i}" sheetId="{i + 1}" r:id="rId1"/>' for i in range(sheets)
    )
    strings_type = (
        '<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.'
        'openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>'
    )
    files = {
        "[Content_Types].xml": (
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.'
            'relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.'
            'openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            + (strings_type if strings is not None else "")
            + "</Types>"
        ),
        "_rels/.rels": (
            f'<Relationships xmlns="{PKG}"><Relationship Id="rId1" '
            f'Type="{REL}/officeDocument" Target="xl/workbook.xml"/></Relationships>'
        ),
        "xl/workbook.xml": (
            f'<workbook xmlns="{SHEET}" xmlns:r="{REL}"><sheets>{sheet_list}</sheets></workbook>'
        ),
        "xl/_rels/workbook.xml.rels": (
            f'<Relationships xmlns="{PKG}"><Relationship Id="rId1" Type="{REL}/worksheet" '
            'Target="worksheets/sheet1.xml"/></Relationships>'
        ),
        "xl/worksheets/sheet1.xml": (
            f'<worksheet xmlns="{SHEET}"><sheetData>{sheet_body}</sheetData></worksheet>'
        ),
    }
    if strings is not None:
        files["xl/sharedStrings.xml"] = strings
    if styles is not None:
        files["xl/styles.xml"] = styles
    return _zip(files)


def test_many_sheets_pointing_at_one_part_read_it_once() -> None:
    body = '<row r="1"><c t="inlineStr"><is><t>only</t></is></c></row>' + "<row/>" * 50_000
    data = _xlsx(body, sheets=200)
    assert len(data) < 10_000
    with _Timer() as timer:
        tabs = xlsx_tabs(data, 100_000)
    assert tabs == [("s0", "only")]
    assert timer.seconds < 2


def test_rows_that_repeat_one_row_number_are_refused_quickly() -> None:
    """openpyxl parses these but yields nothing, so only the tag count sees them."""
    data = _xlsx('<row r="1"/>' * 600_000)
    with _Timer() as timer, pytest.raises(ExtractError, match="too large"):
        xlsx_tabs(data, 100_000)
    assert timer.seconds < 4


def test_a_workbook_listing_too_many_sheets_is_refused_before_parsing() -> None:
    data = _xlsx("<row/>", sheets=600_000)
    with _Timer() as timer, pytest.raises(ExtractError, match="too large"):
        xlsx_tabs(data, 100_000)
    assert timer.seconds < 4


def test_sheet_text_stops_at_the_character_limit() -> None:
    rows = [[f"row {i}", "z" * 50] for i in range(5000)]
    with _Timer() as timer:
        tabs = xlsx_tabs(minimal_xlsx(rows), 2000)
    assert len(tabs) == 1
    assert tabs[0][1].startswith("row 0\t")
    assert len(tabs[0][1]) < 2100
    assert timer.seconds < 2


def test_xlsx_shared_string_repeated_in_every_cell_is_cut_before_joining() -> None:
    """A 3 KB workbook (one 32 000-character string in 30 000 cells) joined a 1 GB row."""
    strings = f'<sst xmlns="{SHEET}"><si><t>{"A" * 32_000}</t></si></sst>'
    row = '<row r="1">' + '<c t="s"><v>0</v></c>' * 30_000 + "</row>"
    data = _xlsx(row, strings=strings)
    assert len(data) < 5000
    with _Timer() as timer:
        result, peak = _peak_bytes(lambda: extract(data, "xlsx", char_limit=100_000))
    assert result.text == ("A" * 32_000 + "\t") * 3 + "A" * 3_998
    assert result.truncated
    assert peak < 60 * _MB
    assert timer.seconds < 2


def test_xlsx_named_styles_are_not_expanded() -> None:
    """openpyxl joins named styles with number formats, quadratically: 20 000 of each
    took 57 s."""
    count = 6000
    styles = (
        f'<styleSheet xmlns="{SHEET}"><numFmts>'
        + "".join(f'<numFmt numFmtId="{200 + i}" formatCode="0.0{i}"/>' for i in range(count))
        + "</numFmts><fonts><font/></fonts><fills><fill>"
        + '<patternFill patternType="none"/></fill></fills><borders><border/></borders>'
        + "<cellStyleXfs>"
        + '<xf numFmtId="200" fontId="0" fillId="0" borderId="0"/>' * count
        + '</cellStyleXfs><cellXfs><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/>'
        + "</cellXfs><cellStyles>"
        + "".join(f'<cellStyle name="s{i}" xfId="{i}"/>' for i in range(count))
        + "</cellStyles></styleSheet>"
    )
    data = _xlsx('<row r="1"><c t="inlineStr"><is><t>hi</t></is></c></row>', styles=styles)
    with _Timer() as timer:
        assert xlsx_tabs(data, 1000) == [("s0", "hi")]
    assert timer.seconds < 2


def test_xlsx_large_shared_string_table_has_its_own_allowance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A shared-string table with more tags than the workbook's allowance (260 000
    unique strings at the real caps) got a normal 1.5 MB workbook refused; the old code
    read its first 100 000 chars. Caps scaled down 100x to keep the test fast."""
    monkeypatch.setattr(extract_module, "_XLSX_MARKUP_CAP", 5000)
    monkeypatch.setattr(extract_module, "_XLSX_STRINGS_MARKUP_CAP", 20_000)
    count, rows = 2600, 200
    strings = (
        f'<sst xmlns="{SHEET}">' + "".join(f"<si><t>s{i}</t></si>" for i in range(count)) + "</sst>"
    )
    body = "".join(
        f'<row r="{r + 1}">'
        + "".join(f'<c t="s"><v>{(r * 8 + c) % count}</v></c>' for c in range(8))
        + "</row>"
        for r in range(rows)
    )
    result = extract(_xlsx(body, strings=strings), "xlsx", char_limit=1000)
    expected = "\n".join(
        "\t".join(f"s{(r * 8 + c) % count}" for c in range(8)) for r in range(rows)
    )
    assert result == Extracted(expected[:1001], truncated=True)


# ---- RTF ----


def test_rtf_hyperlink_fields_do_not_backtrack() -> None:
    """striprtf's hyperlink regex took about 70 s on 70 KB of this."""
    data = b"{\\rtf1 " + b'{\\field{\\*\\fldinst{ HYPERLINK "x" ' * 50_000 + b"}"
    with _Timer() as timer:
        text = extract_text(data, "rtf", char_limit=1000)
    assert text == ""
    assert timer.seconds < 2


def test_rtf_font_table_does_not_backtrack() -> None:
    """striprtf's font-table regex took about 9 s on 100 KB of this."""
    data = b"{\\rtf1{\\fonttbl" + b"\\f1 x" * 100_000 + b"}visible}"
    with _Timer() as timer:
        text = extract_text(data, "rtf", char_limit=1000)
    assert text == "visible"
    assert timer.seconds < 2


def test_rtf_control_words_are_capped() -> None:
    data = b"{\\rtf1 " + b"\\b" * 2_500_000 + b"}"
    with _Timer() as timer, pytest.raises(ExtractError, match="too complex"):
        extract_text(data, "rtf", char_limit=1000)
    assert timer.seconds < 4


def test_rtf_stops_at_the_character_limit_and_skips_binary() -> None:
    # The six bytes after \\bin6 look like group marks but are picture data.
    data = b"{\\rtf1 {\\*\\pict\\bin6 }}}{{{}" + b"a" * 5_000_000 + b"}"
    with _Timer() as timer:
        text = extract_text(data, "rtf", char_limit=1000)
    assert text == "a" * 1001
    assert timer.seconds < 1


# ---- legacy .doc ----


def _doc_streams(body: bytes, pieces: int) -> tuple[bytes, bytes]:
    """A WordDocument stream holding `body` at 0x200 and a piece table of `pieces`
    compressed pieces that all cover the whole of it (fc holds offset * 2 with bit 30)."""
    count = len(body)
    fc = (0x200 * 2) | 0x40000000
    cps = struct.pack(f"<{pieces + 1}I", *(i * count for i in range(pieces + 1)))
    plc = cps + b"".join(struct.pack("<HIH", 0, fc, 0) for _ in range(pieces))
    clx = b"\x02" + struct.pack("<I", len(plc)) + plc
    word = bytearray(0x200) + body
    struct.pack_into("<II", word, 0x1A2, 0, len(clx))
    return bytes(word), clx


def test_doc_overlapping_pieces_stop_at_the_character_limit() -> None:
    """Pieces may point at the same bytes; the output must not grow to pieces x stream size."""
    word, clx = _doc_streams(b"A" * 4000, 5000)
    text = _doc_text(word, clx, char_limit=10_000)
    assert text.startswith("AAAA")
    assert len(text) <= 10_000 + 4000


def test_doc_pieces_of_control_characters_are_capped() -> None:
    """Every piece covers the whole stream of dropped control codes: no output ever
    reaches the limit, so only the decoded-text cap stops the loop."""
    word, clx = _doc_streams(b"\x01" * 1_000_000, 2500)
    with _Timer() as timer, pytest.raises(ExtractError, match="too complex"):
        _doc_text(word, clx, char_limit=10_000)
    assert timer.seconds < 2


def test_doc_long_piece_stops_at_the_character_limit() -> None:
    word, clx = _doc_streams(b"word\r" * 1_000_000, 1)
    text = _doc_text(word, clx, char_limit=10_000)
    assert text.startswith("word\nword\n")
    assert len(text) <= 10_000 + 4096 + 1


# ---- PDF ----


def _pdf(objects: list[bytes]) -> bytes:
    out = bytearray(b"%PDF-1.5\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += f"trailer<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def _stream(content: bytes, extra: bytes = b"") -> bytes:
    packed = zlib.compress(content, 9)
    header = b"<< /Length %d /Filter /FlateDecode %s>>\nstream\n" % (len(packed), extra)
    return header + packed + b"\nendstream"


_FONT = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
_LINES = b"BT /F1 1 Tf 0 0 Td () Tj ET\n"


def _pdf_with_pages(contents: list[bytes], resources: bytes, extra: list[bytes]) -> bytes:
    """Pages with these content streams and resources; `extra` objects are numbered from
    3 + 2 * len(contents)."""
    count = len(contents)
    kids = b" ".join(b"%d 0 R" % (3 + 2 * index) for index in range(count))
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [%s] /Count %d >>" % (kids, count),
    ]
    for index, content in enumerate(contents):
        objects.append(
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 600 800] /Contents %d 0 R "
            b"/Resources %s >>" % (4 + 2 * index, resources)
        )
        objects.append(_stream(content))
    return _pdf(objects + extra)


def _text(words: str, y: int = 700) -> bytes:
    return b"BT /F1 12 Tf 50 %d Td (%s) Tj ET\n" % (y, words.encode())


def _form_page_pdf(content: bytes, form: bytes) -> bytes:
    """One page drawing form /X (object 6) with font /F1 (object 5)."""
    return _pdf(
        [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 400 200] /Contents 4 0 R "
            b"/Resources << /Font << /F1 5 0 R >> /XObject << /X 6 0 R >> >> >>",
            _stream(content),
            _FONT,
            _stream(
                form,
                b"/Type /XObject /Subtype /Form /BBox [0 0 400 200] "
                b"/Resources << /Font << /F1 5 0 R >> >> ",
            ),
        ]
    )


def test_pdf_page_listed_many_times_is_read_once() -> None:
    kids = b" ".join([b"3 0 R"] * 2000)
    data = _pdf(
        [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [%s] /Count 2000 >>" % kids,
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 400 200] /Contents 4 0 R "
            b"/Resources << /Font << /F1 5 0 R >> >> >>",
            _stream(_LINES * 2000 + b"BT /F1 12 Tf 0 0 Td (hello) Tj ET\n"),
            _FONT,
        ]
    )
    with _Timer() as timer:
        text = extract_text(data, "pdf", char_limit=100_000)
    assert text.strip() == "hello"
    assert timer.seconds < 2


def test_pdf_form_drawn_many_times_is_refused_quickly() -> None:
    """A 1 KB file: a page that draws one big form 2000 times took about 110 s."""
    data = _form_page_pdf(b"/X Do\n" * 2000, _LINES * 50_000)
    assert len(data) < 5000
    with _Timer() as timer, pytest.raises(ExtractError, match="too complex"):
        extract_text(data, "pdf", char_limit=100_000)
    # Refusing it takes 2-4 s of real work on a loaded CI machine; 10 s still fails the
    # 110 s regression by a wide margin without failing at random.
    assert timer.seconds < 10


def test_pdf_with_a_small_form_still_reads_its_text() -> None:
    data = _form_page_pdf(
        b"BT /F1 12 Tf 10 100 Td (page text) Tj ET\n/X Do\n",
        b"BT /F1 12 Tf 10 50 Td (form text) Tj ET\n",
    )
    text = extract_text(data, "pdf", char_limit=1000)
    assert "page text" in text and "form text" in text


def test_pdf_forms_a_page_never_draws_are_not_decoded() -> None:
    """Sizing every form up front decoded each one: 60 such forms took 4 GB."""
    forms = 12
    font_ref = 3 + 2 + forms  # after the page, its content and the forms
    names = b" ".join(b"/X%d %d 0 R" % (index, 5 + index) for index in range(forms))
    form = _stream(b" " * 20_000_000, b"/Type /XObject /Subtype /Form /BBox [0 0 1 1] ")
    data = _pdf_with_pages(
        [_text("hello")],
        b"<< /Font << /F1 %d 0 R >> /XObject << %s >> >>" % (font_ref, names),
        [form] * forms + [_FONT],
    )
    assert len(data) < 400_000
    with _Timer() as timer:
        text, peak = _peak_bytes(lambda: extract_text(data, "pdf", char_limit=1000))
    assert text.strip() == "hello"
    assert peak < 40 * _MB
    assert timer.seconds < 2


def test_pdf_page_naming_thousands_of_fonts_is_charged_before_pypdf_builds_them() -> None:
    """pypdf builds a font for every name a page lists before it reads one operator: 20 000
    names for one font with a 14 KB ToUnicode map took 74 s."""
    pairs = b"\n".join(b"<%04X> <0041>" % code for code in range(1000))
    cmap = b"begincmap\n1 begincodespacerange <0000> <FFFF> endcodespacerange\n"
    cmap += b"1000 beginbfchar\n" + pairs + b"\nendbfchar\nendcmap"
    names = b" ".join(b"/F%d 6 0 R" % index for index in range(5000))
    data = _pdf_with_pages(
        [_text("x")],
        b"<< /Font 5 0 R >>",
        [
            b"<< %s >>" % names,
            b"<< /Type /Font /Subtype /Type0 /BaseFont /X /Encoding /Identity-H "
            b"/ToUnicode 7 0 R /DescendantFonts [] >>",
            _stream(cmap),
        ],
    )
    with _Timer() as timer, pytest.raises(ExtractError, match="too complex"):
        extract_text(data, "pdf", char_limit=100_000)
    assert timer.seconds < 2


def _expanding_font_pdf(string_bytes: int, *, normal_page: bool = False) -> bytes:
    """A font whose ToUnicode map turns the byte `A` into 250 characters, and a page
    showing one string of `string_bytes` of them."""
    cmap = b"begincmap\n1 begincodespacerange <00> <FF> endcodespacerange\n"
    cmap += b"1 beginbfchar\n<41> <" + b"0042" * 250 + b">\nendbfchar\nendcmap"
    pages = [b"BT /F1 12 Tf 10 10 Td (" + b"A" * string_bytes + b") Tj ET"]
    if normal_page:
        pages.insert(0, b"BT /F2 12 Tf 10 10 Td (first page) Tj ET")
    return _pdf_with_pages(
        pages,
        b"<< /Font << /F1 %d 0 R /F2 %d 0 R >> >>" % (3 + 2 * len(pages), 5 + 2 * len(pages)),
        [
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /ToUnicode %d 0 R >>"
            % (4 + 2 * len(pages)),
            _stream(cmap),
            _FONT,
        ],
    )


def test_pdf_string_through_an_expanding_font_is_cut_to_the_limit() -> None:
    """12 KB of PDF became 3 GB of text in one Tj, before any limit was checked."""
    data = _expanding_font_pdf(400_000)
    assert len(data) < 5000
    with _Timer() as timer:
        result, peak = _peak_bytes(lambda: extract(data, "pdf", char_limit=1000))
    assert result.text == "B" * 1001
    assert result.truncated
    assert peak < 40 * _MB
    assert timer.seconds < 2


def test_pdf_page_over_the_stream_size_cap_is_skipped_not_the_file() -> None:
    """A 74 MB string took 19 s and 1 GB to parse. A page decoding past the cap is
    skipped; the pages before it are still returned, marked truncated."""
    data = _expanding_font_pdf(6_000_000, normal_page=True)
    with _Timer() as timer:
        result = extract(data, "pdf", char_limit=100_000)
    assert result.text == "first page"
    assert result.truncated
    assert timer.seconds < 2


def test_pdf_scatter_plot_page_is_read_whole() -> None:
    """A figure of 70 000 points was over a per-stream token cap of 250 000, and the
    whole file was refused."""
    plot = b"".join(
        b"%d %d 1 1 re f\n" % (i * 7919 % 500, i * 104_729 % 700) for i in range(70_000)
    )
    data = _pdf_with_pages(
        [
            _text("Introduction on page one"),
            plot + _text("Figure 1: scatter plot caption", 50),
            _text("Conclusion on page three"),
        ],
        b"<< /Font << /F1 9 0 R >> >>",
        [_FONT],
    )
    result = extract(data, "pdf", char_limit=100_000)
    assert result == Extracted(
        "Introduction on page one\nFigure 1: scatter plot caption\nConclusion on page three"
    )


def test_pdf_page_with_hundreds_of_forms_reads_them_all() -> None:
    """More than 256 forms on a page used to refuse the file."""
    forms = 300
    font_ref = 5 + forms
    names = b" ".join(b"/X%d %d 0 R" % (index, 5 + index) for index in range(forms))
    content = b"".join(b"/X%d Do\n" % index for index in range(forms))
    data = _pdf_with_pages(
        [content],
        b"<< /Font << /F1 %d 0 R >> /XObject << %s >> >>" % (font_ref, names),
        [
            _stream(
                _text(f"form {index}", 10 + index * 2),
                b"/Type /XObject /Subtype /Form /BBox [0 0 600 800] "
                b"/Resources << /Font << /F1 %d 0 R >> >> " % font_ref,
            )
            for index in range(forms)
        ]
        + [_FONT],
    )
    result = extract(data, "pdf", char_limit=100_000)
    assert result.text.split() == [word for i in range(forms) for word in ("form", str(i))]
    assert not result.truncated


def test_pdf_unused_form_with_an_unknown_filter_does_not_fail_the_file() -> None:
    bogus = b"<< /Length 4 /Type /XObject /Subtype /Form /Filter /Bogus >>\nstream\nabcd\nendstream"
    data = _pdf_with_pages(
        [_text("still readable")],
        b"<< /Font << /F1 6 0 R >> /XObject << /X 5 0 R >> >>",
        [bogus, _FONT],
    )
    assert extract(data, "pdf", char_limit=1000) == Extracted("still readable")


def test_pdf_out_of_work_returns_the_pages_read_marked_truncated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(extract_module, "_PDF_OPERATION_CAP", 50_000)
    busy = b"0 0 m\n" * 20_000  # 20 000 operators, no text
    data = _pdf_with_pages(
        [_text("page one"), _text("page two"), busy, busy, busy, _text("last page")],
        b"<< /Font << /F1 15 0 R >> >>",
        [_FONT],
    )
    result = extract(data, "pdf", char_limit=1000)
    assert result == Extracted("page one\npage two", truncated=True)


def test_pdf_blank_pages_do_not_use_up_the_character_limit() -> None:
    """Each blank page counted a newline it never added: 600 of them hid the text that
    followed, and the result was not marked truncated."""
    data = _pdf_with_pages(
        [b""] * 600 + [_text("after the blanks")],
        b"<< /Font << /F1 %d 0 R >> >>" % (3 + 2 * 601),
        [_FONT],
    )
    assert extract(data, "pdf", char_limit=500) == Extracted("after the blanks")


def _ligature_pdf(pages: int, chars_per_page: int, *, ligature: bool = True) -> bytes:
    """Pages of plain ASCII text in a font whose ToUnicode map, like a LaTeX font's, also
    maps one glyph to "ffi", so pypdf may turn a byte into 3 characters."""
    cmap = (
        b"/CIDInit /ProcSet findresource begin 12 dict begin begincmap\n"
        b"1 begincodespacerange <00> <FF> endcodespacerange\n"
        b"1 beginbfrange <20> <7E> <0020> endbfrange\n"
        b"1 beginbfchar <0E> <006600660069> endbfchar\n"
        b"endcmap CMapName currentdict /CMap defineresource pop end end"
    )
    line = b"The quick brown fox jumps over the lazy dog again "  # 50 characters
    content = b"BT /F1 10 Tf 20 780 Td "
    content += b"".join(b"(" + line + b") Tj T* " for _ in range(chars_per_page // 50)) + b"ET"
    to_unicode = b" /ToUnicode %d 0 R" % (4 + 2 * pages) if ligature else b""
    return _pdf_with_pages(
        [content] * pages,
        b"<< /Font << /F1 %d 0 R >> >>" % (3 + 2 * pages),
        [
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica" + to_unicode + b" >>",
            _stream(cmap),
        ],
    )


@pytest.mark.parametrize(("pages", "per_page"), [(1, 40_000), (30, 3300)])
def test_pdf_ligature_font_text_under_the_limit_is_not_cut(pages: int, per_page: int) -> None:
    """A font that may turn a byte into "ffi" was charged 3 characters per byte even when
    it made 1: a 40 000-character page came back as 34 699, marked truncated."""
    plain = extract(_ligature_pdf(pages, per_page, ligature=False), "pdf", char_limit=100_000)
    result = extract(_ligature_pdf(pages, per_page), "pdf", char_limit=100_000)
    assert result == plain
    assert result.truncated is False
    assert len(result.text) == len(plain.text) > (pages * per_page) * 0.98


def test_pdf_ligature_font_text_over_the_limit_is_still_cut() -> None:
    result = extract(_ligature_pdf(1, 120_000), "pdf", char_limit=100_000)
    assert result.truncated
    assert len(result.text) == 100_001


def test_pdf_deadline_is_checked_while_a_page_is_parsed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each page took about a second to parse, all of it past the deadline."""
    content = b"BT /F1 12 Tf 10 10 Td (x) Tj ET " + b"0 " * 900_000  # numbers, no operator
    data = _pdf_with_pages([content] * 3, b"<< /Font << /F1 3 0 R >> >>", [_FONT])
    monkeypatch.setattr(extract_module, "_PDF_SECONDS", 0.2)
    with _Timer() as timer, pytest.raises(ExtractError, match="too complex"):
        extract(data, "pdf", char_limit=100_000)
    assert timer.seconds < 0.45


def test_pdf_parse_clock_counts_like_pypdf_outside_extraction() -> None:
    from pypdf.generic import _data_structures

    extract(minimal_pdf("swap in the clocked budget"), "pdf", char_limit=100)
    budget = _data_structures.StreamParsingBudget(remaining_budget=10)
    budget.remaining_budget -= 3
    assert budget.remaining_budget == 7


# ---- the isolated child process ----


def test_isolated_extraction_matches_in_process_from_any_working_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    workbook = minimal_xlsx([["a", 1]], more=[("Two", [["b"]])])
    cases = [
        ("pdf", minimal_pdf("Page one", "Page two")),
        ("docx", minimal_docx("Hello", "World", header="Head")),
        ("xlsx", workbook),
        ("rtf", minimal_rtf("caf\\'e9")),
        ("pdf", _expanding_font_pdf(10_000)),  # truncated=True crosses the pipe
    ]
    for kind, data in cases:
        assert extract_isolated(data, kind, char_limit=500) == extract(data, kind, char_limit=500)
    assert xlsx_tabs_isolated(workbook, char_limit=500) == (xlsx_tabs(workbook, 500), False)


def test_isolated_extraction_reports_the_extractors_refusal() -> None:
    with pytest.raises(ExtractError, match="not a valid Office package"):
        extract_isolated(b"PK\x03\x04 broken", "docx", char_limit=500)


def test_isolated_extraction_stops_at_the_memory_limit() -> None:
    """The element's 600 000 attributes are parsed before any budget sees them; in a
    child limited to 128 MB that fails, and the parent reports it."""
    attributes = " ".join(f'a{i}=""' for i in range(600_000))
    with pytest.raises(ExtractError, match="too large or complex"):
        extract_isolated(_word(f"<w:p {attributes}/>"), "docx", char_limit=1000, memory_mb=128)
    # The same limit leaves room for a normal file.
    assert extract_isolated(minimal_pdf("fine"), "pdf", char_limit=100, memory_mb=128).text


def test_isolated_extraction_is_killed_at_the_timeout() -> None:
    data = _word("<w:x/>" * 3_000_000)
    with _Timer() as timer, pytest.raises(ExtractError, match="took too long"):
        extract_isolated(data, "docx", char_limit=1000, timeout=0.3)
    assert timer.seconds < 2


def _fake_child(monkeypatch: pytest.MonkeyPatch, code: str) -> None:
    monkeypatch.setattr(
        extract_worker, "_child_command", lambda memory_mb: [sys.executable, "-I", "-c", code]
    )


def _replying_child(text: str = "ok", delay: float = 0.0) -> str:
    reply = json.dumps({"text": text, "truncated": False})
    return f"import sys, time; sys.stdin.read(); time.sleep({delay}); print({reply!r})"


_READ = "import sys; sys.stdin.read(); "


@pytest.mark.parametrize(
    ("code", "message"),
    [
        # A garbled reply: nothing from it reaches the caller.
        (_READ + "print('not json')", extract_worker._FAILED),
        (_READ + "print('[1, 2]')", extract_worker._FAILED),
        (_READ + 'print(\'{"text": 5, "truncated": false}\')', extract_worker._FAILED),
        (_READ + 'print(\'{"error": "' + "x" * 400 + "\"}')", extract_worker._FAILED),
        # Out of memory or killed (the CPU limit): the file's doing.
        (_READ + "raise MemoryError", extract_worker._TOO_BIG),
        ("import os; os.kill(os.getpid(), 9)", extract_worker._TOO_BIG),
        # No reply at all: the server's setup is broken, and that is logged as an error.
        # Every such failure used to read as "too large or complex", so a broken
        # deployment looked like a run of hard files.
        ("import scoped_drive_mcp_missing_module", extract_worker._BROKEN),
        ("import sys; sys.stdin.read()", extract_worker._BROKEN),
        ("import sys; sys.exit(3)", extract_worker._BROKEN),
    ],
)
def test_a_bad_child_is_an_extract_error_that_says_why(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, code: str, message: str
) -> None:
    _fake_child(monkeypatch, code)
    with caplog.at_level("ERROR"), pytest.raises(ExtractError) as raised:
        extract_isolated(minimal_pdf("x"), "pdf", char_limit=100)
    assert str(raised.value) == message
    logged = any(record.levelname == "ERROR" for record in caplog.records)
    assert logged is (message == extract_worker._BROKEN)


def test_isolated_tabs_reply_is_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_child(monkeypatch, _READ + 'print(\'{"tabs": [[1, "x"]], "truncated": false}\')')
    with pytest.raises(ExtractError, match="could not be extracted"):
        xlsx_tabs_isolated(b"x", char_limit=100)


def test_isolated_extraction_reads_back_only_a_bounded_reply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_child(
        monkeypatch,
        "import sys\nsys.stdin.buffer.read()\nwhile True: sys.stdout.write('x' * 65536)",
    )
    with _Timer() as timer, pytest.raises(ExtractError, match="could not be extracted"):
        extract_isolated(minimal_pdf("x"), "pdf", char_limit=100)
    assert timer.seconds < 5


def test_isolated_extraction_without_a_process_is_an_extract_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(extract_worker, "_child_command", lambda memory_mb: ["/nonexistent/python"])
    with pytest.raises(ExtractError, match="could not be extracted"):
        extract_isolated(minimal_pdf("x"), "pdf", char_limit=100)


def test_isolated_reply_with_a_surrogate_is_cleaned(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_child(monkeypatch, _replying_child("x\ud800y"))
    assert extract_isolated(b"x", "pdf", char_limit=10).text == "x�y"


def test_isolated_child_gets_no_secrets_and_sets_its_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENCRYPTION_KEY", "not-for-the-child")
    assert "ENCRYPTION_KEY" not in extract_worker._child_env()
    command = extract_worker._child_command(300)
    assert command[:3] == [sys.executable, "-I", "-B"]
    package_parent = str(Path(extract_worker.__file__).resolve().parent.parent)
    assert json.loads(command[command.index("-c") + 2])[0] == package_parent
    probe = (
        "import json, resource, sys; sys.argv[1:] = ['[]', '300', '7'];"
        f"sys.path.insert(0, {package_parent!r});"
        "from scoped_drive_mcp.extract_worker import _set_limits;"
        "_set_limits(300 * 1024 * 1024, 7);"
        "print(json.dumps([resource.getrlimit(resource.RLIMIT_AS),"
        " resource.getrlimit(resource.RLIMIT_CPU)]))"
    )
    out = subprocess.run(  # noqa: S603 (this interpreter, fixed arguments)
        [sys.executable, "-I", "-c", probe], capture_output=True, check=True, env={}
    ).stdout
    memory, cpu = json.loads(out)
    assert memory == [300 * 1024 * 1024, 300 * 1024 * 1024]
    assert cpu == [7, 8]


def test_relative_import_paths_reach_the_child_made_absolute(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "path", [*sys.path, "vendored", ""])
    paths = extract_worker._import_paths()
    assert str(tmp_path / "vendored") in paths
    assert "" not in paths and "vendored" not in paths
    assert all(Path(entry).is_absolute() for entry in paths)


def test_children_read_bytecode_compiled_once_and_write_none(tmp_path: Path) -> None:
    """The host ships no .pyc files and the child writes none, so every file paid to
    compile pypdf and openpyxl from source."""
    folder = tmp_path / "pycache"
    folder.mkdir()
    extract_worker._compile_into(str(folder))
    compiled = {path.name.split(".")[0] for path in folder.rglob("*.pyc")}
    assert {"_page", "excel", "extract"} <= compiled
    before = sorted(folder.rglob("*"))
    extract_worker._warm_bytecode()  # makes the process's own folder
    command = extract_worker._child_command(300)
    assert command[3:5] == ["-X", f"pycache_prefix={extract_worker._bytecode_dir}"]
    assert extract_worker._bytecode_dir is not None
    assert Path(extract_worker._bytecode_dir).stat().st_mode & 0o077 == 0
    assert extract_isolated(minimal_pdf("still reads"), "pdf", char_limit=100).text
    assert sorted(folder.rglob("*")) == before


# ---- sharing the child processes between callers ----


def test_one_caller_runs_one_child_and_others_are_not_held_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Four slow files from one caller held both slots, and a harmless file from anyone
    else waited 22 s (or failed at 25 s)."""
    monkeypatch.setattr(extract_worker, "WAIT_SECONDS", 0.3)
    _fake_child(monkeypatch, _replying_child(delay=0.8))
    outcomes: list[str] = []

    def slow_read() -> None:
        try:
            outcomes.append(extract_isolated(b"x", "pdf", char_limit=10, caller="user:a").text)
        except ExtractError as exc:
            outcomes.append(str(exc))

    threads = [threading.Thread(target=slow_read) for _ in range(3)]
    for thread in threads:
        thread.start()
    time.sleep(0.1)
    _fake_child(monkeypatch, _replying_child("harmless"))
    with _Timer() as timer:
        assert extract_isolated(b"x", "pdf", char_limit=10, caller="user:b").text == "harmless"
    assert timer.seconds < 1.0
    for thread in threads:
        thread.join()
    assert sorted(outcomes) == sorted(["ok"] + [extract_worker._OWN_BUSY] * 2)


def test_a_full_server_says_busy_quickly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(extract_worker, "WAIT_SECONDS", 0.3)
    _fake_child(monkeypatch, _replying_child(delay=0.8))
    threads = [
        threading.Thread(
            target=extract_isolated, args=(b"x", "pdf"), kwargs={"char_limit": 10, "caller": who}
        )
        for who in ("user:a", "user:b")
    ]
    for thread in threads:
        thread.start()
    time.sleep(0.1)
    with _Timer() as timer, pytest.raises(extract_worker.ExtractBusy, match="busy"):
        extract_isolated(b"x", "pdf", char_limit=10, caller="user:c")
    assert timer.seconds < 0.6
    for thread in threads:
        thread.join()


def test_a_child_started_late_still_gets_its_whole_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The wait for a slot came out of the child's time: a slot freed just before the
    wait ran out left the next file almost none, and it was reported as too slow."""
    monkeypatch.setattr(extract_worker, "MAX_CHILDREN", 1)
    monkeypatch.setattr(extract_worker, "WAIT_SECONDS", 1.0)
    _fake_child(monkeypatch, _replying_child(delay=0.8))
    first = threading.Thread(
        target=extract_isolated, args=(b"x", "pdf"), kwargs={"char_limit": 10, "caller": "user:a"}
    )
    first.start()
    time.sleep(0.05)
    result = extract_isolated(b"x", "pdf", char_limit=10, caller="user:b", timeout=1.2)
    assert result.text == "ok"
    first.join()


def test_the_caller_is_the_person_or_token_of_the_call() -> None:
    from scoped_drive_mcp.auth import Principal, current_actor, current_principal
    from scoped_drive_mcp.config import Role
    from scoped_drive_mcp.extract_worker import current_caller

    assert current_caller() is None
    for variable, value, expected in [
        (current_principal, Principal("bot", next(iter(Role))), "token:bot"),
        (
            current_principal,
            Principal("grant", next(iter(Role)), email="a@example.com"),
            "user:a@example.com",
        ),
        (current_actor, "b@example.com", "user:b@example.com"),
    ]:
        token = variable.set(value)
        try:
            assert current_caller() == expected
        finally:
            variable.reset(token)

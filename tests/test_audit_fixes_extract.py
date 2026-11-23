"""Small crafted files must not cost huge work to extract.

Each case is a file of a few kilobytes that, before the shared work budget, made
read_file spend seconds to minutes (or hundreds of megabytes): a part listed many
times, a million empty rows, a regex that backtracks, a form drawn again and again.
"""

import io
import json
import struct
import subprocess
import sys
import time
import tracemalloc
import zipfile
import zlib
from pathlib import Path

import pytest

from scoped_drive_mcp.extract import Extracted, ExtractError, extract, extract_text, xlsx_tabs
from scoped_drive_mcp.extract_worker import extract_isolated, xlsx_tabs_isolated
from tests.office_files import (
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


def _zip(files: dict[str, str | bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, body in files.items():
            archive.writestr(name, body)
    return buf.getvalue()


class _Timer:
    def __enter__(self) -> "_Timer":
        self.start = time.monotonic()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.seconds = time.monotonic() - self.start


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
    xml = f'<w:document xmlns:w="{W}"><w:body>' + "<w:p/>" * 5_000_000 + "</w:body></w:document>"
    data = _zip({"word/document.xml": xml})
    assert len(data) < 100_000
    with _Timer() as timer:
        text = extract_text(data, "docx", char_limit=1000)
    assert len(text) <= 1001
    assert timer.seconds < 2


def test_flat_elements_without_paragraphs_are_refused_quickly() -> None:
    xml = f'<w:document xmlns:w="{W}"><w:body>' + "<w:x/>" * 3_000_000 + "</w:body></w:document>"
    with _Timer() as timer, pytest.raises(ExtractError, match="too complex"):
        extract_text(_zip({"word/document.xml": xml}), "docx", char_limit=1000)
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


def test_a_text_box_paragraph_is_its_own_line_not_repeated() -> None:
    body = (
        "<w:p><w:r><w:t>before </w:t></w:r>"
        "<w:r><w:txbxContent><w:p><w:r><w:t>in the box</w:t></w:r></w:p></w:txbxContent></w:r>"
        "<w:r><w:t>after</w:t></w:r></w:p>"
        "<w:p><w:r><w:t>next</w:t><w:tab/><w:t>tabbed</w:t><w:br/><w:t>broken</w:t></w:r></w:p>"
    )
    xml = f'<w:document xmlns:w="{W}"><w:body>{body}</w:body></w:document>'
    text = extract_text(_zip({"word/document.xml": xml}), "docx", char_limit=1000)
    assert text == "before after\nin the box\nnext\ttabbed\nbroken"


def test_normal_word_file_still_reads_body_table_and_header() -> None:
    text = extract_text(minimal_docx("one", "two", header="Head"), "docx", char_limit=1000)
    assert text == "one\ntwo\ncell text\nHead"


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


def test_normal_workbook_still_reads_every_tab() -> None:
    data = minimal_xlsx([["Name", "Role"], ["Ada", "Labs"]], more=[("Costs", [["GPU", 3]])])
    assert xlsx_tabs(data, 1000) == [
        ("Resume", "# Resume\nName\tRole\nAda\tLabs"),
        ("Costs", "# Costs\nGPU\t3"),
    ]


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


def test_rtf_keeps_fonts_unicode_and_escapes() -> None:
    data = (
        b"{\\rtf1\\ansi\\ansicpg1252\\deff0{\\fonttbl{\\f0\\fswiss\\fcharset0 Arial;}"
        b"{\\f1\\fnil\\fcharset204 Times;}}{\\colortbl;\\red0\\green0\\blue0;}"
        b"\\f0 Hello \\b bold\\b0  world\\par Second\\tab tabbed\\par "
        b"{\\f1 \\'cf\\'f0\\'e8} caf\\'e9 \\u8364?euro{\\*\\unknown hidden}\\line end}"
    )
    text = extract_text(data, "rtf", char_limit=1000)
    assert text == "Hello bold world\nSecond\ttabbed\nПри café €euro\nend"
    assert "plain words" in extract_text(minimal_rtf("plain words"), "rtf", char_limit=1000)


# ---- legacy .doc ----


def _clx(pieces: int, count: int, fc: int) -> bytes:
    cps = struct.pack(f"<{pieces + 1}I", *(i * count for i in range(pieces + 1)))
    pcds = b"".join(struct.pack("<HIH", 0, fc, 0) for _ in range(pieces))
    plc = cps + pcds
    return b"\x02" + struct.pack("<I", len(plc)) + plc


def test_doc_pieces_of_control_characters_are_capped() -> None:
    """Every piece covers the whole stream of dropped control codes: no output ever
    reaches the limit, so only the decoded-text cap stops the loop."""
    from scoped_drive_mcp.extract import _doc_text

    body = b"\x01" * 1_000_000
    word = bytearray(0x200) + body
    clx = _clx(2500, len(body), (0x200 * 2) | 0x40000000)
    struct.pack_into("<II", word, 0x1A2, 0, len(clx))
    with _Timer() as timer, pytest.raises(ExtractError, match="too complex"):
        _doc_text(bytes(word), clx, char_limit=10_000)
    assert timer.seconds < 2


def test_doc_long_piece_stops_at_the_character_limit() -> None:
    from scoped_drive_mcp.extract import _doc_text

    body = b"word\r" * 1_000_000
    word = bytearray(0x200) + body
    clx = _clx(1, len(body), (0x200 * 2) | 0x40000000)
    struct.pack_into("<II", word, 0x1A2, 0, len(clx))
    text = _doc_text(bytes(word), clx, char_limit=10_000)
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
    data = _pdf(
        [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 400 200] /Contents 4 0 R "
            b"/Resources << /Font << /F1 5 0 R >> /XObject << /X 6 0 R >> >> >>",
            _stream(b"/X Do\n" * 2000),
            _FONT,
            _stream(
                _LINES * 50_000,
                b"/Type /XObject /Subtype /Form /BBox [0 0 1 1] "
                b"/Resources << /Font << /F1 5 0 R >> >> ",
            ),
        ]
    )
    assert len(data) < 5000
    with _Timer() as timer, pytest.raises(ExtractError, match="too complex"):
        extract_text(data, "pdf", char_limit=100_000)
    assert timer.seconds < 3


def test_pdf_with_a_small_form_still_reads_its_text() -> None:
    data = _pdf(
        [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 400 200] /Contents 4 0 R "
            b"/Resources << /Font << /F1 5 0 R >> /XObject << /X 6 0 R >> >> >>",
            _stream(b"BT /F1 12 Tf 10 100 Td (page text) Tj ET\n/X Do\n"),
            _FONT,
            _stream(
                b"BT /F1 12 Tf 10 50 Td (form text) Tj ET\n",
                b"/Type /XObject /Subtype /Form /BBox [0 0 400 200] "
                b"/Resources << /Font << /F1 5 0 R >> >> ",
            ),
        ]
    )
    text = extract_text(data, "pdf", char_limit=1000)
    assert "page text" in text and "form text" in text


# ---- second review: work pypdf and openpyxl do that the budget did not see ----


def _peak_bytes(run) -> tuple[object, int]:
    """run() and the most memory Python allocated while it ran."""
    tracemalloc.start()
    try:
        result = run()
        return result, tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


_MB = 1024 * 1024


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
    from scoped_drive_mcp import extract as extract_module

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
    data = _pdf_with_pages([b""] * 600 + [_text("after the blanks")], b"<< >>", [])
    data = _pdf_with_pages(
        [b""] * 600 + [_text("after the blanks")],
        b"<< /Font << /F1 %d 0 R >> >>" % (3 + 2 * 601),
        [_FONT],
    )
    assert extract(data, "pdf", char_limit=500) == Extracted("after the blanks")


def test_word_newlines_are_counted_only_between_blocks() -> None:
    """The first paragraph of each part counted a newline too, so the budget filled up
    early: the header was dropped and the text not marked truncated."""
    limit = 50
    body = "x" * (limit - 1)
    result = extract(minimal_docx(body, header="Head"), "docx", char_limit=limit)
    # minimal_docx adds a table cell after the paragraphs.
    assert result.text == (body + "\ncell text\nHead")[: limit + 1]
    assert result.truncated
    exact = extract(minimal_docx("a" * 20, "b" * 19), "docx", char_limit=60)
    assert exact == Extracted("a" * 20 + "\n" + "b" * 19 + "\ncell text")


def test_word_text_is_marked_truncated_whenever_it_was_cut() -> None:
    for limit in range(1, 40):
        full = "one\ntwo\ncell text\nHead"
        result = extract(minimal_docx("one", "two", header="Head"), "docx", char_limit=limit)
        assert result.text == full[: limit + 1]
        assert result.truncated == (len(full) > limit), limit


# ---- Excel, second review ----


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


def test_xlsx_dates_still_read_with_named_styles_removed() -> None:
    import datetime

    data = minimal_xlsx([["when", datetime.datetime(2024, 5, 6, 7, 8)]])
    assert xlsx_tabs(data, 1000) == [("Resume", "when\t2024-05-06 07:08:00")]


def test_xlsx_large_shared_string_table_has_its_own_allowance() -> None:
    """260 000 unique strings (520 000 tags) went over the workbook's tag allowance, so
    a normal 1.5 MB workbook was refused; the old code read its first 100 000 chars."""
    count = 260_000
    strings = (
        f'<sst xmlns="{SHEET}">' + "".join(f"<si><t>s{i}</t></si>" for i in range(count)) + "</sst>"
    )
    rows = "".join(
        f'<row r="{r + 1}">'
        + "".join(f'<c t="s"><v>{(r * 8 + c) % count}</v></c>' for c in range(8))
        + "</row>"
        for r in range(20_000)
    )
    data = _xlsx(rows, strings=strings)
    result = extract(data, "xlsx", char_limit=100_000)
    expected = "\n".join(
        "\t".join(f"s{(r * 8 + c) % count}" for c in range(8)) for r in range(20_000)
    )
    assert result == Extracted(expected[:100_001], truncated=True)


# ---- RTF and Word, second review ----


def test_rtf_hyperlink_keeps_its_target_as_striprtf_did() -> None:
    data = (
        b'{\\rtf1 See {\\field{\\*\\fldinst{HYPERLINK "http://example.com"}}'
        b"{\\fldrslt{\\ul Example link}}} now.\\par}"
    )
    assert (
        extract_text(data, "rtf", char_limit=1000)
        == 'See Example link("http://example.com") now.\n'
    )


def test_rtf_field_without_a_hyperlink_adds_nothing() -> None:
    data = b"{\\rtf1 Page {\\field{\\*\\fldinst{ PAGE }}{\\fldrslt 3}}.\\par}"
    assert extract_text(data, "rtf", char_limit=1000) == "Page 3.\n"


def test_word_attributes_count_as_work() -> None:
    """One element with 600 000 attributes took hundreds of MB and counted as one node."""
    attributes = " ".join(f'a{i}=""' for i in range(600_000))
    xml = f'<w:document xmlns:w="{W}"><w:body><w:p {attributes}/></w:body></w:document>'
    with pytest.raises(ExtractError, match="too complex"):
        extract_text(_zip({"word/document.xml": xml}), "docx", char_limit=1000)


def test_word_work_allowance_grows_with_the_character_limit() -> None:
    """180 000 short paragraphs are 540 000 elements: over the fixed allowance, so a
    larger MAX_CHARS used to get a refusal instead of the text."""
    body = "<w:p><w:r><w:t>abc</w:t></w:r></w:p>" * 180_000
    xml = f'<w:document xmlns:w="{W}"><w:body>{body}</w:body></w:document>'
    text = extract_text(_zip({"word/document.xml": xml}), "docx", char_limit=2_000_000)
    assert text == "\n".join(["abc"] * 180_000)


def test_word_text_before_the_work_allowance_ran_out_is_returned() -> None:
    body = "<w:p><w:r><w:t>hello</w:t></w:r></w:p>" * 100 + "<w:x/>" * 600_000
    xml = f'<w:document xmlns:w="{W}"><w:body>{body}</w:body></w:document>'
    result = extract(_zip({"word/document.xml": xml}), "docx", char_limit=1000)
    assert result == Extracted("\n".join(["hello"] * 100), truncated=True)


# ---- the isolated child process ----


def test_isolated_extraction_matches_in_process() -> None:
    cases = [
        ("pdf", minimal_pdf("Page one", "Page two")),
        ("docx", minimal_docx("Hello", "World", header="Head")),
        ("xlsx", minimal_xlsx([["a", 1]], more=[("Two", [["b"]])])),
        ("rtf", minimal_rtf("caf\\'e9")),
        ("pdf", _expanding_font_pdf(10_000)),
    ]
    for kind, data in cases:
        assert extract_isolated(data, kind, char_limit=500) == extract(data, kind, char_limit=500)
    workbook = minimal_xlsx([["a", 1]], more=[("Two", [["b"]])])
    assert xlsx_tabs_isolated(workbook, char_limit=500) == (xlsx_tabs(workbook, 500), False)


def test_isolated_extraction_reports_the_extractors_refusal() -> None:
    with pytest.raises(ExtractError, match="not a valid Office package"):
        extract_isolated(b"PK\x03\x04 broken", "docx", char_limit=500)


def test_isolated_extraction_stops_at_the_memory_limit() -> None:
    """The element's 600 000 attributes are parsed before any budget sees them; in a
    child limited to 128 MB that fails, and the parent reports it."""
    attributes = " ".join(f'a{i}=""' for i in range(600_000))
    xml = f'<w:document xmlns:w="{W}"><w:body><w:p {attributes}/></w:body></w:document>'
    data = _zip({"word/document.xml": xml})
    with pytest.raises(ExtractError, match="too large or complex"):
        extract_isolated(data, "docx", char_limit=1000, memory_mb=128)
    # The same limit leaves room for a normal file.
    assert extract_isolated(minimal_pdf("fine"), "pdf", char_limit=100, memory_mb=128).text


def test_isolated_extraction_is_killed_at_the_timeout() -> None:
    xml = f'<w:document xmlns:w="{W}"><w:body>' + "<w:x/>" * 3_000_000 + "</w:body></w:document>"
    data = _zip({"word/document.xml": xml})
    with _Timer() as timer, pytest.raises(ExtractError, match="took too long"):
        extract_isolated(data, "docx", char_limit=1000, timeout=0.3)
    assert timer.seconds < 2


def _fake_child(monkeypatch: pytest.MonkeyPatch, code: str) -> None:
    from scoped_drive_mcp import extract_worker

    monkeypatch.setattr(
        extract_worker, "_child_command", lambda memory_mb: [sys.executable, "-I", "-c", code]
    )


@pytest.mark.parametrize(
    "code",
    [
        "import sys; sys.stdin.read(); print('not json')",
        "import sys; sys.stdin.read(); print('[1, 2]')",
        'import sys; sys.stdin.read(); print(\'{"text": 5, "truncated": false}\')',
        'import sys; sys.stdin.read(); print(\'{"error": "' + "x" * 400 + "\"}')",
        "import sys; sys.exit(3)",
        "import os; os.kill(os.getpid(), 9)",
    ],
)
def test_isolated_extraction_turns_a_bad_child_into_an_extract_error(
    monkeypatch: pytest.MonkeyPatch, code: str
) -> None:
    _fake_child(monkeypatch, code)
    with pytest.raises(ExtractError):
        extract_isolated(minimal_pdf("x"), "pdf", char_limit=100)


def test_isolated_extraction_reads_back_only_a_bounded_reply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_child(
        monkeypatch,
        "import sys\nsys.stdin.buffer.read()\nwhile True: sys.stdout.write('x' * 65536)",
    )
    with _Timer() as timer, pytest.raises(ExtractError):
        extract_isolated(minimal_pdf("x"), "pdf", char_limit=100)
    assert timer.seconds < 5


def test_isolated_extraction_without_a_process_is_an_extract_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scoped_drive_mcp import extract_worker

    monkeypatch.setattr(extract_worker, "_child_command", lambda memory_mb: ["/nonexistent/python"])
    with pytest.raises(ExtractError):
        extract_isolated(minimal_pdf("x"), "pdf", char_limit=100)


def test_isolated_child_gets_no_secrets_and_sets_its_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scoped_drive_mcp import extract_worker

    monkeypatch.setenv("ENCRYPTION_KEY", "not-for-the-child")
    assert "ENCRYPTION_KEY" not in extract_worker._child_env()
    command = extract_worker._child_command(300)
    assert command[:3] == [sys.executable, "-I", "-B"]
    package_parent = str(Path(extract_worker.__file__).resolve().parent.parent)
    assert json.loads(command[5])[0] == package_parent
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


def test_isolated_extraction_works_from_any_working_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    assert extract_isolated(minimal_docx("here"), "docx", char_limit=100).text.startswith("here")


def test_service_reads_in_process_when_isolation_is_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scoped_drive_mcp import service as service_module
    from tests.conftest import make_settings

    def no_child(*args: object, **kwargs: object) -> None:
        raise AssertionError("isolation is off")

    monkeypatch.setattr(service_module, "extract_isolated", no_child)
    off = service_module.DriveService(None, None, make_settings(extract_isolation=False))  # type: ignore[arg-type]
    assert off._extract(minimal_pdf("in process"), "pdf").text == "in process"
    on = service_module.DriveService(None, None, make_settings())  # type: ignore[arg-type]
    with pytest.raises(AssertionError, match="isolation is off"):
        on._extract(minimal_pdf("x"), "pdf")


def test_read_file_marks_text_cut_short_by_the_work_allowance(drive, service) -> None:
    from tests.conftest import ROOT

    drive.add("busy-pdf", "busy.pdf", "application/pdf", [ROOT], minimal_pdf("start"))
    service._extract = lambda data, kind: Extracted("start", truncated=True)
    result = service.read_file("busy-pdf")
    assert result["content"] == "start"
    assert result["truncated"] is True
    assert "too large or complex" in result["note"]


def test_read_file_reads_a_pdf_in_the_child_process(drive, service) -> None:
    from tests.conftest import ROOT

    assert service.extract_isolation  # the default
    drive.add("plain-pdf", "plain.pdf", "application/pdf", [ROOT], minimal_pdf("from the child"))
    result = service.read_file("plain-pdf")
    assert result["content"] == "from the child"
    assert result["truncated"] is False

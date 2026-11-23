"""Small crafted files must not cost huge work to extract.

Each case is a file of a few kilobytes that, before the shared work budget, made
read_file spend seconds to minutes (or hundreds of megabytes): a part listed many
times, a million empty rows, a regex that backtracks, a form drawn again and again.
"""

import io
import struct
import time
import zipfile
import zlib

import pytest

from scoped_drive_mcp.extract import ExtractError, extract_text, xlsx_tabs
from tests.office_files import minimal_docx, minimal_pptx, minimal_rtf, minimal_xlsx

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


def _xlsx(sheet_body: str, sheets: int = 1) -> bytes:
    sheet_list = "".join(
        f'<sheet name="s{i}" sheetId="{i + 1}" r:id="rId1"/>' for i in range(sheets)
    )
    return _zip(
        {
            "[Content_Types].xml": (
                '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.'
                'relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'
                '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.'
                'openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/></Types>'
            ),
            "_rels/.rels": (
                f'<Relationships xmlns="{PKG}"><Relationship Id="rId1" '
                f'Type="{REL}/officeDocument" Target="xl/workbook.xml"/></Relationships>'
            ),
            "xl/workbook.xml": (
                f'<workbook xmlns="{SHEET}" xmlns:r="{REL}">'
                f"<sheets>{sheet_list}</sheets></workbook>"
            ),
            "xl/_rels/workbook.xml.rels": (
                f'<Relationships xmlns="{PKG}"><Relationship Id="rId1" Type="{REL}/worksheet" '
                'Target="worksheets/sheet1.xml"/></Relationships>'
            ),
            "xl/worksheets/sheet1.xml": (
                f'<worksheet xmlns="{SHEET}"><sheetData>{sheet_body}</sheetData></worksheet>'
            ),
        }
    )


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

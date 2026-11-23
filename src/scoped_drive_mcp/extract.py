"""Turn downloaded Office and PDF bytes into plain text.

Extraction stays in-process (no temporary Drive copies, no native binaries such as
poppler). Dependencies are pure Python so the Vercel function stays small. Legacy
.doc files are read from the OLE compound document; the piece table is the Word 97
layout, which later .doc files still start with.

Every extractor works under one `_Budget` for the whole file. The byte caps bound how
big a file is, not how much work it asks for: a part can be listed many times, an
element can be nested or repeated, and a few kilobytes can compress a million empty
rows. So each file also gets a fixed allowance of parts, XML elements, spreadsheet
rows and cells, PDF operators and output characters, shared by all its parts, and
extraction stops as soon as it has the characters the caller asked for.
"""

import codecs
import io
import re
import struct
import time
import zipfile
import zlib
from collections.abc import Iterator
from typing import Any
from xml.etree.ElementTree import ParseError as XmlParseError

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import iterparse as xml_iterparse

# Returned text stops a little past the caller's limit so the service can mark it truncated.
_ZIP_ENTRY_CAP = 2000
_UNCOMPRESSED_CAP = 32 * 1024 * 1024
_PIECE_CAP = 10_000
# Work limits for one file, shared by all of its parts (see the module docstring).
# Parts read from one package: slides, sheets, headers and footers.
_PART_CAP = 1000
# XML elements parsed across every part. The defused parser costs about 2 us each.
_NODE_VISIT_CAP = 500_000
# RTF tokens (control words, text runs), about 0.3 us each.
_RTF_TOKEN_CAP = 1_000_000
# How deep XML elements may nest. Real documents (tables in tables) stay far below it.
_XML_DEPTH_CAP = 256
# Spreadsheet cells plus rows. Empty rows count: a few bytes of `<row/>` are still work.
_CELL_CAP = 2_000_000
# Element tags openpyxl reads from a workbook. It costs a few microseconds per element.
_XLSX_MARKUP_CAP = 500_000
# Text a legacy .doc may decode, including control characters that are thrown away.
_TEXT_CAP = 4_000_000
# PDF content-stream work across all pages and the forms they draw, in operators (a
# form is charged by size each time it is drawn, before pypdf parses it again).
_PDF_OPERATION_CAP = 250_000
# Content-stream bytes per operator, roughly, for charging a form before it is parsed.
_PDF_BYTES_PER_OPERATION = 8
# Form XObjects looked at per page when sizing them.
_PDF_FORM_SCAN_CAP = 256
_PDF_PAGE_CAP = 5000
_PDF_FORM_CAP = 200
# Backstop for PDF work the operator count cannot see, such as font and image decoding.
_PDF_SECONDS = 10.0

_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
_P = "{http://schemas.openxmlformats.org/presentationml/2006/main}"
_R = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
_PKG = "{http://schemas.openxmlformats.org/package/2006/relationships}"

MIME_KIND: dict[str, str] = {
    "application/pdf": "pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "application/vnd.ms-word.document.macroenabled.12": "docx",
    "application/msword": "doc",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx",
    "application/vnd.ms-powerpoint.presentation.macroenabled.12": "pptx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
    "application/vnd.ms-excel.sheet.macroenabled.12": "xlsx",
    "application/rtf": "rtf",
    "text/rtf": "rtf",
    "application/x-rtf": "rtf",
}

EXT_KIND: dict[str, str] = {
    ".pdf": "pdf",
    ".docx": "docx",
    ".docm": "docx",
    ".doc": "doc",
    ".pptx": "pptx",
    ".pptm": "pptx",
    ".xlsx": "xlsx",
    ".xlsm": "xlsx",
    ".rtf": "rtf",
}

# Mimes Drive uses when it does not know the real type. The file name is the fallback.
GENERIC_MIMES = frozenset(
    {
        "",
        "application/octet-stream",
        "application/zip",
        "application/x-zip-compressed",
        "binary/octet-stream",
    }
)

_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_ZIP_MAGIC = b"PK\x03\x04"


class ExtractError(Exception):
    """Text could not be extracted. The message is safe to show to the caller."""


class _Budget:
    """The work one file may cost, shared by all of its parts.

    `full` turns true once the output has the characters the caller asked for; the
    extractors check it and stop early. Going over any other allowance raises.
    """

    def __init__(self, char_limit: int) -> None:
        self.char_goal = char_limit + 1
        self.chars = 0
        self.parts = 0
        self.nodes = 0
        self.cells = 0
        self.markup = 0
        self.operations = 0

    @property
    def full(self) -> bool:
        return self.chars >= self.char_goal

    def add_chars(self, count: int) -> None:
        self.chars += count

    def part(self) -> None:
        self.parts += 1
        if self.parts > _PART_CAP:
            raise ExtractError("file has too many parts to extract; use download_file")

    def node(self, count: int = 1, cap: int = _NODE_VISIT_CAP) -> None:
        self.nodes += count
        if self.nodes > cap:
            raise ExtractError("document is too complex to extract; use download_file")

    def cell(self, count: int) -> None:
        self.cells += count
        if self.cells > _CELL_CAP:
            raise ExtractError("spreadsheet is too large to extract; use download_file")

    def xml_bytes(self, data: bytes) -> None:
        """Count the element tags in raw XML a library is about to parse."""
        self.markup += data.count(b"<") - data.count(b"</")
        if self.markup > _XLSX_MARKUP_CAP:
            raise ExtractError("spreadsheet is too large to extract; use download_file")

    def operation(self, count: int = 1) -> None:
        self.operations += count
        if self.operations > _PDF_OPERATION_CAP:
            raise ExtractError("PDF is too complex to extract; use download_file")


def document_kind(mime_type: str, name: str) -> str | None:
    """Which extractor to use, or None when the file should be returned as bytes."""
    mime = mime_type.lower().split(";")[0].strip()
    if mime in MIME_KIND:
        return MIME_KIND[mime]
    if mime in GENERIC_MIMES:
        ext = _extension(name)
        return EXT_KIND.get(ext)
    return None


def extract_text(data: bytes, kind: str, *, char_limit: int) -> str:
    """Extract plain text. May run slightly past `char_limit`; the caller truncates."""
    if char_limit < 1:
        raise ExtractError("character limit is too small")
    kind = _sniff_kind(kind, data)
    if kind == "pdf":
        text = _pdf(data, char_limit)
    elif kind == "docx":
        text = _docx(data, char_limit)
    elif kind == "pptx":
        text = _pptx(data, char_limit)
    elif kind == "xlsx":
        text = _xlsx(data, char_limit)
    elif kind == "rtf":
        text = _rtf(data, char_limit)
    elif kind == "doc":
        text = _doc(data, char_limit)
    else:
        raise ExtractError(f"no text extractor for {kind}")
    return text.replace("\x00", "")[: char_limit + 1]


def _extension(name: str) -> str:
    dot = name.rfind(".")
    if dot < 0 or dot == len(name) - 1:
        return ""
    return name[dot:].lower()


def _sniff_kind(kind: str, data: bytes) -> str:
    """A .doc label on a zip (or the reverse) is a mislabeled Office file."""
    if kind == "doc" and data.startswith(_ZIP_MAGIC):
        return "docx"
    if kind == "docx" and data.startswith(_OLE_MAGIC):
        return "doc"
    if kind in {"pptx", "xlsx"} and data.startswith(_OLE_MAGIC):
        raise ExtractError("legacy Office binary is not a zip package; use download_file")
    return kind


def _clip(parts: list[str], limit: int) -> str:
    """Join sections with a newline so the next page, slide, or sheet does not run on."""
    out: list[str] = []
    size = 0
    for part in parts:
        if not part:
            continue
        if size >= limit:
            break
        if out:
            out.append("\n")
            size += 1
        out.append(part)
        size += len(part)
    return "".join(out)


# Reading a zip member can fail past the directory check: a bad CRC, a broken deflate
# stream, an encrypted entry or an unsupported compression method.
_ZIP_READ_ERRORS = (zipfile.BadZipFile, zlib.error, EOFError, RuntimeError, NotImplementedError)


def _open_zip(data: bytes) -> zipfile.ZipFile:
    if not data.startswith(_ZIP_MAGIC):
        raise ExtractError("file is not a zip package")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ExtractError("file is not a valid Office package") from exc
    infos = archive.infolist()
    if len(infos) > _ZIP_ENTRY_CAP:
        raise ExtractError("Office package has too many parts")
    total = 0
    for info in infos:
        total += max(info.file_size, 0)
        if total > _UNCOMPRESSED_CAP:
            raise ExtractError("Office package is too large to extract")
    return archive


def _local(tag: str, ns: str) -> str:
    return f"{ns}{tag}"


def _xml_events(archive: zipfile.ZipFile, name: str, budget: _Budget) -> Iterator[tuple[str, Any]]:
    """("start" | "end", element) for one package part, streamed, or nothing if it is missing.

    Every element counts against the file's budget, so a huge part stops being parsed
    once the budget is spent rather than after it is all in memory. An element is
    dropped from the tree after its end event, so read its text then, not later.
    """
    try:
        source = archive.open(name)
    except KeyError:
        return
    except _ZIP_READ_ERRORS as exc:
        raise ExtractError("file is not a valid Office package") from exc
    stack: list = []
    with source:
        try:
            for event, node in xml_iterparse(source, events=("start", "end")):
                if event == "start":
                    budget.node()
                    stack.append(node)
                    if len(stack) > _XML_DEPTH_CAP:
                        raise ExtractError("document is too complex to extract; use download_file")
                    yield event, node
                else:
                    yield event, node
                    stack.pop()
                    node.clear()
                    if stack:
                        # Earlier siblings are gone already, so this is the parent's only child.
                        stack[-1].remove(node)
        except (XmlParseError, DefusedXmlException) as exc:
            raise ExtractError("could not parse document XML") from exc
        except _ZIP_READ_ERRORS as exc:
            raise ExtractError("file is not a valid Office package") from exc


def _part_text(archive: zipfile.ZipFile, name: str, ns: str, budget: _Budget) -> str:
    """The paragraphs of one part, a line each, in document order.

    A paragraph nested inside another (a text box in a Word paragraph) gets its own
    line after its parent's; its text is not repeated in the parent's line.
    """
    paragraph_tag, text_tag = _local("p", ns), _local("t", ns)
    break_tag, tab_tag = _local("br", ns), _local("tab", ns)
    lines: list[list[str]] = []
    open_lines: list[list[str]] = []
    for event, node in _xml_events(archive, name, budget):
        tag = node.tag
        if event == "start":
            if tag == paragraph_tag:
                line: list[str] = []
                lines.append(line)
                open_lines.append(line)
                budget.add_chars(1)  # the newline before it
            elif open_lines and tag == tab_tag:
                open_lines[-1].append("\t")
                budget.add_chars(1)
            elif open_lines and tag == break_tag:
                open_lines[-1].append("\n")
                budget.add_chars(1)
        elif tag == paragraph_tag:
            if open_lines:
                open_lines.pop()
        elif tag == text_tag and open_lines:
            text = node.text
            if text:
                open_lines[-1].append(text)
                budget.add_chars(len(text))
        if budget.full:
            break
    return "\n".join("".join(line) for line in lines)


def _docx(data: bytes, char_limit: int) -> str:
    archive = _open_zip(data)
    budget = _Budget(char_limit)
    try:
        names = set(archive.namelist())
        if "word/document.xml" not in names:
            raise ExtractError("Word file has no document.xml")
        parts = ["word/document.xml", "word/footnotes.xml", "word/endnotes.xml"]
        parts += sorted(
            name for name in names if name.lower().startswith(("word/header", "word/footer"))
        )
        blocks: list[str] = []
        for name in parts:
            if budget.full:
                break
            if name not in names:
                continue
            budget.part()
            text = _part_text(archive, name, _W, budget)
            if text:
                blocks.append(text)
        return _clip(blocks, char_limit + 1)
    finally:
        archive.close()


def _pptx(data: bytes, char_limit: int) -> str:
    archive = _open_zip(data)
    budget = _Budget(char_limit)
    try:
        slides = _slide_names(archive, budget)
        if not slides:
            raise ExtractError("PowerPoint file has no slides")
        blocks: list[str] = []
        for name in slides:
            if budget.full:
                break
            budget.part()
            text = _part_text(archive, name, _A, budget)
            if text:
                blocks.append(text)
        return _clip(blocks, char_limit + 1)
    finally:
        archive.close()


def _slide_names(archive: zipfile.ZipFile, budget: _Budget) -> list[str]:
    """Slide parts in presentation order, each once, only those in the package.

    presentation.xml may list one slide relationship any number of times; reading it
    again would add no text, only work.
    """
    names = set(archive.namelist())
    targets: dict[str, str] = {}
    for event, rel in _xml_events(archive, "ppt/_rels/presentation.xml.rels", budget):
        if event != "start" or not rel.tag.endswith("Relationship"):
            continue
        attrib = rel.attrib
        rel_id = attrib.get("Id", "")
        target = attrib.get("Target", "")
        rel_type = attrib.get("Type", "")
        if rel_id and target and rel_type.endswith("/slide"):
            targets[rel_id] = target.lstrip("/")
    ordered: list[str] = []
    seen: set[str] = set()
    if targets:
        slide_tag, id_attr = _local("sldId", _P), _local("id", _R)
        for event, node in _xml_events(archive, "ppt/presentation.xml", budget):
            if event != "start" or node.tag != slide_tag:
                continue
            target = targets.get(node.attrib.get(id_attr, ""))
            if not target:
                continue
            path = target if target.startswith("ppt/") else f"ppt/{target}"
            if path in seen or path not in names:
                continue
            seen.add(path)
            ordered.append(path)
            if len(ordered) > _PART_CAP:
                raise ExtractError("PowerPoint file has too many slides to extract")
    if ordered:
        return ordered
    return sorted(
        name for name in names if name.startswith("ppt/slides/slide") and name.endswith(".xml")
    )


def _xlsx(data: bytes, char_limit: int) -> str:
    return _clip([text for _, text in xlsx_tabs(data, char_limit)], char_limit + 1)


def xlsx_tabs(data: bytes, char_limit: int) -> list[tuple[str, str]]:
    """(tab title, text) for each non-empty tab, in order, stopping once past `char_limit`.

    Rows are tab-separated. With more than one tab, each tab's text starts with a
    `# <title>` line. Callers that need to know which tab a cut landed in use the titles
    here rather than searching the text, where a cell can also start with `# `.
    """
    if char_limit < 1:
        raise ExtractError("character limit is too small")
    _sniff_kind("xlsx", data)  # refuses a legacy binary workbook
    archive_check = _open_zip(data)
    archive_check.close()
    budget = _Budget(char_limit)
    try:
        workbook = _load_workbook(data, budget)
    except ExtractError:
        raise
    except Exception as exc:
        raise ExtractError("could not read spreadsheet") from exc
    try:
        return _workbook_tabs(workbook, budget)
    except ExtractError:
        raise
    except Exception as exc:
        raise ExtractError("could not read spreadsheet") from exc
    finally:
        workbook.close()


def _workbook_tabs(workbook, budget: _Budget) -> list[tuple[str, str]]:
    sheets = list(workbook.worksheets)
    tabs: list[tuple[str, str]] = []
    multi = len(sheets) > 1
    for sheet in sheets:
        rows: list[str] = []
        if multi:
            rows.append(f"# {sheet.title}")
            budget.add_chars(len(rows[-1]) + 1)
        for row in sheet.iter_rows(values_only=True):
            # Every row is work, even one with no cells, and rows openpyxl fills in for
            # a gap in the row numbers are rows too.
            budget.cell(len(row) + 1)
            cells = ["" if cell is None else str(cell) for cell in row]
            while cells and cells[-1] == "":
                cells.pop()
            if not cells:
                continue
            rows.append("\t".join(cells))
            budget.add_chars(len(rows[-1]) + 1)
            if budget.full:
                break
        if rows:
            tabs.append((str(sheet.title), "\n".join(rows).replace("\x00", "")))
        if budget.full:
            break
    return tabs


class _MeteredReader:
    """A zip member stream that counts the XML tags read through it."""

    def __init__(self, source, budget: _Budget) -> None:
        self._source = source
        self._budget = budget

    def read(self, size: int = -1) -> bytes:
        data = self._source.read(size)
        self._budget.xml_bytes(data)
        return data

    def close(self) -> None:
        self._source.close()

    def __enter__(self) -> "_MeteredReader":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def __getattr__(self, name: str):
        return getattr(self._source, name)


class _MeteredZip:
    """The workbook's zip as openpyxl sees it: every member it reads is metered.

    openpyxl parses the XML itself, so the element count comes from the raw bytes as
    they are read, before parsing, and covers every part it touches.
    """

    def __init__(self, archive: zipfile.ZipFile, budget: _Budget) -> None:
        self._archive = archive
        self._budget = budget

    def open(self, name, *args, **kwargs) -> _MeteredReader:
        return _MeteredReader(self._archive.open(name, *args, **kwargs), self._budget)

    def read(self, name, *args, **kwargs) -> bytes:
        data = self._archive.read(name, *args, **kwargs)
        self._budget.xml_bytes(data)
        return data

    def __getattr__(self, name: str):
        return getattr(self._archive, name)


def _load_workbook(data: bytes, budget: _Budget):
    """openpyxl.load_workbook(read_only=True, data_only=True) with the file's budget applied.

    workbook.xml may point many sheets at one part; each sheet is read once. External
    links are not loaded: they hold cached copies of other workbooks and add no text.
    """
    from openpyxl.reader.excel import ExcelReader

    class _Reader(ExcelReader):
        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **kwargs)
            self.archive = _MeteredZip(self.archive, budget)

        def read_worksheets(self) -> None:
            self.parser.sheets = _unique_sheets(self.parser)
            super().read_worksheets()

    reader = _Reader(io.BytesIO(data), read_only=True, data_only=True, keep_links=False)
    reader.read()
    return reader.wb


def _unique_sheets(parser) -> list:
    sheets = list(parser.sheets)
    if len(sheets) > _PART_CAP:
        raise ExtractError("spreadsheet has too many sheets to extract; use download_file")
    rels = parser.rels
    kept = []
    seen: set[str] = set()
    for sheet in sheets:
        rel = rels.get(sheet.id) if sheet.id else None
        if rel is None or rel.target in seen:
            continue
        seen.add(rel.target)
        kept.append(sheet)
    return kept


def _pdf(data: bytes, char_limit: int) -> str:
    from pypdf import PdfReader, apply_configuration

    budget = _Budget(char_limit)
    deadline = time.monotonic() + _PDF_SECONDS
    form_cost: dict[str, int] = {}
    nested_form_cost = 0

    def count_operation(operator: bytes = b"", operands: object = None, *_args: object) -> None:
        cost = 1
        if operator == b"Do" and isinstance(operands, list) and operands:
            # pypdf parses a form again each time it is drawn and does not let an error
            # raised inside one stop the page, so pay for the form before it is parsed.
            cost += form_cost.get(str(operands[0]), nested_form_cost)
        budget.operation(cost)
        if time.monotonic() > deadline:
            raise ExtractError("PDF is too complex to extract; use download_file")

    # pypdf's own limits are per stream and per page; tighten the ones a small file can
    # multiply: how often a page may draw forms, and how big one content stream may be.
    with apply_configuration(
        xform_maximum_invocations_per_extraction=_PDF_FORM_CAP,
        stream_parsing_work_maximum_count=_PDF_OPERATION_CAP,
    ):
        try:
            reader = PdfReader(io.BytesIO(data))
        except Exception as exc:
            raise ExtractError("could not read PDF") from exc
        if reader.is_encrypted:
            try:
                unlocked = reader.decrypt("")
            except Exception as exc:
                raise ExtractError("PDF is password-protected") from exc
            if unlocked == 0:
                raise ExtractError("PDF is password-protected")
        pages: list[str] = []
        seen: set[tuple[int, int]] = set()
        try:
            for page in reader.pages:
                if budget.full:
                    break
                if len(pages) >= _PDF_PAGE_CAP:
                    raise ExtractError("PDF has too many pages to extract; use download_file")
                ref = page.indirect_reference
                if ref is not None:
                    key = (ref.idnum, ref.generation)
                    if key in seen:  # one page object listed again in the page tree
                        continue
                    seen.add(key)
                form_cost, nested_form_cost = _pdf_form_costs(page)
                count_operation()  # a page costs something even with no content
                text = page.extract_text(visitor_operand_before=count_operation) or ""
                pages.append(text)
                budget.add_chars(len(text) + 1)
        except ExtractError:
            raise
        except Exception as exc:
            raise ExtractError("could not read PDF") from exc
    return _clip(pages, char_limit + 1)


def _pdf_form_costs(page) -> tuple[dict[str, int], int]:
    """What drawing each of the page's forms costs, by resource name, and the most any
    form reachable from the page costs (for a `Do` inside a form, whose resources differ).
    """

    def forms_of(resources) -> dict[str, object]:
        try:
            xobjects = resources.get_object().get("/XObject")
            if xobjects is None:
                return {}
            found = {}
            for name, value in xobjects.get_object().items():
                stream = value.get_object()
                if stream.get("/Subtype") == "/Form":
                    found[str(name)] = stream
            return found
        except AttributeError:
            return {}

    def cost(stream) -> int:
        return len(stream.get_data()) // _PDF_BYTES_PER_OPERATION

    resources = page.get("/Resources")
    if resources is None:
        return {}, 0
    direct = forms_of(resources)
    costs = {name: cost(stream) for name, stream in list(direct.items())[:_PDF_FORM_SCAN_CAP]}
    most = max(costs.values(), default=0)
    pending = list(direct.values())
    visited = {id(stream) for stream in pending}
    while pending and len(visited) <= _PDF_FORM_SCAN_CAP:
        stream = pending.pop()
        most = max(most, cost(stream))
        inner = stream.get("/Resources")
        if inner is None:
            continue
        for child in forms_of(inner).values():
            if id(child) not in visited:
                visited.add(id(child))
                pending.append(child)
    if len(visited) > _PDF_FORM_SCAN_CAP:
        raise ExtractError("PDF is too complex to extract; use download_file")
    return costs, most


# RTF is read with our own linear scanner, using striprtf's tables. striprtf's
# rtf_to_text runs two regexes (hyperlinks and the font table) whose backtracking is
# quadratic or worse on crafted input: 70 KB took over a minute.
_RTF_TOKEN = re.compile(
    rb"\\([a-z]{1,32})(-?\d{1,10})?[ ]?|\\'([0-9a-f]{2})|\\([^a-z])|([{}])|[\r\n]+|([^\\{}\r\n]+)",
    re.IGNORECASE,
)


def _rtf(data: bytes, char_limit: int) -> str:
    try:
        return _rtf_text(data, char_limit)
    except ExtractError:
        raise
    except Exception as exc:
        raise ExtractError("could not read RTF") from exc


def _rtf_text(data: bytes, char_limit: int) -> str:
    """Plain text of an RTF document, following striprtf's rules, in one pass.

    Text runs are one token, so a long run of picture hex data is cheap. `\\binN` data is
    skipped. Stops once past `char_limit`.
    """
    from striprtf.striprtf import charset_map, destinations, specialchars

    budget = _Budget(char_limit)
    encoding = "cp1252"
    fonts: dict[bytes, str] = {}
    stack: list[tuple[int, bool, bool, bytes | None, bool]] = []
    ucskip = 1
    curskip = 0
    ignorable = suppress = in_fonttbl = False
    current_font: bytes | None = None
    font_entry: bytes | None = None
    hexes = bytearray()
    out: list[str] = []
    depth = 0
    in_document = False

    def emit(text: str) -> None:
        if text:
            out.append(text)
            budget.add_chars(len(text))

    def decode_hexes() -> None:
        codec = fonts.get(current_font, encoding) if current_font is not None else encoding
        try:
            codecs.lookup(codec)
        except LookupError:
            codec = "cp1252"
        emit(bytes(hexes).decode(codec, errors="ignore"))
        hexes.clear()

    pos = 0
    end = len(data)
    while pos < end and not budget.full:
        match = _RTF_TOKEN.match(data, pos)
        if match is None:  # a lone backslash at the very end
            pos += 1
            continue
        pos = match.end()
        budget.node(cap=_RTF_TOKEN_CAP)
        word, arg, hexpair, char, brace, run = match.groups()
        if hexes and hexpair is None:
            decode_hexes()
        if brace:
            curskip = 0
            if brace == b"{":
                depth += 1
                in_document = True
                stack.append((ucskip, ignorable, suppress, current_font, in_fonttbl))
            else:
                depth -= 1
                if stack:
                    ucskip, ignorable, suppress, current_font, in_fonttbl = stack.pop()
                else:
                    ucskip = 0
                    ignorable = True
                if in_document and depth <= 0:
                    break  # anything after the document group is discarded, as Word does
        elif char:
            curskip = 0
            key = char.decode("latin-1")
            if key in specialchars:
                if not ignorable:
                    emit(specialchars[key])
            elif key == "*":
                ignorable = True
        elif word:
            curskip = 0
            name = word.decode("ascii")
            if name == "bin" and arg:
                pos = min(end, pos + max(int(arg), 0))  # raw binary data, never text
                continue
            if name == "fonttbl":
                in_fonttbl = True  # a destination, so ignorable: only fonts are read in it
            elif in_fonttbl:
                if name == "f":
                    font_entry = arg
                elif name == "fcharset" and font_entry is not None and arg:
                    fonts[font_entry] = charset_map.get(int(arg), "cp1252")
            if name in destinations:
                ignorable = True
            elif name == "ansicpg" and arg:
                encoding = f"cp{int(arg)}"
                try:
                    codecs.lookup(encoding)
                except LookupError:
                    encoding = "utf8"
            if ignorable or suppress:
                pass
            elif name in specialchars:
                emit(specialchars[name])
            elif name == "uc":
                if arg:
                    ucskip = max(int(arg), 0)
            elif name == "u":
                if arg is None:
                    curskip = ucskip
                else:
                    code = int(arg)
                    if code < 0:
                        code += 0x10000
                    if 0 <= code <= 0x10FFFF:
                        emit(chr(code))
                    curskip = ucskip
            elif name == "f":
                current_font = arg
            elif name == "colortbl":
                suppress = True
        elif hexpair:
            if curskip > 0:
                curskip -= 1
            elif not ignorable:
                hexes.append(int(hexpair, 16))
                if len(hexes) > 2 * budget.char_goal:
                    decode_hexes()
        elif run:
            if curskip > 0:
                skipped = min(curskip, len(run))
                curskip -= skipped
                run = run[skipped:]
            if run and not ignorable and not suppress:
                emit(run.decode("latin-1"))
    if hexes:
        decode_hexes()
    return "".join(out)[: char_limit + 1]


def _doc(data: bytes, char_limit: int) -> str:
    import olefile

    if not data.startswith(_OLE_MAGIC):
        raise ExtractError("file is not a Word .doc document")
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except Exception as exc:
        raise ExtractError("could not read Word .doc document") from exc
    try:
        if not ole.exists("WordDocument"):
            raise ExtractError("Word .doc document has no WordDocument stream")
        word = ole.openstream("WordDocument").read()
        if len(word) < 0x1AA or struct.unpack_from("<H", word, 0)[0] != 0xA5EC:
            raise ExtractError("file is not a Word .doc document")
        flags = struct.unpack_from("<H", word, 0x0A)[0]
        preferred = "1Table" if flags & 0x0200 else "0Table"
        table = b""
        for name in (preferred, "0Table" if preferred == "1Table" else "1Table"):
            if ole.exists(name):
                table = ole.openstream(name).read()
                break
        if not table:
            raise ExtractError("Word .doc document has no table stream")
    finally:
        ole.close()
    text = _doc_text(word, table, char_limit)
    if not _mostly_text(text):
        raise ExtractError("could not extract readable text from Word .doc")
    return text[: char_limit + 1]


def _doc_text(word: bytes, table: bytes, char_limit: int) -> str:
    """Text from the piece table. Stops once `char_limit` is passed: pieces may overlap,
    so a small crafted file could otherwise expand to pieces x stream-size characters.
    Characters decoded and then dropped (control codes) count too, against `_TEXT_CAP`.
    """
    fc_clx, lcb_clx = struct.unpack_from("<II", word, 0x1A2)
    if lcb_clx <= 0 or fc_clx < 0 or fc_clx + lcb_clx > len(table):
        raise ExtractError("Word .doc piece table is missing")
    clx = table[fc_clx : fc_clx + lcb_clx]
    offset = 0
    while offset < len(clx) and clx[offset] == 0x01:
        if offset + 3 > len(clx):
            raise ExtractError("Word .doc piece table is truncated")
        grp_len = struct.unpack_from("<H", clx, offset + 1)[0]
        offset += 3 + grp_len
    if offset >= len(clx) or clx[offset] != 0x02:
        raise ExtractError("Word .doc piece table is missing")
    if offset + 5 > len(clx):
        raise ExtractError("Word .doc piece table is truncated")
    plc_len = struct.unpack_from("<I", clx, offset + 1)[0]
    plc = clx[offset + 5 : offset + 5 + plc_len]
    if len(plc) != plc_len or plc_len < 16 or (plc_len - 4) % 12 != 0:
        raise ExtractError("Word .doc piece table is truncated")
    pieces = (plc_len - 4) // 12
    if pieces > _PIECE_CAP:
        raise ExtractError("Word .doc document has too many text pieces")
    cps = struct.unpack_from(f"<{pieces + 1}I", plc, 0)
    chars: list[str] = []
    size = 0
    decoded = 0
    for index in range(pieces):
        if size > char_limit:
            break
        count = cps[index + 1] - cps[index]
        if count < 0 or count > len(word):
            raise ExtractError("Word .doc piece table is invalid")
        pcd_at = (pieces + 1) * 4 + index * 8
        fc = struct.unpack_from("<I", plc, pcd_at + 2)[0]
        compressed = bool(fc & 0x40000000)
        byte_at = (fc & 0x3FFFFFFF) // 2 if compressed else fc
        width = 1 if compressed else 2
        end = byte_at + count * width
        if byte_at < 0 or end > len(word):
            raise ExtractError("Word .doc text is outside the document stream")
        # Read the piece a window at a time so a long piece stops at the limit too.
        window = max(char_limit + 1 - size, 4096)
        at = byte_at
        while at < end and size <= char_limit:
            stop = min(end, at + window * width)
            decoded += (stop - at) // width
            if decoded > _TEXT_CAP + 2 * char_limit:
                raise ExtractError(
                    "Word .doc document is too complex to extract; use download_file"
                )
            blob = word[at:stop]
            piece = blob.decode("cp1252" if compressed else "utf-16le", errors="replace")
            cleaned = _clean_word_chars(piece)
            chars.append(cleaned)
            size += len(cleaned)
            at = stop
    return "".join(chars)


# Paragraph, line and page marks become newlines, a cell mark a tab; other control
# characters are dropped.
_WORD_CHARS = {code: None for code in range(32) if chr(code) not in "\n\t"}
_WORD_CHARS.update({ord("\r"): "\n", 0x0B: "\n", 0x0C: "\n", 0x07: "\t"})


def _clean_word_chars(text: str) -> str:
    return text.translate(_WORD_CHARS)


def _mostly_text(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    bad = sum(1 for char in stripped if ord(char) < 32 and char not in "\n\t")
    return bad * 20 <= len(stripped)

"""Turn downloaded Office and PDF bytes into plain text.

Extraction needs no temporary Drive copies and no native binaries such as poppler.
Dependencies are pure Python so the Vercel function stays small. Legacy .doc files are
read from the OLE compound document; the piece table is the Word 97 layout, which
later .doc files still start with.

These functions read untrusted bytes in the calling process. The service runs them in
a child process with hard memory and CPU limits instead (see extract_worker.py); the
limits here keep normal files well inside those.

Every extractor works under one `_Budget` for the whole file. The byte caps bound how
big a file is, not how much work it asks for: a part can be listed many times, an
element can be nested or repeated, and a few kilobytes can compress a million empty
rows. So each file also gets a fixed allowance of parts, XML elements, spreadsheet
rows and cells, PDF operators and output characters, shared by all its parts, and
extraction stops as soon as it has the characters the caller asked for. When an
allowance runs out after some text was read, that text is returned marked truncated.
"""

import codecs
import io
import re
import struct
import time
import zipfile
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
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
# XML elements and attributes parsed across every part, at least this many and more
# for a larger character limit. The defused parser costs about 2 us each.
_NODE_VISIT_CAP = 500_000
_NODES_PER_CHAR = 5
# RTF tokens (control words, text runs), about 0.3 us each.
_RTF_TOKEN_CAP = 1_000_000
_RTF_TOKENS_PER_CHAR = 10
# How deep XML elements may nest. Real documents (tables in tables) stay far below it.
_XML_DEPTH_CAP = 256
# Spreadsheet cells plus rows. Empty rows count: a few bytes of `<row/>` are still work.
_CELL_CAP = 2_000_000
# Element tags openpyxl reads from a workbook. It costs a few microseconds per element.
_XLSX_MARKUP_CAP = 500_000
# The shared-string table has its own allowance: a workbook of short unique strings
# keeps two or three tags per string there.
_XLSX_STRINGS_MARKUP_CAP = 2_000_000
# openpyxl joins every named style (<cellStyle>) with the custom number formats
# (<numFmt>), which is quadratic. Named styles add no text, so they are not read.
_XLSX_NAMED_STYLES = re.compile(
    rb"<(?:[A-Za-z_][\w.-]*:)?cellStyles\b.*?</(?:[A-Za-z_][\w.-]*:)?cellStyles\s*>", re.DOTALL
)
# Text a legacy .doc may decode, including control characters that are thrown away.
_TEXT_CAP = 4_000_000
# PDF content-stream work across all pages and the forms they draw, in operators. A
# form is charged by size each time it is drawn, before pypdf parses it again, and a
# font by the size of its tables each time pypdf builds it (once per page or form per
# font name). One unit is roughly 3 to 10 us of pypdf's time. A larger character limit
# allows more.
_PDF_OPERATION_CAP = 500_000
_PDF_OPERATIONS_PER_CHAR = 2
# Decoded content-stream bytes per operator, roughly, for charging a form before it is
# parsed, and ToUnicode bytes and font-array entries per unit for charging a font.
_PDF_BYTES_PER_OPERATION = 8
_PDF_CMAP_BYTES_PER_OPERATION = 32
_PDF_ARRAY_ITEMS_PER_OPERATION = 16
_PDF_FONT_COST = 5
# What pypdf may decode from one stream, and how many tokens it may parse from one
# content stream. A page over either is skipped and the text is marked truncated.
_PDF_STREAM_BYTES = 4 * 1024 * 1024
_PDF_STREAM_TOKENS = 1_000_000
_PDF_RECOVERY_BYTES = 1_000_000
_PDF_PAGE_CAP = 5000
# Forms one page may draw (pypdf skips the rest). Each draw is charged by size anyway.
_PDF_FORM_CAP = 1000
# How far estimated text may run past the character limit before strings are cut.
_PDF_TEXT_SLACK = 4096
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


class _OutOfBudget(ExtractError):
    """A work allowance ran out. Text read before it may still be returned, truncated."""


@dataclass(frozen=True)
class Extracted:
    """Text from a document. `truncated` is true when text past the end was not read,
    because of the character limit or because a work allowance ran out."""

    text: str
    truncated: bool = False


class _Budget:
    """The work one file may cost, shared by all of its parts.

    `full` turns true once the output has the characters the caller asked for; the
    extractors check it and stop early. Going over any other allowance raises
    `_OutOfBudget`; an extractor that has text by then returns it with `truncated` set.
    """

    def __init__(self, char_limit: int) -> None:
        self.char_goal = char_limit + 1
        self.node_cap = max(_NODE_VISIT_CAP, _NODES_PER_CHAR * char_limit)
        self.chars = 0
        self.parts = 0
        self.nodes = 0
        self.cells = 0
        self.markup = 0
        self.strings_markup = 0
        self.operations = 0
        # Set when an extractor stopped before the end for a reason other than `full`.
        self.truncated = False
        self.reason = ""

    @property
    def full(self) -> bool:
        return self.chars >= self.char_goal

    @property
    def room(self) -> int:
        """Characters still wanted."""
        return max(self.char_goal - self.chars, 0)

    def add_chars(self, count: int) -> None:
        self.chars += count

    def part(self) -> None:
        self.parts += 1
        if self.parts > _PART_CAP:
            raise ExtractError("file has too many parts to extract; use download_file")

    def node(self, count: int = 1, cap: int | None = None) -> None:
        self.nodes += count
        if self.nodes > (self.node_cap if cap is None else cap):
            raise _OutOfBudget("document is too complex to extract; use download_file")

    def cell(self, count: int) -> None:
        self.cells += count
        if self.cells > _CELL_CAP:
            raise _OutOfBudget("spreadsheet is too large to extract; use download_file")

    def xml_bytes(self, data: bytes, *, strings: bool = False) -> None:
        """Count the element tags in raw XML a library is about to parse."""
        tags = data.count(b"<") - data.count(b"</")
        if strings:
            self.strings_markup += tags
            over = self.strings_markup > _XLSX_STRINGS_MARKUP_CAP
        else:
            self.markup += tags
            over = self.markup > _XLSX_MARKUP_CAP
        if over:
            raise _OutOfBudget("spreadsheet is too large to extract; use download_file")

    def stop(self, exc: ExtractError) -> None:
        """Note that an allowance ran out, so the text so far is all there will be."""
        self.truncated = True
        self.reason = self.reason or str(exc)

    def result(self, text: str, char_limit: int) -> "Extracted":
        """The text read so far. With none and an allowance spent, refuse instead."""
        if self.truncated and not text.strip():
            raise ExtractError(
                self.reason or "document is too complex to extract; use download_file"
            )
        return Extracted(text, self.truncated or len(text) > char_limit)


def document_kind(mime_type: str, name: str) -> str | None:
    """Which extractor to use, or None when the file should be returned as bytes."""
    mime = mime_type.lower().split(";")[0].strip()
    if mime in MIME_KIND:
        return MIME_KIND[mime]
    if mime in GENERIC_MIMES:
        ext = _extension(name)
        return EXT_KIND.get(ext)
    return None


def extract(data: bytes, kind: str, *, char_limit: int) -> Extracted:
    """Extract plain text in this process. The text may run one character past
    `char_limit` (the caller truncates); `truncated` says whether anything was left out."""
    if char_limit < 1:
        raise ExtractError("character limit is too small")
    kind = _sniff_kind(kind, data)
    if kind == "pdf":
        result = _pdf(data, char_limit)
    elif kind == "docx":
        result = _docx(data, char_limit)
    elif kind == "pptx":
        result = _pptx(data, char_limit)
    elif kind == "xlsx":
        result = _xlsx(data, char_limit)
    elif kind == "rtf":
        result = _rtf(data, char_limit)
    elif kind == "doc":
        result = _doc(data, char_limit)
    else:
        raise ExtractError(f"no text extractor for {kind}")
    text = result.text.replace("\x00", "")
    return Extracted(text[: char_limit + 1], result.truncated or len(text) > char_limit)


def extract_text(data: bytes, kind: str, *, char_limit: int) -> str:
    """Extract plain text. May run slightly past `char_limit`; the caller truncates."""
    return extract(data, kind, char_limit=char_limit).text


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


def _add_block(blocks: list[str], text: str, budget: _Budget, *, counted: bool = False) -> None:
    """Keep a non-empty section and count it (unless its characters were `counted` as
    they were read) with the newline `_clip` puts before it."""
    if text:
        budget.add_chars((0 if counted else len(text)) + (1 if blocks else 0))
        blocks.append(text)


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
                    # Attributes are parsed too: one element can carry a million.
                    budget.node(1 + len(node.attrib))
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
    line after its parent's; its text is not repeated in the parent's line. Characters
    are counted here (the part's own newlines too) but not the part as a block; the
    caller counts that once it knows the part has text. If the work allowance runs out,
    the paragraphs read so far are returned and the budget is marked truncated.
    """
    paragraph_tag, text_tag = _local("p", ns), _local("t", ns)
    break_tag, tab_tag = _local("br", ns), _local("tab", ns)
    lines: list[list[str]] = []
    open_lines: list[list[str]] = []
    try:
        for event, node in _xml_events(archive, name, budget):
            tag = node.tag
            if event == "start":
                if tag == paragraph_tag:
                    if lines:
                        budget.add_chars(1)  # the newline before it
                    line: list[str] = []
                    lines.append(line)
                    open_lines.append(line)
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
    except _OutOfBudget as exc:
        budget.stop(exc)
    return "\n".join("".join(line) for line in lines)


def _part_blocks(archive: zipfile.ZipFile, parts: list[str], ns: str, budget: _Budget) -> str:
    blocks: list[str] = []
    for name in parts:
        if budget.full or budget.truncated:
            break
        budget.part()
        _add_block(blocks, _part_text(archive, name, ns, budget), budget, counted=True)
    return _clip(blocks, budget.char_goal)


def _docx(data: bytes, char_limit: int) -> Extracted:
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
        parts = [name for name in parts if name in names]
        return budget.result(_part_blocks(archive, parts, _W, budget), char_limit)
    finally:
        archive.close()


def _pptx(data: bytes, char_limit: int) -> Extracted:
    archive = _open_zip(data)
    budget = _Budget(char_limit)
    try:
        slides = _slide_names(archive, budget)
        if not slides:
            raise ExtractError("PowerPoint file has no slides")
        return budget.result(_part_blocks(archive, slides, _A, budget), char_limit)
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


def _xlsx(data: bytes, char_limit: int) -> Extracted:
    tabs, truncated = read_xlsx_tabs(data, char_limit)
    text = _clip([text for _, text in tabs], char_limit + 1)
    return Extracted(text, truncated or len(text) > char_limit)


def xlsx_tabs(data: bytes, char_limit: int) -> list[tuple[str, str]]:
    """(tab title, text) for each non-empty tab, in order, stopping once past `char_limit`.

    Rows are tab-separated. With more than one tab, each tab's text starts with a
    `# <title>` line. Callers that need to know which tab a cut landed in use the titles
    here rather than searching the text, where a cell can also start with `# `.
    """
    return read_xlsx_tabs(data, char_limit)[0]


def read_xlsx_tabs(data: bytes, char_limit: int) -> tuple[list[tuple[str, str]], bool]:
    """xlsx_tabs, and whether text was left out (the limit, or a work allowance ran out)."""
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
        tabs = _workbook_tabs(workbook, budget)
    except ExtractError:
        raise
    except Exception as exc:
        raise ExtractError("could not read spreadsheet") from exc
    finally:
        workbook.close()
    if budget.truncated and not tabs:
        raise ExtractError(budget.reason)
    return tabs, budget.truncated or budget.full


def _join_cells(cells: list[str], room: int) -> tuple[str, bool]:
    """Cells joined by tabs, cut to `room` characters before they are joined (one shared
    string can be repeated in every cell of a row), and whether anything was cut."""
    out: list[str] = []
    size = 0
    for index, cell in enumerate(cells):
        if index:
            if size >= room:
                return "".join(out), True
            out.append("\t")
            size += 1
        if size + len(cell) > room:
            out.append(cell[: max(room - size, 0)])
            return "".join(out), True
        out.append(cell)
        size += len(cell)
    return "".join(out), False


def _workbook_tabs(workbook, budget: _Budget) -> list[tuple[str, str]]:
    sheets = list(workbook.worksheets)
    tabs: list[tuple[str, str]] = []
    multi = len(sheets) > 1
    for sheet in sheets:
        rows: list[str] = []
        if multi:
            rows.append(f"# {sheet.title}")
            budget.add_chars(len(rows[-1]) + (1 if tabs else 0))
        try:
            for row in sheet.iter_rows(values_only=True):
                # Every row is work, even one with no cells, and rows openpyxl fills in
                # for a gap in the row numbers are rows too.
                budget.cell(len(row) + 1)
                cells = ["" if cell is None else str(cell) for cell in row]
                while cells and cells[-1] == "":
                    cells.pop()
                if not cells:
                    continue
                # The newline before the row: after the title, an earlier row or tab.
                newline = 1 if rows or tabs else 0
                # A cut row fills the room, so the budget is full after it.
                line, _ = _join_cells(cells, budget.room - newline)
                rows.append(line)
                budget.add_chars(len(line) + newline)
                if budget.full:
                    break
        except _OutOfBudget as exc:
            budget.stop(exc)
        if rows:
            tabs.append((str(sheet.title), "\n".join(rows).replace("\x00", "")))
        if budget.full or budget.truncated:
            break
    return tabs


class _MeteredReader:
    """A zip member stream that counts the XML tags read through it."""

    def __init__(self, source, budget: _Budget, strings: bool = False) -> None:
        self._source = source
        self._budget = budget
        self._strings = strings

    def read(self, size: int = -1) -> bytes:
        data = self._source.read(size)
        self._budget.xml_bytes(data, strings=self._strings)
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
    they are read, before parsing, and covers every part it touches. The shared-string
    table is counted against its own allowance, and named styles are left out of the
    stylesheet (see `_XLSX_NAMED_STYLES`).
    """

    def __init__(self, archive: zipfile.ZipFile, budget: _Budget) -> None:
        self._archive = archive
        self._budget = budget
        self.reading_strings = False

    def open(self, name, *args, **kwargs) -> _MeteredReader:
        source = self._archive.open(name, *args, **kwargs)
        return _MeteredReader(source, self._budget, strings=self.reading_strings)

    def read(self, name, *args, **kwargs) -> bytes:
        data = self._archive.read(name, *args, **kwargs)
        self._budget.xml_bytes(data)
        if name == "xl/styles.xml":  # the path openpyxl reads styles from
            data = _XLSX_NAMED_STYLES.sub(b"", data)
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

        def read_strings(self) -> None:
            self.archive.reading_strings = True
            try:
                super().read_strings()
            finally:
                self.archive.reading_strings = False

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


class _PdfStop(BaseException):
    """Ends PDF extraction from inside pypdf, which catches any Exception raised while it
    reads a form XObject and carries on. Never escapes `_pdf`."""


# Operators that show text, and where their string operand is.
_PDF_TEXT_OPERAND = {b"Tj": 0, b"'": 0, b'"': 2}


def _pdf(data: bytes, char_limit: int) -> Extracted:
    from pypdf import PdfReader, apply_configuration

    budget = _Budget(char_limit)
    # pypdf's own limits are per stream and per page. Tighten the ones a small file can
    # multiply: how often a page may draw forms, how much one stream may decode to and
    # how many tokens one content stream may hold. Never run an external decoder.
    with apply_configuration(
        xform_maximum_invocations_per_extraction=_PDF_FORM_CAP,
        stream_parsing_work_maximum_count=_PDF_STREAM_TOKENS,
        zlib_maximum_output_length=_PDF_STREAM_BYTES,
        zlib_maximum_recovery_input_length=_PDF_RECOVERY_BYTES,
        lzw_maximum_output_length=_PDF_STREAM_BYTES,
        run_length_maximum_output_length=_PDF_STREAM_BYTES,
        array_based_stream_maximum_output_length=_PDF_STREAM_BYTES,
        brotli_maximum_output_length=_PDF_STREAM_BYTES,
        jbig2_maximum_output_length=_PDF_STREAM_BYTES,
        jbig2dec_binary=None,
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
        pages = _PdfPages(budget, time.monotonic() + _PDF_SECONDS).read(reader)
    return budget.result(_clip(pages, char_limit + 1), char_limit)


class _PdfPages:
    """Reads a PDF's pages within one budget.

    Before pypdf does work the operator count cannot see, it is charged here: building
    a page's or form's fonts (pypdf builds every font a resource dictionary names, used
    or not) and parsing a form each time it is drawn. Text-showing operators have their
    strings cut so that, at the most a font can expand a byte, the page cannot produce
    much more than the characters still wanted. A page pypdf cannot read is skipped;
    running out of work or time ends the file with the text so far, marked truncated.
    """

    def __init__(self, budget: _Budget, deadline: float) -> None:
        self.budget = budget
        self.deadline = deadline
        self.operation_cap = max(_PDF_OPERATION_CAP, _PDF_OPERATIONS_PER_CHAR * budget.char_goal)
        # Per stream or font object: (the object, kept so its id is not reused, its cost).
        self.costs: dict[int, tuple[object, int]] = {}
        self.expansions: dict[int, int] = {}
        self.resource_expansions: dict[int, tuple[object, int]] = {}
        # The most characters one string byte may become, for the page and each form
        # being read (pypdf reads a form with only the form's own fonts).
        self.expansion: list[int] = [1]
        self.page_chars = 0
        self.pending = 0
        self.pieces: list[str] = []

    def read(self, reader) -> list[str]:
        pages: list[str] = []
        seen: set[tuple[int, int]] = set()
        try:
            for index, page in enumerate(reader.pages):
                if self.budget.full:
                    break
                if index >= _PDF_PAGE_CAP:
                    self.budget.stop(ExtractError("PDF has too many pages to extract"))
                    break
                ref = page.indirect_reference
                if ref is not None:
                    key = (ref.idnum, ref.generation)
                    if key in seen:  # one page object listed again in the page tree
                        continue
                    seen.add(key)
                _add_block(pages, self.page_text(page), self.budget)
        except _PdfStop:
            _add_block(pages, "".join(self.pieces), self.budget)
            self.budget.stop(ExtractError("PDF is too complex to extract; use download_file"))
        except Exception as exc:  # the page tree itself is broken past this point
            if not pages:
                raise ExtractError("could not read PDF") from exc
            self.budget.stop(ExtractError("could not read PDF"))
        return pages

    def page_text(self, page) -> str:
        self.page_chars = 0
        self.pending = 0
        self.pieces = []
        self.charge(1)  # a page costs something even with no content
        draws = 0
        try:
            self.expansion = [self.resource_cost(_pdf_resources(page))]
            original = page.extract_xform_text

            def xform_text(xform, *args, **kwargs):
                nonlocal draws
                draws += 1
                if draws >= _PDF_FORM_CAP:  # pypdf skips any form drawn after this one
                    self.budget.stop(ExtractError("PDF is too complex to extract"))
                self.charge(self.stream_cost(xform))
                self.expansion.append(self.resource_cost(_pdf_resources(xform)))
                try:
                    return original(xform, *args, **kwargs)
                finally:
                    self.expansion.pop()

            # pypdf reads a drawn form through this method of the page.
            page.extract_xform_text = xform_text
            text = page.extract_text(visitor_operand_before=self.operator, visitor_text=self.text)
            return text or ""
        except _PdfStop:
            raise
        except Exception as exc:
            # A page over one of pypdf's limits, or broken: the rest can still be read.
            from pypdf.errors import LimitReachedError

            if isinstance(exc, LimitReachedError):
                self.budget.stop(ExtractError("PDF is too complex to extract; use download_file"))
            else:
                self.budget.stop(ExtractError("could not read PDF"))
            return ""

    def charge(self, cost: int) -> None:
        self.budget.operations += cost
        if self.budget.operations > self.operation_cap or time.monotonic() > self.deadline:
            raise _PdfStop

    def operator(self, operator: bytes, operands: list, *_args: object) -> None:
        self.charge(1)
        if operator == b"TJ":
            if operands and isinstance(operands[0], list):
                items = operands[0]
                for index, item in enumerate(items):
                    if _is_pdf_string(item):
                        items[index] = self.fit(item)
        elif operator in _PDF_TEXT_OPERAND:
            index = _PDF_TEXT_OPERAND[operator]
            if len(operands) > index and _is_pdf_string(operands[index]):
                operands[index] = self.fit(operands[index])

    def text(self, text: str, *_args: object) -> None:
        if text:
            self.page_chars += len(text)
            self.pending = max(self.pending - len(text), 0)
            self.pieces.append(text)

    def fit(self, value):
        """The string, cut so the text it may become fits what is still wanted."""
        expansion = self.expansion[-1]
        room = self.budget.room - self.page_chars + _PDF_TEXT_SLACK - self.pending
        cost = len(value) * expansion
        if cost <= room:
            self.pending += cost
            return value
        keep = max(room, 0) // expansion
        self.pending += keep * expansion
        self.budget.truncated = True
        self.budget.reason = self.budget.reason or "PDF text was cut"
        return _cut_pdf_string(value, keep)

    def resource_cost(self, resources) -> int:
        """Charge for the fonts pypdf will build from `resources`; their expansion."""
        fonts = _pdf_entry(resources, "/Font")
        if not isinstance(fonts, dict):
            return 1
        cached = self.resource_expansions.get(id(fonts))
        expansion = 1
        for value in list(fonts.values()):
            font = _pdf_object(value)
            if not isinstance(font, dict):
                continue
            self.charge(1 + self.font_cost(font))
            if cached is None:
                expansion = max(expansion, self.font_expansion(font))
        if cached is not None:
            return cached[1]
        self.resource_expansions[id(fonts)] = (fonts, expansion)
        return expansion

    def font_cost(self, font: dict) -> int:
        """What pypdf's building of the font costs, from the size of its tables."""
        known = self.costs.get(id(font))
        if known is not None:
            return known[1]
        cost = _PDF_FONT_COST
        try:
            to_unicode = _pdf_object(font.get("/ToUnicode"))
            if isinstance(to_unicode, dict):
                cost += _pdf_stream_size(to_unicode) // _PDF_CMAP_BYTES_PER_OPERATION
            items = _pdf_items(font.get("/Widths"))
            encoding = _pdf_object(font.get("/Encoding"))
            if isinstance(encoding, dict):
                items += _pdf_items(encoding.get("/Differences"))
            descendants = _pdf_object(font.get("/DescendantFonts"))
            if isinstance(descendants, list):
                for descendant in descendants[:4]:
                    descendant = _pdf_object(descendant)
                    if isinstance(descendant, dict):
                        items += _pdf_items(descendant.get("/W"))
            cost += items // _PDF_ARRAY_ITEMS_PER_OPERATION
        except Exception:
            cost = _PDF_FONT_COST  # pypdf will fail on it too, then skip the font or the page
        self.costs[id(font)] = (font, cost)
        return cost

    def font_expansion(self, font: dict) -> int:
        """The most characters pypdf may turn one string byte into with this font: an
        encoding entry may name a glyph, and a ToUnicode entry may map each character
        of that to up to 256 more."""
        known = self.expansions.get(id(font))
        if known is not None:
            return known
        expansion = 1
        try:
            from pypdf.generic._font import Font

            built = Font.from_font_resource(font)
            encoding = built.encoding
            by_byte = 1
            if isinstance(encoding, dict):
                by_byte = max((len(v) for v in encoding.values() if isinstance(v, str)), default=1)
            by_char = max(
                (len(v) for v in built.character_map.values() if isinstance(v, str)), default=1
            )
            expansion = max(by_byte, 1) * max(by_char, 1)
        except Exception:
            expansion = 1  # pypdf skips a font it cannot build, or fails the page
        self.expansions[id(font)] = expansion
        self.costs.setdefault(id(font), (font, _PDF_FONT_COST))
        return expansion

    def stream_cost(self, stream) -> int:
        """What parsing a form's content stream costs, from its decoded size."""
        known = self.costs.get(id(stream))
        if known is not None:
            return known[1]
        cost = 1 + _pdf_stream_size(stream) // _PDF_BYTES_PER_OPERATION
        self.costs[id(stream)] = (stream, cost)
        return cost


def _pdf_object(value):
    try:
        return value.get_object() if value is not None else None
    except Exception:
        return None


def _pdf_resources(obj):
    """The /Resources pypdf reads text with, inherited from the page tree as it does."""
    try:
        return obj.get_inherited("/Resources", None)
    except Exception:
        return None


def _pdf_entry(dictionary, key: str):
    dictionary = _pdf_object(dictionary)
    if not isinstance(dictionary, dict):
        return None
    return _pdf_object(dictionary.get(key))


def _pdf_items(array) -> int:
    """Entries in an array, counting one level of nested arrays (as in a /W array)."""
    array = _pdf_object(array)
    if not isinstance(array, list):
        return 0
    return len(array) + sum(len(item) for item in array if isinstance(item, list))


def _pdf_stream_size(stream) -> int:
    """How many bytes a stream decodes to, at most `_PDF_STREAM_BYTES`.

    A Flate stream (nearly all of them) is inflated from its raw bytes into a buffer
    that is dropped at once; pypdf caches what it decodes, so asking it would keep
    every stream looked at in memory. Other filters are left to pypdf, under its caps.
    """
    raw = getattr(stream, "_data", None)
    if not isinstance(raw, bytes):
        return 0
    filters = _pdf_object(stream.get("/Filter"))
    if isinstance(filters, list):
        filters = [_pdf_object(item) for item in filters]
    else:
        filters = [] if filters is None else [filters]
    if not filters:
        return min(len(raw), _PDF_STREAM_BYTES)
    if getattr(stream, "decoded_self", None) is None and filters in (["/FlateDecode"], ["/Fl"]):
        try:
            inflater = zlib.decompressobj()
            return len(inflater.decompress(raw, _PDF_STREAM_BYTES))
        except zlib.error:
            return min(len(raw), _PDF_STREAM_BYTES)
    try:
        return min(len(stream.get_data()), _PDF_STREAM_BYTES)
    except Exception:
        return 0


def _is_pdf_string(value) -> bool:
    from pypdf.generic import NameObject

    return isinstance(value, (str, bytes)) and not isinstance(value, NameObject)


def _cut_pdf_string(value, keep: int):
    from pypdf.generic import ByteStringObject, TextStringObject

    if isinstance(value, ByteStringObject):
        return ByteStringObject(bytes(value[:keep]))
    if isinstance(value, TextStringObject):
        return TextStringObject(str(value[:keep]))
    return value[:keep]


# RTF is read with our own linear scanner, using striprtf's tables. striprtf's
# rtf_to_text runs two regexes (hyperlinks and the font table) whose backtracking is
# quadratic or worse on crafted input: 70 KB took over a minute.
_RTF_TOKEN = re.compile(
    rb"\\([a-z]{1,32})(-?\d{1,10})?[ ]?|\\'([0-9a-f]{2})|\\([^a-z])|([{}])|[\r\n]+|([^\\{}\r\n]+)",
    re.IGNORECASE,
)


def _rtf(data: bytes, char_limit: int) -> Extracted:
    budget = _Budget(char_limit)
    try:
        text = _rtf_text(data, char_limit, budget)
    except ExtractError:
        raise
    except Exception as exc:
        raise ExtractError("could not read RTF") from exc
    return budget.result(text, char_limit)


# striprtf turns a hyperlink field into its shown text followed by the quoted target in
# parentheses, `text("url")`. Field instructions are kept to do the same, up to this
# many characters for the whole file.
_RTF_FIELD_INSTRUCTION_CAP = 65_536
_RTF_HYPERLINK = re.compile(r'HYPERLINK\s(".*")', re.IGNORECASE | re.DOTALL)


def _rtf_text(data: bytes, char_limit: int, budget: _Budget) -> str:
    """Plain text of an RTF document, following striprtf's rules, in one pass.

    Text runs are one token, so a long run of picture hex data is cheap. `\\binN` data is
    skipped. Stops once past `char_limit`, or with the text so far when the token
    allowance runs out.
    """
    from striprtf.striprtf import charset_map, destinations, specialchars

    token_cap = max(_RTF_TOKEN_CAP, _RTF_TOKENS_PER_CHAR * char_limit)
    encoding = "cp1252"
    fonts: dict[bytes, str] = {}
    stack: list[tuple[int, bool, bool, bytes | None, bool, bool]] = []
    ucskip = 1
    curskip = 0
    ignorable = suppress = in_fonttbl = in_fldinst = False
    current_font: bytes | None = None
    font_entry: bytes | None = None
    hexes = bytearray()
    out: list[str] = []
    depth = 0
    in_document = False
    # Open \\field groups: (the depth of the group, its instruction text so far).
    fields: list[tuple[int, list[str]]] = []
    instruction_room = _RTF_FIELD_INSTRUCTION_CAP

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
        try:
            budget.node(cap=token_cap)
        except _OutOfBudget as exc:
            budget.stop(exc)
            break
        word, arg, hexpair, char, brace, run = match.groups()
        if hexes and hexpair is None:
            decode_hexes()
        if brace:
            curskip = 0
            if brace == b"{":
                depth += 1
                in_document = True
                stack.append((ucskip, ignorable, suppress, current_font, in_fonttbl, in_fldinst))
            else:
                depth -= 1
                if stack:
                    state = stack.pop()
                    ucskip, ignorable, suppress, current_font, in_fonttbl, in_fldinst = state
                else:
                    ucskip = 0
                    ignorable = True
                while fields and fields[-1][0] > depth:  # a field group closed
                    link = _RTF_HYPERLINK.search("".join(fields.pop()[1]))
                    if link and not ignorable and not suppress:
                        emit(f"({link.group(1)})")
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
            if name == "field":
                fields.append((depth, []))
            elif name == "fldinst" and fields:
                in_fldinst = True  # a destination: kept only to find a hyperlink target
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
            if run and in_fldinst and fields and instruction_room > 0:
                fields[-1][1].append(run[:instruction_room].decode("latin-1"))
                instruction_room -= min(len(run), instruction_room)
            if run and not ignorable and not suppress:
                emit(run.decode("latin-1"))
    if hexes:
        decode_hexes()
    return "".join(out)


def _doc(data: bytes, char_limit: int) -> Extracted:
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
    return Extracted(text, len(text) > char_limit)


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

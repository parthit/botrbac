"""Turn downloaded Office and PDF bytes into plain text.

Extraction stays in-process (no temporary Drive copies, no native binaries such as
poppler). Dependencies are pure Python so the Vercel function stays small. Legacy
.doc files are read from the OLE compound document; the piece table is the Word 97
layout, which later .doc files still start with.
"""

import io
import struct
import zipfile
from xml.etree.ElementTree import ParseError as XmlParseError

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import fromstring as xml_fromstring

# Returned text stops a little past the caller's limit so the service can mark it truncated.
_ZIP_ENTRY_CAP = 2000
_UNCOMPRESSED_CAP = 32 * 1024 * 1024
_PIECE_CAP = 10_000

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


def _xml(data: bytes):
    try:
        return xml_fromstring(data)
    except (XmlParseError, DefusedXmlException) as exc:
        raise ExtractError("could not parse document XML") from exc


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


def _zip_read(archive: zipfile.ZipFile, name: str) -> bytes | None:
    try:
        return archive.read(name)
    except KeyError:
        return None


def _local(tag: str, ns: str) -> str:
    return f"{ns}{tag}"


def _paragraphs(root, paragraph_tag: str, text_tag: str, break_tag: str, tab_tag: str) -> list[str]:
    lines: list[str] = []
    for paragraph in root.iter(paragraph_tag):
        chunks: list[str] = []
        for node in paragraph.iter():
            if node.tag == text_tag and node.text:
                chunks.append(node.text)
            elif node.tag == tab_tag:
                chunks.append("\t")
            elif node.tag == break_tag:
                chunks.append("\n")
        lines.append("".join(chunks))
    return lines


def _docx(data: bytes, char_limit: int) -> str:
    archive = _open_zip(data)
    try:
        names = set(archive.namelist())
        document = _zip_read(archive, "word/document.xml")
        if document is None:
            raise ExtractError("Word file has no document.xml")
        parts = ["\n".join(_word_paragraphs(_xml(document)))]
        for extra in ("word/footnotes.xml", "word/endnotes.xml"):
            raw = _zip_read(archive, extra)
            if raw is not None:
                parts.append("\n".join(_word_paragraphs(_xml(raw))))
        for name in sorted(names):
            lower = name.lower()
            if lower.startswith("word/header") or lower.startswith("word/footer"):
                raw = _zip_read(archive, name)
                if raw is not None:
                    parts.append("\n".join(_word_paragraphs(_xml(raw))))
        return _clip([part for part in parts if part], char_limit + 1)
    finally:
        archive.close()


def _word_paragraphs(root) -> list[str]:
    return _paragraphs(root, _local("p", _W), _local("t", _W), _local("br", _W), _local("tab", _W))


def _pptx(data: bytes, char_limit: int) -> str:
    archive = _open_zip(data)
    try:
        slides = _slide_names(archive)
        if not slides:
            raise ExtractError("PowerPoint file has no slides")
        blocks: list[str] = []
        for name in slides:
            raw = _zip_read(archive, name)
            if raw is None:
                continue
            lines = _paragraphs(
                _xml(raw), _local("p", _A), _local("t", _A), _local("br", _A), _local("tab", _A)
            )
            blocks.append("\n".join(lines))
        return _clip(blocks, char_limit + 1)
    finally:
        archive.close()


def _slide_names(archive: zipfile.ZipFile) -> list[str]:
    rels = _zip_read(archive, "ppt/_rels/presentation.xml.rels")
    presentation = _zip_read(archive, "ppt/presentation.xml")
    targets: dict[str, str] = {}
    if rels is not None:
        for rel in _xml(rels):
            if not rel.tag.endswith("Relationship"):
                continue
            rel_id = rel.attrib.get("Id", "")
            target = rel.attrib.get("Target", "")
            rel_type = rel.attrib.get("Type", "")
            if rel_id and target and rel_type.endswith("/slide"):
                targets[rel_id] = target.lstrip("/")
    ordered: list[str] = []
    if presentation is not None and targets:
        root = _xml(presentation)
        for node in root.iter(_local("sldId", _P)):
            rel_id = node.attrib.get(_local("id", _R), "")
            target = targets.get(rel_id)
            if target:
                path = target if target.startswith("ppt/") else f"ppt/{target}"
                ordered.append(path)
    if ordered:
        return ordered
    return sorted(
        name
        for name in archive.namelist()
        if name.startswith("ppt/slides/slide") and name.endswith(".xml")
    )


def _xlsx(data: bytes, char_limit: int) -> str:
    return _clip([text for _, text in xlsx_tabs(data, char_limit)], char_limit + 1)


def xlsx_tabs(data: bytes, char_limit: int) -> list[tuple[str, str]]:
    """(tab title, text) for each non-empty tab, in order, stopping once past `char_limit`.

    Rows are tab-separated. With more than one tab, each tab's text starts with a
    `# <title>` line. Callers that need to know which tab a cut landed in use the titles
    here rather than searching the text, where a cell can also start with `# `.
    """
    import openpyxl

    if char_limit < 1:
        raise ExtractError("character limit is too small")
    _sniff_kind("xlsx", data)  # refuses a legacy binary workbook
    archive_check = _open_zip(data)
    archive_check.close()
    try:
        workbook = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    except Exception as exc:
        raise ExtractError("could not read spreadsheet") from exc
    try:
        sheets = list(workbook.worksheets)
        tabs: list[tuple[str, str]] = []
        size = 0
        multi = len(sheets) > 1
        for sheet in sheets:
            rows: list[str] = []
            if multi:
                rows.append(f"# {sheet.title}")
            for row in sheet.iter_rows(values_only=True):
                cells = ["" if cell is None else str(cell) for cell in row]
                while cells and cells[-1] == "":
                    cells.pop()
                if not cells:
                    continue
                rows.append("\t".join(cells))
                size += len(rows[-1])
                if size > char_limit:
                    break
            if rows:
                tabs.append((str(sheet.title), "\n".join(rows).replace("\x00", "")))
            if size > char_limit:
                break
        return tabs
    finally:
        workbook.close()


def _pdf(data: bytes, char_limit: int) -> str:
    from pypdf import PdfReader
    from pypdf.errors import PdfReadError

    try:
        reader = PdfReader(io.BytesIO(data))
    except PdfReadError as exc:
        raise ExtractError("could not read PDF") from exc
    if reader.is_encrypted:
        try:
            unlocked = reader.decrypt("")
        except Exception as exc:
            raise ExtractError("PDF is password-protected") from exc
        if unlocked == 0:
            raise ExtractError("PDF is password-protected")
    pages: list[str] = []
    size = 0
    try:
        for page in reader.pages:
            text = page.extract_text() or ""
            pages.append(text)
            size += len(text)
            if size > char_limit:
                break
    except Exception as exc:
        raise ExtractError("could not read PDF") from exc
    return _clip(pages, char_limit + 1)


def _rtf(data: bytes, char_limit: int) -> str:
    from striprtf.striprtf import rtf_to_text

    # RTF is a 7-bit format with escaped bytes; latin-1 keeps every byte.
    try:
        text = rtf_to_text(data.decode("latin-1"), errors="ignore")
    except Exception as exc:
        raise ExtractError("could not read RTF") from exc
    return text.replace("\x00", "")[: char_limit + 1]


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
    so a small crafted file could otherwise expand to pieces x stream-size characters."""
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
        blob = word[byte_at:end]
        piece = blob.decode("cp1252" if compressed else "utf-16le", errors="replace")
        cleaned = _clean_word_chars(piece)
        chars.append(cleaned)
        size += len(cleaned)
    return "".join(chars)


def _clean_word_chars(text: str) -> str:
    out: list[str] = []
    for char in text:
        code = ord(char)
        if char in "\r\x0b\x0c":
            out.append("\n")
        elif char == "\x07":
            out.append("\t")
        elif code < 32 and char not in "\n\t":
            continue
        else:
            out.append(char)
    return "".join(out)


def _mostly_text(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    bad = sum(1 for char in stripped if ord(char) < 32 and char not in "\n\t")
    return bad * 20 <= len(stripped)

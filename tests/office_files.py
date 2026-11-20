"""Tiny Office and PDF fixtures built in memory so the suite stays offline."""

import io
import struct
import zipfile
from xml.sax.saxutils import escape


def _pdf_literal(text: str) -> bytes:
    safe = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    return f"BT /F1 24 Tf 36 120 Td ({safe}) Tj ET".encode("latin-1")


def minimal_pdf(*pages: str) -> bytes:
    if not pages:
        pages = ("",)
    font_id = 3 + 2 * len(pages)
    kids: list[str] = []
    objects: list[bytes] = []
    for index, text in enumerate(pages):
        page_id = 3 + 2 * index
        content_id = page_id + 1
        kids.append(f"{page_id} 0 R")
        stream = _pdf_literal(text)
        objects.append(
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 400 200] "
                f"/Contents {content_id} 0 R /Resources << /Font << /F1 {font_id} 0 R >> >> >>"
            ).encode()
        )
        objects.append(b"<< /Length %d >>\nstream\n%s\nendstream" % (len(stream), stream))
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    objects.insert(0, f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(pages)} >>".encode())
    objects.insert(0, b"<< /Type /Catalog /Pages 2 0 R >>")
    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{index} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for offset in offsets[1:]:
        out += f"{offset:010d} 00000 n \n".encode()
    out += f"trailer<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def _zip(parts: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for name, body in parts.items():
            archive.writestr(name, body)
    return buf.getvalue()


def minimal_docx(*paragraphs: str, header: str = "") -> bytes:
    body = "".join(
        f"<w:p><w:r><w:t>{escape(paragraph)}</w:t></w:r></w:p>" for paragraph in paragraphs
    )
    document_type = (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
    )
    header_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"
    table = "<w:tbl><w:tr><w:tc><w:p><w:r><w:t>cell text</w:t></w:r></w:p></w:tc></w:tr></w:tbl>"
    parts = {
        "[Content_Types].xml": f"""<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="{document_type}"/>
  <Override PartName="/word/header1.xml" ContentType="{header_type}"/>
</Types>""",
        "word/document.xml": f"""<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>{body}{table}</w:body>
</w:document>""",
        "word/header1.xml": f"""<?xml version="1.0" encoding="UTF-8"?>
<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:p><w:r><w:t>{escape(header)}</w:t></w:r></w:p>
</w:hdr>""",
    }
    return _zip(parts)


def minimal_pptx(*slides: str) -> bytes:
    rels = []
    sld_ids = []
    parts: dict[str, str] = {}
    for index, text in enumerate(slides, start=1):
        rid = f"rId{index}"
        rels.append(
            f'<Relationship Id="{rid}" '
            f'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" '
            f'Target="slides/slide{index}.xml"/>'
        )
        sld_ids.append(f'<p:sldId id="{255 + index}" r:id="{rid}"/>')
        parts[f"ppt/slides/slide{index}.xml"] = f"""<?xml version="1.0" encoding="UTF-8"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
       xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld><p:spTree><p:sp><p:txBody>
    <a:p><a:r><a:t>{escape(text)}</a:t></a:r></a:p>
  </p:txBody></p:sp></p:spTree></p:cSld>
</p:sld>"""
    parts["ppt/presentation.xml"] = f"""<?xml version="1.0" encoding="UTF-8"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
                xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <p:sldIdLst>{"".join(sld_ids)}</p:sldIdLst>
</p:presentation>"""
    parts["ppt/_rels/presentation.xml.rels"] = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + "".join(rels)
        + "</Relationships>"
    )
    return _zip(parts)


def minimal_xlsx(
    rows: list[list[object]],
    sheet: str = "Resume",
    more: list[tuple[str, list[list[object]]]] | None = None,
) -> bytes:
    import openpyxl

    workbook = openpyxl.Workbook()
    worksheet = workbook.active
    assert worksheet is not None
    worksheet.title = sheet
    for row in rows:
        worksheet.append(row)
    for title, sheet_rows in more or []:
        extra = workbook.create_sheet(title)
        for row in sheet_rows:
            extra.append(row)
    buf = io.BytesIO()
    workbook.save(buf)
    workbook.close()
    return buf.getvalue()


def minimal_rtf(text: str) -> bytes:
    escaped = text.replace("\\", "\\\\").replace("{", "\\{").replace("}", "\\}")
    return f"{{\\rtf1\\ansi {escaped}\\par}}".encode("ascii")


def _dir_entry(
    name: str,
    obj_type: int,
    left: int,
    right: int,
    child: int,
    start: int,
    size: int,
) -> bytes:
    encoded = name.encode("utf-16le") + b"\x00\x00"
    if len(encoded) > 64:
        raise ValueError("directory name is too long")
    entry = bytearray(128)
    entry[: len(encoded)] = encoded
    struct.pack_into("<H", entry, 0x40, len(encoded))
    entry[0x42] = obj_type
    entry[0x43] = 1  # black
    struct.pack_into("<III", entry, 0x44, left, right, child)
    struct.pack_into("<I", entry, 0x74, start)
    struct.pack_into("<I", entry, 0x78, size)
    return bytes(entry)


def _compound_file(streams: dict[str, bytes]) -> bytes:
    """A v3 compound file whose streams are larger than the mini-stream cutoff."""
    nostream = 0xFFFFFFFF
    names = list(streams)
    data = [(name, streams[name]) for name in names]
    # sector 0 = FAT, sector 1 = directory, then one run of sectors per stream
    directory = bytearray(512)
    # Root's child is the first stream; each next stream hangs off the right sibling.
    # Names in these fixtures sort in insertion order only when the caller passes them
    # already sorted, so the tree is built by name instead.
    order = sorted(range(len(names)), key=lambda i: names[i].lower())
    nodes: dict[int, tuple[int, int]] = {}

    def walk(indexes: list[int]) -> int:
        if not indexes:
            return nostream
        mid = len(indexes) // 2
        sid = indexes[mid] + 1
        nodes[sid] = (walk(indexes[:mid]), walk(indexes[mid + 1 :]))
        return sid

    root_child = walk(order)
    sector = 2
    layout: list[tuple[str, int, bytes]] = []
    for name, payload in data:
        layout.append((name, sector, payload))
        sector += (len(payload) + 511) // 512
    fat_count = sector  # sectors 0..sector-1
    if fat_count > 128:
        raise ValueError("fixture needs more than one FAT sector")

    directory[:128] = _dir_entry("Root Entry", 5, nostream, nostream, root_child, nostream, 0)
    for index, (name, start, payload) in enumerate(layout, start=1):
        left, right = nodes[index]
        entry = _dir_entry(name, 2, left, right, nostream, start, len(payload))
        directory[index * 128 : (index + 1) * 128] = entry

    fat = bytearray(512)
    for index in range(128):
        struct.pack_into("<I", fat, index * 4, 0xFFFFFFFF)
    struct.pack_into("<I", fat, 0, 0xFFFFFFFD)  # FAT sector
    struct.pack_into("<I", fat, 4, 0xFFFFFFFE)  # directory
    for _name, start, payload in layout:
        count = (len(payload) + 511) // 512
        for offset in range(count - 1):
            struct.pack_into("<I", fat, (start + offset) * 4, start + offset + 1)
        struct.pack_into("<I", fat, (start + count - 1) * 4, 0xFFFFFFFE)

    header = bytearray(512)
    header[:8] = bytes.fromhex("D0CF11E0A1B11AE1")
    struct.pack_into("<H", header, 0x18, 0x003E)
    struct.pack_into("<H", header, 0x1A, 0x0003)
    struct.pack_into("<H", header, 0x1C, 0xFFFE)
    struct.pack_into("<H", header, 0x1E, 9)
    struct.pack_into("<H", header, 0x20, 6)
    struct.pack_into("<I", header, 0x2C, 1)  # FAT sector count
    struct.pack_into("<I", header, 0x30, 1)  # first directory sector
    struct.pack_into("<I", header, 0x38, 4096)
    struct.pack_into("<I", header, 0x3C, 0xFFFFFFFE)
    struct.pack_into("<I", header, 0x44, 0xFFFFFFFE)
    struct.pack_into("<I", header, 0x4C, 0)  # DIFAT[0] = FAT sector 0
    for index in range(1, 109):
        struct.pack_into("<I", header, 0x4C + index * 4, 0xFFFFFFFF)

    blob = bytearray(header)
    blob += fat
    blob += directory
    for _name, _start, payload in layout:
        blob += payload
        pad = (-len(payload)) % 512
        blob += b"\x00" * pad
    return bytes(blob)


def minimal_doc(text: str, *, compressed: bool = False) -> bytes:
    """A Word 97 .doc whose piece table points at one run of `text`."""
    stored = text.replace("\n", "\r")
    encoded = stored.encode("cp1252" if compressed else "utf-16le")
    word = bytearray(5000)
    struct.pack_into("<H", word, 0x00, 0xA5EC)
    struct.pack_into("<H", word, 0x02, 0x00C1)
    text_at = 4200
    word[text_at : text_at + len(encoded)] = encoded
    chars = len(stored)
    cps = struct.pack("<II", 0, chars)
    # Bit 30 set means 8-bit text at fc/2. Clear means UTF-16 at fc.
    fc = (text_at * 2) | 0x40000000 if compressed else text_at
    pcd = struct.pack("<HIH", 0, fc, 0)
    plc = cps + pcd
    clx = struct.pack("<BI", 0x02, len(plc)) + plc
    table = bytearray(4608)
    table[: len(clx)] = clx
    struct.pack_into("<I", word, 0x1A2, 0)
    struct.pack_into("<I", word, 0x1A6, len(clx))
    return _compound_file({"0Table": bytes(table), "WordDocument": bytes(word)})

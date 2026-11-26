"""Tools for the Google Drive files and folders the owner shared."""

from typing import Any

from mcp.server.fastmcp import FastMCP

from ..service import DriveService
from .common import DESTRUCTIVE, READ_ONLY, WRITE, Guarded, _run


def register(mcp: FastMCP, guarded: Guarded, service: DriveService) -> None:
    @mcp.tool(annotations=READ_ONLY)
    @guarded("search_files")
    async def search_files(query: str, max_results: int = 10) -> dict[str, Any]:
        """Search file names and contents in the shared items (max 50 results)."""
        return await _run(service.search_files, query, max_results)

    @mcp.tool(annotations=READ_ONLY)
    @guarded("list_folder")
    async def list_folder(folder_id: str | None = None, max_results: int = 100) -> dict[str, Any]:
        """List the items in a folder. Omit folder_id to list the items the owner shared."""
        return await _run(service.list_folder, folder_id, max_results)

    @mcp.tool(annotations=READ_ONLY)
    @guarded("get_metadata")
    async def get_metadata(file_id: str) -> dict[str, Any]:
        """Get a file's metadata (name, type, size, parents, timestamps, link)."""
        return await _run(service.get_metadata, file_id)

    @mcp.tool(annotations=READ_ONLY)
    @guarded("read_file")
    async def read_file(file_id: str) -> dict[str, Any]:
        """Read a file as text. Google Docs and Slides are exported as plain text. Google
        Sheets return every tab as tab-separated rows, each tab headed "# <tab name>" when
        there is more than one. PDF, Word (.docx and .doc), PowerPoint (.pptx), Excel (.xlsx),
        RTF, CSV, Markdown, JSON, and other text files are extracted to text. Images, archives,
        and other non-text files return no content; use download_file for those bytes. Only
        files the owner shared (directly or inside a shared folder) can be read. Large text
        is truncated."""
        return await _run(service.read_file, file_id)

    @mcp.tool(annotations=READ_ONLY)
    @guarded("download_file")
    async def download_file(file_id: str) -> dict[str, Any]:
        """Download a shared file's bytes as base64. Use this for images, archives, and other
        files read_file cannot turn into text. The same share check as read_file applies.
        Results are capped at 1 MiB (and never above MAX_BYTES); truncated is true when the
        file is longer. Google Docs, Sheets, and Slides have no raw bytes (use read_file).
        Shortcuts are not followed."""
        return await _run(service.download_file, file_id)

    @mcp.tool(annotations=READ_ONLY)
    @guarded("export_file")
    async def export_file(file_id: str, format: str = "pdf") -> dict[str, Any]:
        """Export a shared Google Doc, Sheet or Slides through Google Drive, with its real
        fonts and layout, and return the bytes as base64. format: Docs pdf, docx, odt, rtf,
        txt, md, html (zip), epub; Sheets pdf, xlsx, ods, csv, tsv; Slides pdf, pptx, odp,
        txt. The same cap as download_file applies; a larger export returns no bytes, so for
        a long document or a PDF you mean to keep, call save_export instead."""
        return await _run(service.export_file, file_id, format)

    @mcp.tool(annotations=WRITE)
    @guarded("save_export")
    async def save_export(
        file_id: str, format: str = "pdf", parent_id: str | None = None, name: str | None = None
    ) -> dict[str, Any]:
        """Export a shared Google Doc, Sheet or Slides (same formats as export_file) and save
        it as a new file, e.g. a PDF of a Doc. Omit parent_id to save it in the same folder
        as the original; name defaults to the original's name plus the format's extension.
        Up to Drive's 10 MB export limit."""
        return await _run(service.save_export, file_id, format, parent_id, name)

    @mcp.tool(annotations=WRITE)
    @guarded("create_folder")
    async def create_folder(name: str, parent_id: str | None = None) -> dict[str, Any]:
        """Create a folder. Omit parent_id only if there is a single shared folder."""
        return await _run(service.create_folder, name, parent_id)

    @mcp.tool(annotations=WRITE)
    @guarded("create_doc")
    async def create_doc(
        title: str, content: str = "", parent_id: str | None = None
    ) -> dict[str, Any]:
        """Create a Google Doc from plain text."""
        return await _run(service.create_doc, title, content, parent_id)

    @mcp.tool(annotations=WRITE)
    @guarded("upload_file")
    async def upload_file(
        name: str,
        mime_type: str,
        content_text: str | None = None,
        content_base64: str | None = None,
        parent_id: str | None = None,
    ) -> dict[str, Any]:
        """Upload a file. Give exactly one of content_text or content_base64."""
        return await _run(
            service.upload_file, name, mime_type, content_text, content_base64, parent_id
        )

    @mcp.tool(annotations=DESTRUCTIVE)
    @guarded("update_file_content")
    async def update_file_content(file_id: str, content: str) -> dict[str, Any]:
        """Replace the full content of a Google Doc or text file."""
        return await _run(service.update_file_content, file_id, content)

    @mcp.tool(annotations=WRITE)
    @guarded("rename_file")
    async def rename_file(file_id: str, new_name: str) -> dict[str, Any]:
        """Rename a file or folder (not an item the owner shared directly)."""
        return await _run(service.rename_file, file_id, new_name)

    @mcp.tool(annotations=DESTRUCTIVE)
    @guarded("trash_file")
    async def trash_file(file_id: str) -> dict[str, Any]:
        """Move a file or folder to the trash (recoverable; not an item the owner shared
        directly)."""
        return await _run(service.trash_file, file_id)

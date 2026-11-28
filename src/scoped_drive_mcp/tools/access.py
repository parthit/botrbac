"""Tools for asking the owner for access to something outside the shared items."""

from typing import Any, Literal

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from ..access import AccessService
from ..auth import current_principal
from ..policy import require
from .common import READ_ONLY, WRITE, _run


def register(mcp: FastMCP, access: AccessService | None) -> None:
    @mcp.tool(annotations=WRITE)
    @require("request_access")
    async def request_access(
        description: str,
        reason: str,
        file_id: str | None = None,
        service: Literal["google_drive", "onedrive"] = "google_drive",
    ) -> dict[str, Any]:
        """Ask the owner for access to a file or folder you cannot see. Describe what you
        need (and give file_id if you know it). service is "onedrive" for a OneDrive item.
        Show the returned approval_url to the user."""
        if access is None:
            raise ToolError("access requests are not configured (APP_BASE_URL is not set)")
        principal = current_principal.get()
        return await _run(
            access.request_access,
            description,
            reason,
            file_id,
            token_name=principal.token_name if principal else None,
            service=service,
        )

    @mcp.tool(annotations=READ_ONLY)
    @require("check_access_request")
    async def check_access_request(request_id: str) -> dict[str, Any]:
        """Check whether the owner approved or denied an access request."""
        if access is None:
            raise ToolError("access requests are not configured (APP_BASE_URL is not set)")
        return await _run(access.check_access_request, request_id)

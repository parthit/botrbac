"""Role-to-tool map and the `require(tool)` decorator that enforces it and writes the audit log."""

import functools
import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any, ParamSpec, TypeVar

import anyio.to_thread
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import CallToolResult, TextContent

from .audit import app_tag, audit
from .auth import Principal, current_principal
from .config import Role
from .drive_client import BotNotConnectedError
from .notion_client import NotionApiError
from .onedrive_client import OneDriveApiError
from .scope import ForbiddenError, InvalidInputError, OutOfScopeError

logger = logging.getLogger(__name__)

# Reading what another person shared with paired assistants. These run as that person's
# guest: read-only, limited to their external list, whatever role this connection has.
GUEST_TOOLS: frozenset[str] = frozenset(
    {
        "list_shared_with_me",
        "search_shared_files",
        "list_shared_folder",
        "read_shared_file",
        "download_shared_file",
    }
)

# Reading the person's own Notion, limited to what they allowed (notion.py). Read-only.
NOTION_TOOLS: frozenset[str] = frozenset({"notion_list_pages", "notion_read_page", "notion_search"})
# Creating a new page under an allowed Notion page (notion.py). Never edits or deletes one.
# Off unless the deployment sets NOTION_ALLOW_CREATE: see OPT_IN_TOOLS below.
NOTION_WRITE_TOOLS: frozenset[str] = frozenset({"notion_create_page"})

# Reading the person's own OneDrive, limited to what they allowed (onedrive.py). Read-only.
ONEDRIVE_TOOLS: frozenset[str] = frozenset(
    {"onedrive_list_folder", "onedrive_read_file", "onedrive_download_file", "onedrive_search"}
)

VIEWER_TOOLS: frozenset[str] = (
    GUEST_TOOLS
    | NOTION_TOOLS
    | ONEDRIVE_TOOLS
    | frozenset(
        {
            "search_files",
            "list_folder",
            "get_metadata",
            "read_file",
            "download_file",
            "export_file",
            "request_access",
            "check_access_request",
            "request_link",
            "list_links",
            "send_message",
            "list_inbox",
            "check_messages",
            "reply",
            "mark_read",
            "get_webhook",
            "set_webhook",
            "clear_webhook",
            # Files paired people sent this human (drops.py), marked untrusted.
            "list_drops",
            "read_drop",
            "download_drop",
        }
    )
)
# Writing into an item another person shared with this person's assistant and marked
# editable. The owner's "edit" setting is checked on the server for every call; the
# assistant's own connection must also be allowed to edit.
GUEST_WRITE_TOOLS: frozenset[str] = frozenset(
    {
        "create_shared_doc",
        "create_shared_folder",
        "upload_shared_file",
        "update_shared_file",
        "rename_shared_file",
    }
)
# A file sent in pieces (uploads.py), and a Google file exported and saved as a new file.
# The same scope checks as upload_file, so the same role.
UPLOAD_TOOLS: frozenset[str] = frozenset(
    {"start_upload", "append_chunk", "finish_upload", "cancel_upload", "save_export"}
)
# Changing the person's own OneDrive, inside what they allowed (onedrive.py). Like the
# Drive writes: only for a connection allowed to edit. Nothing deletes, moves or shares.
ONEDRIVE_WRITE_TOOLS: frozenset[str] = frozenset(
    {
        "onedrive_create_folder",
        "onedrive_upload_file",
        "onedrive_update_file",
        "onedrive_rename_file",
        # A new file sent in pieces; append_chunk and finish_upload are in UPLOAD_TOOLS.
        "onedrive_start_upload",
    }
)
# Sending one file to a paired person (drops.py), and saving one sent to this human into
# their own Drive. Like the writes above, only for a connection allowed to edit.
DROP_TOOLS: frozenset[str] = frozenset({"send_file", "save_drop"})

EDITOR_TOOLS: frozenset[str] = (
    VIEWER_TOOLS
    | GUEST_WRITE_TOOLS
    | DROP_TOOLS
    | UPLOAD_TOOLS
    | ONEDRIVE_WRITE_TOOLS
    | {
        "create_folder",
        "create_doc",
        "upload_file",
        "update_file_content",
        "rename_file",
    }
)
ADMIN_TOOLS: frozenset[str] = EDITOR_TOOLS | {"trash_file"}

ROLE_TOOLS: dict[Role, frozenset[str]] = {
    Role.VIEWER: VIEWER_TOOLS,
    Role.EDITOR: EDITOR_TOOLS,
    Role.ADMIN: ADMIN_TOOLS,
}

ALL_TOOLS = ADMIN_TOOLS

# Parts of a connection the owner can switch off for one app (consent page, Settings).
# "mailbox": messages and pairings between the owner's own assistants, and wake-ups.
# "shared": what paired people share with the owner, and files they send.
FEATURE_TOOLS: dict[str, frozenset[str]] = {
    "mailbox": frozenset(
        {
            "request_link",
            "list_links",
            "send_message",
            "list_inbox",
            "check_messages",
            "reply",
            "mark_read",
            "get_webhook",
            "set_webhook",
            "clear_webhook",
        }
    ),
    "shared": GUEST_TOOLS
    | GUEST_WRITE_TOOLS
    | frozenset({"list_drops", "read_drop", "download_drop", "send_file", "save_drop"}),
}
FEATURES: tuple[str, ...] = tuple(FEATURE_TOOLS)


def tools_off(features: dict[str, bool] | None) -> frozenset[str]:
    """The tools a connection may not call because its owner switched that part off."""
    if not features:
        return frozenset()
    off: frozenset[str] = frozenset()
    for name, tools in FEATURE_TOOLS.items():
        if features.get(name) is False:
            off |= tools
    return off


# What a call made through a named role (agent_roles.py) may use: the tools for this
# person's own Drive files, which the role cuts down to its own items. Everything else
# (the mailbox, pairing, webhooks, access requests, other people's shared files) is not
# part of a role, so a role-limited agent is not offered it.
AGENT_ROLE_TOOLS: frozenset[str] = frozenset(
    {
        "search_files",
        "list_folder",
        "get_metadata",
        "read_file",
        "download_file",
        "create_folder",
        "create_doc",
        "upload_file",
        "update_file_content",
        "rename_file",
        "trash_file",
    }
)

# Tools that are not in the role sets above and exist only when a deployment turns them on
# with a setting; tools/ registers them only then. Until it does, there is no such tool
# to list or call, whatever this says. Like create_doc, they are for connections that may
# edit.
OPT_IN_TOOLS: dict[Role, frozenset[str]] = {
    Role.EDITOR: NOTION_WRITE_TOOLS,
    Role.ADMIN: NOTION_WRITE_TOOLS,
}
_OPT_IN_NAMES: frozenset[str] = frozenset().union(*OPT_IN_TOOLS.values())

# Tools whose result is a new item: its id goes into the audit record.
# Calls that change something, or reach someone, for which every allowed call is kept on
# Activity: they are never folded or counted against the app's hourly row budget, so a
# bot cannot hide them behind a burst of reads (store.records.ActivityLog).
SENDING_TOOLS: frozenset[str] = frozenset(
    {"request_access", "request_link", "send_message", "reply", "set_webhook", "clear_webhook"}
)


def changes_something(tool: str) -> bool:
    return tool != "append_chunk" and (tool not in VIEWER_TOOLS or tool in SENDING_TOOLS)


NEW_ITEM_TOOLS: frozenset[str] = frozenset(
    {"finish_upload", "save_export", "onedrive_create_folder", "onedrive_upload_file"}
)

_AUDITED_ID_ARGS = (
    "file_id",
    "folder_id",
    "parent_id",
    "request_id",
    "owner",
    "page_id",
    "parent_page_id",
    "upload_id",
)

# (file_id, tool, token_name) -> access_required payload; runs in a worker thread.
ScopeDeniedHandler = Callable[[str, str, str | None], dict[str, Any]]

P = ParamSpec("P")
R = TypeVar("R")


# Set by `require` on the wrapper it returns: the tool name whose role it checks. The
# server refuses to register a tool function that does not carry its own name here.
GUARDED_ATTR = "__botrbac_guarded_tool__"


def guarded_tool(fn: object) -> str | None:
    """The tool name `require` checks for this function, or None if it is not wrapped."""
    name = getattr(fn, GUARDED_ATTR, None)
    return name if isinstance(name, str) else None


class PermissionDeniedError(Exception):
    """The caller's role does not include this tool."""


def is_allowed(role: Role | str | None, tool: str) -> bool:
    if role is None:
        return False
    try:
        known = Role(role)
    except ValueError:
        return False
    return tool in ROLE_TOOLS[known] or tool in OPT_IN_TOOLS.get(known, frozenset())


def off_its_role(principal: Principal) -> bool:
    """A connection approved for one named role, on a call not running under that role.
    AgentRoleMiddleware refuses these before any tool; this is the same check again."""
    return principal.bound_role is not None and principal.agent_role != principal.bound_role


def may_call(principal: Principal | None, tool: str) -> bool:
    """The level check, plus the shorter tool list of a call made through a named role."""
    if principal is None or off_its_role(principal):
        return False
    if principal.agent_role is not None and tool not in AGENT_ROLE_TOOLS:
        return False
    if tool in principal.tools_off:
        return False
    return is_allowed(principal.role, tool)


def check_permission(principal: Principal | None, tool: str) -> Principal:
    if principal is None:
        raise PermissionDeniedError("not authenticated")
    if off_its_role(principal):
        raise PermissionDeniedError("this connection only works through its named role")
    if principal.agent_role is not None and tool not in AGENT_ROLE_TOOLS:
        raise PermissionDeniedError(f"'{tool}' is not available through a named role")
    if tool in principal.tools_off:
        raise PermissionDeniedError(
            f"'{tool}' is switched off for this app; its owner can turn it on in Settings"
        )
    if not is_allowed(principal.role, tool):
        raise PermissionDeniedError(f"role '{principal.role}' may not call '{tool}'")
    return principal


class PayloadToolError(ToolError):
    """A tool error with a machine-readable payload (`{"error": code, "message": ...}`).

    `require` turns it into an error result that carries the payload as structuredContent,
    and keeps the text FastMCP always used (`Error executing tool <name>: <json>`), so
    clients that parse the text keep working.
    """

    def __init__(self, payload: dict[str, Any]) -> None:
        super().__init__(json.dumps(payload))
        self.payload = payload


def payload_error_result(tool: str, payload: dict[str, Any]) -> CallToolResult:
    return CallToolResult(
        content=[
            TextContent(type="text", text=f"Error executing tool {tool}: {json.dumps(payload)}")
        ],
        structuredContent=payload,
        isError=True,
    )


def access_required_result(payload: dict[str, Any]) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(payload))],
        structuredContent=payload,
        isError=True,
    )


def require(
    tool: str, *, on_scope_denied: ScopeDeniedHandler | None = None
) -> Callable[[Callable[P, Awaitable[R]]], Callable[P, Awaitable[R]]]:
    """Wrap an async tool: check the caller's role, audit the call, and map errors.

    Role denials are plain errors. Scope denials (OutOfScopeError) become an
    `access_required` tool error with an approval link when `on_scope_denied` is set.
    The wrapper keeps the original signature (via functools.wraps) so FastMCP still
    generates the right input schema.
    """
    if tool not in ALL_TOOLS and tool not in _OPT_IN_NAMES:
        raise ValueError(f"tool {tool!r} is not in the role map")

    def decorator(fn: Callable[P, Awaitable[R]]) -> Callable[P, Awaitable[R]]:
        @functools.wraps(fn)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            principal = current_principal.get()
            ids: dict[str, Any] = {
                k: kwargs.get(k) if isinstance(kwargs.get(k), str) else None
                for k in _AUDITED_ID_ARGS
            }
            who = {
                "token_name": principal.token_name if principal else None,
                "role": str(principal.role) if principal else None,
            }
            if principal and principal.grant_id:
                # Which connection made the call: two apps may register the same name.
                who["app"] = app_tag(principal.grant_id)
            named_role = principal.agent_role if principal else None
            if named_role:
                who["agent_role"] = named_role
            try:
                check_permission(principal, tool)
            except PermissionDeniedError as exc:
                audit(tool=tool, decision="deny", reason=str(exc), **who, **ids)
                raise ToolError(f"Permission denied: {exc}") from None

            try:
                result = await fn(*args, **kwargs)
            except OutOfScopeError as exc:
                audit(tool=tool, decision="deny", reason="out_of_scope", **who, **ids)
                if named_role:
                    # No access request: approving one adds to the allowlist, not to the
                    # role, so the retry would be refused again. The owner edits the role.
                    raise ToolError(
                        f"Forbidden: not available to the role '{named_role}'. "
                        "Its owner chooses the role's files in Bot RBAC Settings."
                    ) from None
                if on_scope_denied is None:
                    raise ToolError(f"Forbidden: {exc}") from None
                try:
                    payload = await anyio.to_thread.run_sync(
                        on_scope_denied, exc.file_id, tool, who["token_name"]
                    )
                except Exception:
                    logger.exception("could not record an access request")
                    raise ToolError(f"Forbidden: {exc}") from None
                return access_required_result(payload)  # type: ignore[return-value]
            except ForbiddenError as exc:
                audit(tool=tool, decision="deny", reason=str(exc), **who, **ids)
                raise ToolError(f"Forbidden: {exc}") from None
            except InvalidInputError as exc:
                audit(tool=tool, decision="error", reason=str(exc), **who, **ids)
                raise ToolError(f"Invalid input: {exc}") from None
            except PayloadToolError as exc:
                reason = str(exc.payload.get("error") or "error")
                audit(tool=tool, decision="error", reason=reason, **who, **ids)
                return payload_error_result(tool, exc.payload)  # type: ignore[return-value]
            except ToolError as exc:
                audit(tool=tool, decision="error", reason=str(exc), **who, **ids)
                raise
            except BotNotConnectedError as exc:
                audit(tool=tool, decision="error", reason="bot_not_connected", **who, **ids)
                raise ToolError(exc.user_message) from None
            except NotionApiError as exc:
                audit(tool=tool, decision="error", reason="notion_error", **who, **ids)
                logger.warning("tool %s: %s", tool, exc)
                if getattr(exc, "code", "") == "validation_error":
                    # On API version 2022-06-28, a database with more than one data source
                    # answers with a validation error.
                    raise ToolError(
                        "Notion refused that request. A database with more than one data "
                        "source can't be read yet."
                    ) from None
                raise ToolError("Notion request failed. Try again in a moment.") from None
            except OneDriveApiError as exc:
                audit(tool=tool, decision="error", reason="onedrive_error", **who, **ids)
                logger.warning("tool %s: %s", tool, exc)
                raise ToolError("OneDrive request failed. Try again in a moment.") from None
            except Exception as exc:
                audit(tool=tool, decision="error", reason=type(exc).__name__, **who, **ids)
                logger.exception("tool %s failed", tool)
                raise ToolError("Drive request failed; see server logs") from None
            if tool == "request_access" and not ids.get("request_id") and isinstance(result, dict):
                # Lets Activity name the row from the request ("asked for … budget sheet").
                rid = result.get("request_id")
                ids["request_id"] = rid if isinstance(rid, str) else None
            if tool in ("start_upload", "onedrive_start_upload") and isinstance(result, dict):
                # Ties the start, the pieces and the finish of one upload together in the log.
                uid = result.get("upload_id")
                ids["upload_id"] = uid if isinstance(uid, str) else None
                if not ids.get("parent_id") and isinstance(result.get("parent_id"), str):
                    ids["parent_id"] = result["parent_id"]
            if tool in NEW_ITEM_TOOLS and isinstance(result, dict):
                # The new file, so Activity can name what was written.
                fid = result.get("id")
                if isinstance(fid, str) and not ids.get("file_id"):
                    ids["file_id"] = fid
            if tool == "notion_create_page" and isinstance(result, dict):
                # The new page, next to the parent it was asked for (parent_page_id).
                pid = result.get("id")
                ids["page_id"] = pid if isinstance(pid, str) else None
            audit(tool=tool, decision="allow", reason="ok", **who, **ids)
            return result

        setattr(wrapper, GUARDED_ATTR, tool)
        return wrapper

    return decorator

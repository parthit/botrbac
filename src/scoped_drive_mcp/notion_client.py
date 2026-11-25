"""Notion's public API: the OAuth exchange and the few read calls Bot RBAC makes.

Connecting Notion is a separate OAuth flow from Google sign-in. Notion shows its own
consent screen, where the person picks which pages Bot RBAC's connection may see. Those
pages are the outer limit. Bot RBAC's own Notion allowlist (chosen on Files) is the inner
limit that assistants are held to.

Only reads are implemented: search, retrieve a page, database or block, list a block's
children and query a database. Nothing here writes to Notion.
"""

import base64
import contextlib
import re
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlencode

import httpx

API_BASE = "https://api.notion.com/v1"
AUTHORIZE_URL = f"{API_BASE}/oauth/authorize"
TOKEN_URL = f"{API_BASE}/oauth/token"
REVOKE_URL = f"{API_BASE}/oauth/revoke"
# Pinned so a Notion change to response shapes cannot change what this code reads.
# Notion still serves 2022-06-28, but on it a database with more than one data source
# answers with a validation error. Moving to 2025-09-03 (data sources) is a follow-up.
NOTION_VERSION = "2022-06-28"

PAGE = "page"
DATABASE = "database"
BLOCK = "block"

_HEX = "[0-9a-fA-F]"
# An id ending the segment, not glued to a hex character before it (a slug's own dash
# before the id is fine: the groups have fixed widths, so slug letters cannot join in).
_DASHED_ID_AT_END = re.compile(
    rf"(?<![0-9a-fA-F])({_HEX}{{8}}-{_HEX}{{4}}-{_HEX}{{4}}-{_HEX}{{4}}-{_HEX}{{12}})$"
)
_HEX32_AT_END = re.compile(rf"(?<![0-9a-fA-F])({_HEX}{{32}})$")


class NotionOAuthError(Exception):
    """The OAuth exchange with Notion failed; the message is safe to show."""


class NotionApiError(Exception):
    """A Notion API call failed."""

    def __init__(self, status: int, code: str = "") -> None:
        super().__init__(f"Notion returned {status} {code}".strip())
        self.status = status
        self.code = code


class NotionNotFoundError(NotionApiError):
    """Not found, or not shared with this connection (Notion answers 404 for both)."""


class NotionForbiddenError(NotionApiError):
    """403 restricted_resource: this connection may not read it."""


class NotionUnauthorizedError(NotionApiError):
    """The access token is no longer valid (revoked in Notion, or expired)."""


def normalize_notion_id(raw: object) -> str | None:
    """A Notion id in its dashed form, from a dashed or undashed id or a Notion URL.

    None when `raw` holds no id. Only an id at the end of the last path segment counts,
    which is where Notion links keep it (`.../My-page-1a2b...`, `.../p/<id>`). The slug
    is never merged into it, so a slug made of hex letters ("Bad-Face") cannot change
    which id is read."""
    if not isinstance(raw, str) or len(raw) > 500:
        return None
    text = raw.strip().split("?", 1)[0].split("#", 1)[0].rstrip("/")
    segment = text.rsplit("/", 1)[-1]
    match = _DASHED_ID_AT_END.search(segment) or _HEX32_AT_END.search(segment)
    if not match:
        return None
    h = match.group(1).replace("-", "").lower()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


@dataclass(frozen=True)
class NotionTokens:
    access_token: str
    refresh_token: str | None
    workspace_id: str
    workspace_name: str
    bot_id: str


class NotionOAuth:
    """Notion's authorization-code flow for a public connection."""

    def __init__(
        self, client_id: str, client_secret: str, redirect_uri: str, timeout: float = 15
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.timeout = timeout

    def _basic(self) -> str:
        pair = f"{self.client_id}:{self.client_secret}".encode()
        return "Basic " + base64.b64encode(pair).decode()

    def authorization_url(self, state: str) -> str:
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "owner": "user",
            "redirect_uri": self.redirect_uri,
            "state": state,
        }
        return f"{AUTHORIZE_URL}?{urlencode(params)}"

    def _token_call(self, body: dict[str, str]) -> NotionTokens:
        try:
            resp = httpx.post(
                TOKEN_URL,
                json=body,
                headers={
                    "Authorization": self._basic(),
                    "Notion-Version": NOTION_VERSION,
                    "Content-Type": "application/json",
                },
                timeout=self.timeout,
            )
        except httpx.HTTPError:
            raise NotionOAuthError("could not reach Notion") from None
        if resp.status_code != 200:
            raise NotionOAuthError("Notion rejected the connection code")
        try:
            data = resp.json()
            token = data["access_token"]
            if not isinstance(token, str) or not token:
                raise ValueError
            refresh = data.get("refresh_token")
            return NotionTokens(
                access_token=token,
                refresh_token=refresh if isinstance(refresh, str) and refresh else None,
                workspace_id=str(data.get("workspace_id") or ""),
                workspace_name=str(data.get("workspace_name") or "")[:200],
                bot_id=str(data.get("bot_id") or ""),
            )
        except (ValueError, KeyError, TypeError, AttributeError):
            raise NotionOAuthError("Notion returned an unexpected response") from None

    def exchange_code(self, code: str) -> NotionTokens:
        return self._token_call(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.redirect_uri,
            }
        )

    def refresh(self, refresh_token: str) -> NotionTokens:
        return self._token_call({"grant_type": "refresh_token", "refresh_token": refresh_token})

    def revoke(self, token: str) -> bool:
        """Ask Notion to end this token (one token per call). True when Notion confirms, or
        says the token is already invalid. False when Notion could not be reached or
        refused, so the caller can tell the person to remove the connection in Notion."""
        try:
            resp = httpx.post(
                REVOKE_URL,
                json={"token": token},
                headers={
                    "Authorization": self._basic(),
                    "Notion-Version": NOTION_VERSION,
                    "Content-Type": "application/json",
                },
                timeout=self.timeout,
            )
        except httpx.HTTPError:
            return False
        if resp.status_code == 200:
            return True
        # 400 invalid_grant: the token is already invalid, so it is gone either way.
        # 401 is invalid_client (wrong client id or secret): nothing was revoked.
        if resp.status_code == 400:
            with contextlib.suppress(ValueError, AttributeError):
                return resp.json().get("code") == "invalid_grant"
        return False


class NotionApi(Protocol):
    def search(
        self, query: str, cursor: str | None = None, page_size: int = 100
    ) -> dict[str, Any]: ...
    def get_page(self, page_id: str) -> dict[str, Any]: ...
    def get_database(self, database_id: str) -> dict[str, Any]: ...
    def get_block(self, block_id: str) -> dict[str, Any]: ...
    def block_children(self, block_id: str, cursor: str | None = None) -> dict[str, Any]: ...
    def query_database(self, database_id: str, cursor: str | None = None) -> dict[str, Any]: ...


class HttpNotionApi:
    """Notion's REST API with one access token."""

    def __init__(self, access_token: str, timeout: float = 20) -> None:
        self._client = httpx.Client(
            base_url=API_BASE,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Notion-Version": NOTION_VERSION,
                "Content-Type": "application/json",
            },
            timeout=timeout,
        )

    def close(self) -> None:
        self._client.close()

    def _call(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        # Every failure is a NotionApiError, which the tools and the dashboard report as
        # "Notion didn't answer"; a raw network error would surface as a 500.
        try:
            resp = self._client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise NotionApiError(0, "unreachable") from exc
        if resp.status_code == 200:
            try:
                data = resp.json()
            except ValueError:
                raise NotionApiError(200, "bad_response") from None
            if not isinstance(data, dict):
                raise NotionApiError(resp.status_code, "bad_response")
            return data
        code = ""
        with contextlib.suppress(ValueError, AttributeError):
            code = str(resp.json().get("code") or "")
        if resp.status_code == 404:
            raise NotionNotFoundError(404, code)
        if resp.status_code == 401:
            raise NotionUnauthorizedError(401, code)
        if resp.status_code == 403:
            raise NotionForbiddenError(403, code)
        raise NotionApiError(resp.status_code, code)

    def search(self, query: str, cursor: str | None = None, page_size: int = 100) -> dict[str, Any]:
        body: dict[str, Any] = {"page_size": max(1, min(page_size, 100))}
        if query:
            body["query"] = query
        if cursor:
            body["start_cursor"] = cursor
        return self._call("POST", "/search", json=body)

    def get_page(self, page_id: str) -> dict[str, Any]:
        return self._call("GET", f"/pages/{page_id}")

    def get_database(self, database_id: str) -> dict[str, Any]:
        return self._call("GET", f"/databases/{database_id}")

    def get_block(self, block_id: str) -> dict[str, Any]:
        return self._call("GET", f"/blocks/{block_id}")

    def block_children(self, block_id: str, cursor: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {"page_size": 100}
        if cursor:
            params["start_cursor"] = cursor
        return self._call("GET", f"/blocks/{block_id}/children", params=params)

    def query_database(self, database_id: str, cursor: str | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"page_size": 100}
        if cursor:
            body["start_cursor"] = cursor
        return self._call("POST", f"/databases/{database_id}/query", json=body)


# ---- reading Notion objects ------------------------------------------------------


def plain(rich: object) -> str:
    """The plain text of a rich-text array."""
    if not isinstance(rich, list):
        return ""
    return "".join(str(r.get("plain_text") or "") for r in rich if isinstance(r, dict))


def title_of(obj: dict[str, Any]) -> str:
    """A page's or database's title, or "Untitled"."""
    if obj.get("object") == DATABASE:
        text = plain(obj.get("title"))
    else:
        text = ""
        props = obj.get("properties")
        if isinstance(props, dict):
            for prop in props.values():
                if isinstance(prop, dict) and prop.get("type") == "title":
                    text = plain(prop.get("title"))
                    break
    return text.strip() or "Untitled"


def parent_of(obj: dict[str, Any]) -> tuple[str, str] | None:
    """(kind, id) of an object's parent, or None at the top of the workspace."""
    parent = obj.get("parent")
    if not isinstance(parent, dict):
        return None
    kind = parent.get("type")
    if kind == "page_id":
        return PAGE, str(parent.get("page_id") or "")
    if kind == "database_id":
        return DATABASE, str(parent.get("database_id") or "")
    if kind == "block_id":
        return BLOCK, str(parent.get("block_id") or "")
    # "workspace", or a kind this version does not know: nothing above it to check.
    return None


_PREFIX = {
    "heading_1": "# ",
    "heading_2": "## ",
    "heading_3": "### ",
    "bulleted_list_item": "- ",
    "numbered_list_item": "1. ",
    "quote": "> ",
    "callout": "> ",
    "toggle": "▸ ",
}


def block_line(block: dict[str, Any]) -> str | None:
    """One block as a line of Markdown-like text. None for blocks with no text."""
    kind = str(block.get("type") or "")
    body = block.get(kind)
    if not isinstance(body, dict):
        body = {}
    if kind == "child_page":
        return f"[page] {body.get('title') or 'Untitled'} (id {block.get('id')})"
    if kind == "child_database":
        return f"[database] {body.get('title') or 'Untitled'} (id {block.get('id')})"
    if kind == "divider":
        return "---"
    if kind == "equation":
        return str(body.get("expression") or "")
    if kind in ("bookmark", "embed", "link_preview"):
        url = body.get("url")
        return f"<{url}>" if url else None
    text = plain(body.get("rich_text"))
    if kind == "to_do":
        return f"[{'x' if body.get('checked') else ' '}] {text}"
    if kind == "code":
        return f"```{body.get('language') or ''}\n{text}\n```"
    if kind in _PREFIX:
        return _PREFIX[kind] + text
    if kind == "table_row":
        cells = body.get("cells")
        if isinstance(cells, list):
            return " | ".join(plain(c) for c in cells)
        return None
    return text or None


def property_text(prop: dict[str, Any]) -> str:
    """A database row's property value as short text."""
    kind = prop.get("type")
    value = prop.get(kind) if isinstance(kind, str) else None
    if kind in ("title", "rich_text"):
        return plain(value)
    if kind in ("select", "status") and isinstance(value, dict):
        return str(value.get("name") or "")
    if kind == "multi_select" and isinstance(value, list):
        return ", ".join(str(v["name"]) for v in value if isinstance(v, dict) and v.get("name"))
    if kind == "date" and isinstance(value, dict):
        start, end = value.get("start"), value.get("end")
        return f"{start} → {end}" if end else str(start or "")
    if kind == "checkbox":
        return "yes" if value else "no"
    if kind in ("number", "url", "email", "phone_number") and value is not None:
        return str(value)
    if kind == "people" and isinstance(value, list):
        # A person Notion won't name (a bot, or someone who left) is left out, not "Ada, ".
        return ", ".join(str(p["name"]) for p in value if isinstance(p, dict) and p.get("name"))
    if kind == "formula" and isinstance(value, dict):
        inner = value.get(value.get("type")) if isinstance(value.get("type"), str) else None
        return "" if inner is None else str(inner)
    return ""

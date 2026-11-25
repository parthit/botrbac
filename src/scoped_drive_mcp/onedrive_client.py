"""Microsoft OneDrive: the OAuth exchange and the few read calls Bot RBAC makes.

Connecting OneDrive is a separate OAuth flow from Google sign-in, run by the Microsoft
identity platform (the `common` endpoint, so personal Microsoft accounts and work or
school accounts both work). Bot RBAC asks for `Files.Read` (read the person's own
files), `User.Read` (their name, to show which account is connected) and
`offline_access` (a refresh token). A token that carries anything wider is refused and
not stored.

`Files.Read` lets this server read the whole of the person's own OneDrive. Microsoft has
no per-file consent for personal accounts, so Bot RBAC's OneDrive allowlist (chosen on
Files) is what holds assistants to the items the person picked.

Only reads are implemented: get an item, list a folder, search, and download a file's
bytes. Nothing here writes to OneDrive.
"""

import contextlib
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import quote, urlencode, urlsplit

import httpx

AUTHORITY = "https://login.microsoftonline.com/common/oauth2/v2.0"
AUTHORIZE_URL = f"{AUTHORITY}/authorize"
TOKEN_URL = f"{AUTHORITY}/token"
GRAPH = "https://graph.microsoft.com/v1.0"

# Requested on the consent screen. Short names; Microsoft may answer with full URIs.
SCOPES = ("Files.Read", "User.Read", "offline_access")
REQUIRED_SCOPE = "files.read"
# Anything outside this set on a token means it can do more than Bot RBAC asked for (an
# organization admin may have granted the app wider access): it is refused.
ALLOWED_SCOPES = frozenset(
    {"files.read", "user.read", "offline_access", "openid", "profile", "email"}
)
_SCOPE_PREFIXES = ("https://graph.microsoft.com/", "00000003-0000-0000-c000-000000000000/")

# What an item lookup asks Graph for.
ITEM_FIELDS = (
    "id,name,size,file,folder,package,remoteItem,root,deleted,parentReference,webUrl,"
    "lastModifiedDateTime"
)
# OneDrive item ids: personal accounts use "HEX!123" (and some newer forms with other
# letters), work and school accounts a 34-character base32-like string. Never "/", "?",
# "#", "%", spaces or quotes, and at least one letter or digit (so never "." or "..", which
# an HTTP client would treat as a path step), so an id can be put into a Graph path as it is.
_ITEM_ID = re.compile(r"^(?=.*[A-Za-z0-9])[A-Za-z0-9!._\-]{1,256}$")
# Redirects a download may follow after Graph's own redirect.
MAX_DOWNLOAD_REDIRECTS = 3


class OneDriveOAuthError(Exception):
    """The OAuth exchange with Microsoft failed; the message is safe to show."""


class OneDriveOAuthUnavailableError(OneDriveOAuthError):
    """Microsoft could not be reached, or answered with a server error. Trying again later
    may work; the connection itself may be fine."""


class OneDriveApiError(Exception):
    """A Microsoft Graph call failed."""

    def __init__(self, status: int, code: str = "") -> None:
        super().__init__(f"Microsoft Graph returned {status} {code}".strip())
        self.status = status
        self.code = code


class OneDriveNotFoundError(OneDriveApiError):
    """No such item (or not in this person's drive)."""


class OneDriveForbiddenError(OneDriveApiError):
    """403: this token may not read it."""


class OneDriveUnauthorizedError(OneDriveApiError):
    """The access token is no longer valid (expired or revoked)."""


def normalize_item_id(raw: object) -> str | None:
    """A OneDrive item id, or None when `raw` is not shaped like one."""
    if not isinstance(raw, str):
        return None
    value = raw.strip()
    return value if _ITEM_ID.match(value) else None


def normalize_scopes(granted: Iterable[str]) -> set[str]:
    """Scope names in lower case, without Graph's resource prefix."""
    out: set[str] = set()
    for scope in granted:
        s = scope.strip().lower()
        for prefix in _SCOPE_PREFIXES:
            if s.startswith(prefix):
                s = s[len(prefix) :]
        if s:
            out.add(s)
    return out


def scopes_acceptable(granted: Iterable[str]) -> bool:
    """True when the token can read files and nothing beyond what Bot RBAC asked for."""
    names = normalize_scopes(granted)
    return REQUIRED_SCOPE in names and names <= ALLOWED_SCOPES


@dataclass(frozen=True)
class OneDriveTokens:
    access_token: str
    refresh_token: str | None
    expires_at: float
    scopes: tuple[str, ...]


@dataclass(frozen=True)
class OneDriveAccount:
    drive_id: str
    drive_type: str
    name: str


class OneDriveOAuth:
    """Microsoft's authorization-code flow for a web app with a client secret."""

    def __init__(
        self, client_id: str, client_secret: str, redirect_uri: str, timeout: float = 15
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.timeout = timeout

    def authorization_url(self, state: str) -> str:
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "response_mode": "query",
            "scope": " ".join(SCOPES),
            "state": state,
            # Let the person choose the account instead of silently using the one the
            # browser is signed in with.
            "prompt": "select_account",
        }
        return f"{AUTHORIZE_URL}?{urlencode(params)}"

    def _token_call(self, body: dict[str, str]) -> OneDriveTokens:
        form = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": " ".join(SCOPES),
            **body,
        }
        try:
            resp = httpx.post(TOKEN_URL, data=form, timeout=self.timeout)
        except httpx.HTTPError:
            raise OneDriveOAuthUnavailableError("could not reach Microsoft") from None
        if resp.status_code >= 500 or resp.status_code == 429:
            raise OneDriveOAuthUnavailableError("Microsoft is not answering right now")
        if resp.status_code != 200:
            raise OneDriveOAuthError("Microsoft rejected the connection code")
        try:
            data = resp.json()
            token = data["access_token"]
            if not isinstance(token, str) or not token:
                raise ValueError
            refresh = data.get("refresh_token")
            expires_in = int(data.get("expires_in") or 3600)
            scope = str(data.get("scope") or "")
            return OneDriveTokens(
                access_token=token,
                refresh_token=refresh if isinstance(refresh, str) and refresh else None,
                # A minute early, so a call does not start with a token about to expire.
                expires_at=time.time() + max(60, expires_in) - 60,
                scopes=tuple(scope.split()),
            )
        except (ValueError, KeyError, TypeError, AttributeError):
            raise OneDriveOAuthError("Microsoft returned an unexpected response") from None

    def exchange_code(self, code: str) -> OneDriveTokens:
        return self._token_call(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.redirect_uri,
            }
        )

    def refresh(self, refresh_token: str) -> OneDriveTokens:
        return self._token_call({"grant_type": "refresh_token", "refresh_token": refresh_token})


class OneDriveApi(Protocol):
    def account(self) -> OneDriveAccount: ...
    def get_item(self, item_id: str) -> dict[str, Any]: ...
    def children(self, item_id: str | None, cursor: str | None = None) -> dict[str, Any]: ...
    def search(self, query: str, cursor: str | None = None) -> dict[str, Any]: ...
    def download(self, item_id: str, limit: int) -> bytes: ...


class HttpOneDriveApi:
    """Microsoft Graph with one access token, limited to the signed-in person's drive."""

    def __init__(
        self,
        access_token: str,
        timeout: float = 20,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        # `transport` is for tests; it is used for Graph and for download addresses.
        self._client = httpx.Client(
            base_url=GRAPH,
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            timeout=timeout,
            transport=transport,
        )
        self._timeout = timeout
        self._transport = transport

    def close(self) -> None:
        self._client.close()

    @staticmethod
    def _raise(resp: httpx.Response) -> None:
        code = ""
        with contextlib.suppress(ValueError, AttributeError, TypeError):
            code = str(resp.json().get("error", {}).get("code") or "")
        if resp.status_code == 404:
            raise OneDriveNotFoundError(404, code)
        if resp.status_code == 401:
            raise OneDriveUnauthorizedError(401, code)
        if resp.status_code == 403:
            raise OneDriveForbiddenError(403, code)
        raise OneDriveApiError(resp.status_code, code)

    def _get(self, path_or_url: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            resp = self._client.get(path_or_url, params=params)
        except httpx.HTTPError:
            raise OneDriveApiError(0, "unreachable") from None
        if resp.status_code != 200:
            self._raise(resp)
        try:
            data = resp.json()
        except ValueError:
            raise OneDriveApiError(resp.status_code, "bad_response") from None
        if not isinstance(data, dict):
            raise OneDriveApiError(resp.status_code, "bad_response")
        return data

    def _page(self, path: str, params: dict[str, Any], cursor: str | None) -> dict[str, Any]:
        """One page of a list. `cursor` is Graph's @odata.nextLink, which is only followed
        when it points back at Graph (the access token is sent with it)."""
        if cursor:
            if not cursor.startswith(GRAPH + "/"):
                raise OneDriveApiError(0, "bad_next_link")
            return self._get(cursor)
        return self._get(path, params)

    def account(self) -> OneDriveAccount:
        drive = self._get("/me/drive", {"$select": "id,driveType,owner"})
        owner = (drive.get("owner") or {}).get("user") or {}
        name = str(owner.get("displayName") or "")
        with contextlib.suppress(OneDriveApiError):
            me = self._get("/me", {"$select": "displayName,userPrincipalName,mail"})
            email = me.get("mail") or me.get("userPrincipalName")
            name = str(email or me.get("displayName") or name)
        return OneDriveAccount(
            drive_id=str(drive.get("id") or ""),
            drive_type=str(drive.get("driveType") or ""),
            name=name[:200],
        )

    def get_item(self, item_id: str) -> dict[str, Any]:
        return self._get(f"/me/drive/items/{item_id}", {"$select": ITEM_FIELDS})

    def children(self, item_id: str | None, cursor: str | None = None) -> dict[str, Any]:
        path = f"/me/drive/items/{item_id}/children" if item_id else "/me/drive/root/children"
        return self._page(path, {"$top": 200, "$select": ITEM_FIELDS}, cursor)

    def search(
        self, query: str, cursor: str | None = None, folder_id: str | None = None
    ) -> dict[str, Any]:
        """Microsoft's search: inside one folder, or the whole drive with no `folder_id`
        (the dashboard, for the person themselves; never for an assistant)."""
        # The query sits inside a quoted OData string: a quote is doubled, then the whole
        # thing is percent-encoded so it cannot change the path.
        q = quote(query.replace("'", "''"), safe="")
        where = f"items/{folder_id}" if folder_id else "root"
        return self._page(f"/me/drive/{where}/search(q='{q}')", {"$top": 100}, cursor)

    def download(self, item_id: str, limit: int) -> bytes:
        """Up to `limit` bytes of a file. Graph answers with a redirect to a short-lived,
        pre-authorized download address; that address is fetched without the token, with
        a capped number of further redirects. Bodies are streamed and cut at `limit`."""
        try:
            return self._download(item_id, limit)
        except httpx.TooManyRedirects:
            raise OneDriveApiError(0, "too_many_redirects") from None
        except httpx.HTTPError:
            raise OneDriveApiError(0, "unreachable") from None

    def _download(self, item_id: str, limit: int) -> bytes:
        path = f"/me/drive/items/{item_id}/content"
        with self._client.stream("GET", path, follow_redirects=False) as resp:
            if resp.status_code == 200:
                return _read_capped(resp, limit)
            if resp.status_code not in (301, 302, 303, 307, 308):
                resp.read()
                self._raise(resp)
            location = resp.headers.get("location") or ""
        if urlsplit(location).scheme != "https":
            raise OneDriveApiError(302, "bad_download_url")
        with (
            httpx.Client(
                timeout=self._timeout,
                follow_redirects=True,
                max_redirects=MAX_DOWNLOAD_REDIRECTS,
                transport=self._transport,
                # Every hop, not only the first, must stay on https.
                event_hooks={"request": [_https_only]},
            ) as plain,
            plain.stream("GET", location) as body,
        ):
            if body.status_code != 200:
                raise OneDriveApiError(body.status_code, "download_failed")
            return _read_capped(body, limit)


def _https_only(request: httpx.Request) -> None:
    if request.url.scheme != "https":
        raise OneDriveApiError(0, "bad_download_url")


def _read_capped(resp: httpx.Response, limit: int) -> bytes:
    out = bytearray()
    for chunk in resp.iter_bytes():
        out.extend(chunk)
        if len(out) >= limit:
            break
    return bytes(out[:limit])


# ---- reading OneDrive items ----------------------------------------------------------

FOLDER = "folder"
FILE = "file"
PACKAGE = "package"


def kind_of(item: dict[str, Any]) -> str:
    if isinstance(item.get("folder"), dict):
        return FOLDER
    if isinstance(item.get("package"), dict):
        # A OneNote notebook and similar: a bundle with no single body to read.
        return PACKAGE
    return FILE


def parent_id_of(item: dict[str, Any]) -> str | None:
    ref = item.get("parentReference")
    if not isinstance(ref, dict):
        return None
    value = ref.get("id")
    return value if isinstance(value, str) and value else None


def mime_of(item: dict[str, Any]) -> str:
    kind = kind_of(item)
    if kind == FOLDER:
        return "onedrive/folder"
    if kind == PACKAGE:
        return "onedrive/package"
    file = item.get("file")
    mime = file.get("mimeType") if isinstance(file, dict) else None
    return str(mime or "application/octet-stream")

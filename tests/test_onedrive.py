"""OneDrive: an optional connection with Microsoft's OAuth, its own allowlist and
read-only tools."""

import io
import time
import zipfile
from urllib.parse import parse_qs, urlparse

import pytest

from scoped_drive_mcp.onedrive_client import (
    OneDriveAccount,
    OneDriveNotFoundError,
    OneDriveOAuthError,
    OneDriveTokens,
    OneDriveUnauthorizedError,
    normalize_item_id,
    scopes_acceptable,
)
from scoped_drive_mcp.server import build_app
from scoped_drive_mcp.store import KEY_PREFIX, ONEDRIVE_ALLOWLIST_KEY, ONEDRIVE_TOKEN_KEY
from tests.conftest import OWNER_EMAIL, TOKENS, make_settings
from tests.dash import MCP_HEADERS, client, csrf, login, mcp_call

ROOT = "D00D!101"  # the top of the drive
SCHOOL = "D00D!102"  # folder at the top
ESSAY = "D00D!103"  # text file in SCHOOL
SUB = "D00D!104"  # folder in SCHOOL
NOTES = "D00D!105"  # Markdown file in SUB
DIARY = "D00D!106"  # file at the top, never allowed
SHORTCUT = "D00D!107"  # "Add to my files" shortcut to someone else's folder
REPORT = "D00D!108"  # Word file in SCHOOL
PHOTO = "D00D!109"  # image in SCHOOL


def docx_bytes(text: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/'
            '2006/content-types"><Override PartName="/word/document.xml" ContentType="'
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"'
            "/></Types>",
        )
        z.writestr(
            "word/document.xml",
            '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/'
            f'wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p>'
            "</w:body></w:document>",
        )
    return buf.getvalue()


def item(iid: str, name: str, parent: str | None, *, folder=False, mime=None, **extra) -> dict:
    out: dict = {
        "id": iid,
        "name": name,
        "lastModifiedDateTime": "2026-11-20T10:00:00Z",
        "webUrl": f"https://onedrive.live.com/?id={iid}",
    }
    if parent:
        out["parentReference"] = {
            "id": parent,
            "path": "/drive/root:" if parent == ROOT else f"/drive/root:/{parent}",
        }
    if folder:
        out["folder"] = {"childCount": 0}
    else:
        out["file"] = {"mimeType": mime or "application/octet-stream"}
        out["size"] = 10
    out.update(extra)
    return out


class FakeOneDrive:
    """One person's drive. `tokens` are the access tokens Graph accepts."""

    def __init__(self) -> None:
        self.items = {
            ROOT: {"id": ROOT, "name": "root", "root": {}, "folder": {"childCount": 3}},
            SCHOOL: item(SCHOOL, "School", ROOT, folder=True),
            ESSAY: item(ESSAY, "essay.txt", SCHOOL, mime="text/plain"),
            SUB: item(SUB, "Biology", SCHOOL, folder=True),
            NOTES: item(NOTES, "cells.md", SUB, mime="text/markdown"),
            DIARY: item(DIARY, "diary.txt", ROOT, mime="text/plain"),
            SHORTCUT: item(SHORTCUT, "Group project", ROOT, folder=True, remoteItem={"id": "X!1"}),
            REPORT: item(
                REPORT,
                "report.docx",
                SCHOOL,
                mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ),
            PHOTO: item(PHOTO, "photo.jpg", SCHOOL, mime="image/jpeg"),
        }
        self.content = {
            ESSAY: b"my essay about rivers",
            NOTES: b"# Cells\nmitochondria",
            DIARY: b"dear diary",
            REPORT: docx_bytes("lab report text"),
            PHOTO: b"\xff\xd8\xff\xe0jpegbytes",
        }
        self.tokens = {"ms-access-1"}
        self.calls: list[tuple[str, str | None]] = []
        self.drive_id = "drive-1"

    def factory(self, token: str) -> "FakeOneDriveApi":
        return FakeOneDriveApi(self, token)


class FakeOneDriveApi:
    def __init__(self, world: FakeOneDrive, token: str) -> None:
        self.world = world
        self.token = token

    def _check(self, what: str, iid: str | None) -> None:
        self.world.calls.append((what, iid))
        if self.token not in self.world.tokens:
            raise OneDriveUnauthorizedError(401, "InvalidAuthenticationToken")

    def account(self) -> OneDriveAccount:
        self._check("account", None)
        return OneDriveAccount(self.world.drive_id, "personal", "student@outlook.com")

    def get_item(self, item_id: str) -> dict:
        self._check("get_item", item_id)
        if item_id not in self.world.items:
            raise OneDriveNotFoundError(404, "itemNotFound")
        return dict(self.world.items[item_id])

    def children(self, item_id: str | None, cursor: str | None = None) -> dict:
        self._check("children", item_id)
        parent = item_id or ROOT
        return {
            "value": [
                dict(i)
                for i in self.world.items.values()
                if (i.get("parentReference") or {}).get("id") == parent
            ]
        }

    def search(self, query: str, cursor: str | None = None) -> dict:
        self._check("search", query)
        q = query.lower()
        return {
            "value": [
                dict(i)
                for i in self.world.items.values()
                if "root" not in i
                and (
                    q in i["name"].lower()
                    or q in self.world.content.get(i["id"], b"").decode("latin-1")
                )
            ]
        }

    def download(self, item_id: str, limit: int) -> bytes:
        self._check("download", item_id)
        return self.world.content.get(item_id, b"")[:limit]


class FakeOneDriveOAuth:
    def __init__(self, world: FakeOneDrive) -> None:
        self.world = world
        self.states: list[str] = []
        self.refreshed: list[str] = []
        self.scopes: tuple[str, ...] = ("Files.Read", "User.Read", "offline_access")
        self.expires_in = 3600

    def authorization_url(self, state: str) -> str:
        self.states.append(state)
        return f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?state={state}"

    def exchange_code(self, code: str) -> OneDriveTokens:
        if code != "ms-code":
            raise OneDriveOAuthError("Microsoft rejected the connection code")
        return OneDriveTokens(
            "ms-access-1", "ms-refresh-1", time.time() + self.expires_in, self.scopes
        )

    def refresh(self, refresh_token: str) -> OneDriveTokens:
        self.refreshed.append(refresh_token)
        self.world.tokens.add("ms-access-2")
        return OneDriveTokens("ms-access-2", "ms-refresh-2", time.time() + 3600, self.scopes)


@pytest.fixture
def drive() -> FakeOneDrive:
    return FakeOneDrive()


@pytest.fixture
def ms_oauth(drive) -> FakeOneDriveOAuth:
    return FakeOneDriveOAuth(drive)


@pytest.fixture
def app(world, p2_settings, memstore, oauth, drive, ms_oauth):
    return build_app(
        p2_settings,
        world.as_user(OWNER_EMAIL),
        store=memstore,
        owner_drive_factory=lambda token: world.as_user(OWNER_EMAIL),
        oauth=oauth,
        onedrive_api_factory=drive.factory,
        onedrive_oauth=ms_oauth,
    )


@pytest.fixture
def c(app):
    c = client(app)
    login(c)
    return c


def start_connect(c) -> str:
    token = csrf(c, "/settings")
    r = c.post("/connect/onedrive", data={"csrf": token, "next": "/settings"})
    assert r.status_code == 303, r.text
    assert r.headers["location"].startswith("https://login.microsoftonline.com/")
    return parse_qs(urlparse(r.headers["location"]).query)["state"][0]


def connect(c, code: str = "ms-code"):
    state = start_connect(c)
    return c.get("/connect/onedrive/callback", params={"code": code, "state": state})


def allow(c, item_id: str, folder: str | None = None):
    token = csrf(c, "/files?tab=onedrive")
    data = {"csrf": token, "file_id": item_id}
    if folder:
        data["folder"] = folder
    return c.post("/onedrive/allow", data=data)


def result(c, tool: str, **args) -> dict:
    return mcp_call(c, tool, **args)


def stored_allowlist(memstore) -> dict:
    return memstore.hgetall(f"{KEY_PREFIX}{ONEDRIVE_ALLOWLIST_KEY}")


ONEDRIVE_TOOLS = {
    "onedrive_list_folder",
    "onedrive_read_file",
    "onedrive_download_file",
    "onedrive_search",
}


# ---- configuration -----------------------------------------------------------------


def test_onedrive_is_hidden_when_not_configured(world, p2_settings, memstore, oauth) -> None:
    app = build_app(
        p2_settings,
        world.as_user(OWNER_EMAIL),
        store=memstore,
        owner_drive_factory=lambda token: world.as_user(OWNER_EMAIL),
        oauth=oauth,
    )
    c = client(app)
    login(c)
    assert 'id="connection-onedrive"' not in c.get("/settings").text
    assert "From OneDrive" not in c.get("/files").text
    token = csrf(c, "/settings")
    assert c.post("/connect/onedrive", data={"csrf": token}).status_code == 404
    listed = c.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={**MCP_HEADERS, "Authorization": f"Bearer {TOKENS['viewer']}"},
    )
    names = {t["name"] for t in listed.json()["result"]["tools"]}
    assert not names & ONEDRIVE_TOOLS


def test_placeholder_secret_does_not_turn_onedrive_on() -> None:
    s = make_settings(
        onedrive_oauth_client_id="11111111-2222-3333-4444-555555555555",
        onedrive_oauth_client_secret="REPLACE_WITH_SECRET",
    )
    assert not s.onedrive_configured
    s = make_settings(
        onedrive_oauth_client_id="11111111-2222-3333-4444-555555555555",
        onedrive_oauth_client_secret="real~secret",
    )
    assert s.onedrive_configured


def test_tools_are_listed_and_read_only_when_configured(c) -> None:
    listed = c.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={**MCP_HEADERS, "Authorization": f"Bearer {TOKENS['viewer']}"},
    )
    tools = {t["name"]: t for t in listed.json()["result"]["tools"]}
    assert ONEDRIVE_TOOLS <= set(tools)
    for name in ONEDRIVE_TOOLS:
        assert tools[name]["annotations"]["readOnlyHint"] is True


def test_item_ids_and_scopes() -> None:
    assert normalize_item_id(" D00D!101 ") == "D00D!101"
    assert normalize_item_id("01ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") is not None
    for bad in ("", "a/b", "../x", "a?b", "a b", "a'b", "a%2Fb", None, 5):
        assert normalize_item_id(bad) is None
    assert scopes_acceptable(["Files.Read", "User.Read", "offline_access"])
    assert scopes_acceptable(
        ["https://graph.microsoft.com/Files.Read", "https://graph.microsoft.com/User.Read"]
    )
    assert not scopes_acceptable(["User.Read"])  # cannot read files
    assert not scopes_acceptable(["Files.Read", "Files.ReadWrite.All"])  # wider than asked
    assert not scopes_acceptable(["Files.Read", "Mail.Read"])


def test_connect_form_may_redirect_to_microsoft() -> None:
    from scoped_drive_mcp.dashboard import STRICT_CSP

    assert b"https://login.microsoftonline.com" in STRICT_CSP


# ---- connecting ----------------------------------------------------------------------


def test_connect_stores_an_encrypted_token_and_shows_the_account(c, memstore) -> None:
    r = connect(c)
    assert r.status_code == 303
    assert r.headers["location"] == "/files?tab=onedrive"
    raw = memstore.get(f"{KEY_PREFIX}{ONEDRIVE_TOKEN_KEY}") or ""
    assert raw and "ms-access-1" not in raw and "ms-refresh-1" not in raw
    page = c.get("/settings").text
    assert 'id="connection-onedrive"' in page
    assert "Account: student@outlook.com" in page


def test_connect_needs_a_matching_state(c, ms_oauth) -> None:
    start_connect(c)
    r = c.get("/connect/onedrive/callback", params={"code": "ms-code", "state": "forged"})
    assert r.status_code == 400
    # The real state was spent with the nonce on the failed try.
    r = c.get(
        "/connect/onedrive/callback", params={"code": "ms-code", "state": ms_oauth.states[-1]}
    )
    assert r.status_code == 400


def test_state_from_another_account_is_refused(app, c, ms_oauth, memstore) -> None:
    start_connect(c)
    owner_state = ms_oauth.states[-1]
    other = client(app)
    login(other, "eve-code")
    start_connect(other)
    r = other.get("/connect/onedrive/callback", params={"code": "ms-code", "state": owner_state})
    assert r.status_code == 400


def test_a_token_with_wider_access_is_refused(c, ms_oauth, memstore) -> None:
    ms_oauth.scopes = ("Files.Read", "Files.ReadWrite.All", "offline_access")
    r = connect(c)
    assert r.status_code == 400
    assert memstore.get(f"{KEY_PREFIX}{ONEDRIVE_TOKEN_KEY}") is None
    assert "different access" in r.text


def test_cancel_and_admin_consent_messages(c) -> None:
    start_connect(c)
    r = c.get("/connect/onedrive/callback", params={"error": "access_denied", "state": "x"})
    assert r.status_code == 400
    assert "You didn’t connect OneDrive" in r.text
    start_connect(c)
    r = c.get(
        "/connect/onedrive/callback",
        params={
            "error": "access_denied",
            "error_description": "AADSTS90094: Admin consent is required.",
            "state": "x",
        },
    )
    assert "IT administrator" in r.text


def test_callback_needs_a_signed_in_owner(app) -> None:
    anon = client(app)
    r = anon.get("/connect/onedrive/callback", params={"code": "ms-code", "state": "x"})
    assert r.status_code in (302, 303, 401, 403)


def test_disconnect_removes_the_token_and_the_list(c, memstore) -> None:
    connect(c)
    allow(c, SCHOOL)
    assert stored_allowlist(memstore)
    token = csrf(c, "/settings")
    r = c.post("/connect/onedrive/disconnect", data={"csrf": token})
    assert r.status_code == 303
    assert memstore.get(f"{KEY_PREFIX}{ONEDRIVE_TOKEN_KEY}") is None
    assert stored_allowlist(memstore) == {}
    out = result(c, "onedrive_list_folder")
    assert out["structuredContent"]["error"] == "onedrive_not_connected"


def test_connecting_another_microsoft_account_clears_the_list(c, drive, memstore) -> None:
    connect(c)
    allow(c, SCHOOL)
    drive.drive_id = "drive-2"
    connect(c)
    assert stored_allowlist(memstore) == {}


# ---- the From OneDrive tab ------------------------------------------------------------


def test_files_tab_offers_connect_first(c) -> None:
    page = c.get("/files?tab=onedrive")
    assert page.status_code == 200
    assert 'id="onedrive-connect"' in page.text


def test_files_tab_browses_and_allows_a_folder(c, memstore) -> None:
    connect(c)
    page = c.get("/files?tab=onedrive").text
    assert "School" in page and "diary.txt" in page
    assert "Group project" not in page  # shortcuts are not listed
    r = allow(c, SCHOOL)
    assert r.status_code == 303
    assert set(stored_allowlist(memstore)) == {SCHOOL}
    inside = c.get(f"/files?tab=onedrive&folder={SCHOOL}").text
    assert 'id="onedrive-folder-allowed"' in inside
    assert inside.count("Allowed through “School”") >= 3  # essay, Biology, report, photo


def test_cannot_allow_the_top_of_the_drive_or_a_shortcut(c, memstore) -> None:
    connect(c)
    for bad in (ROOT, SHORTCUT, "D00D!999", "../etc"):
        allow(c, bad)
    assert stored_allowlist(memstore) == {}


def test_allow_needs_csrf(c, memstore) -> None:
    connect(c)
    r = c.post("/onedrive/allow", data={"file_id": SCHOOL})
    assert r.status_code == 403
    assert stored_allowlist(memstore) == {}


# ---- the tools -----------------------------------------------------------------------------


@pytest.fixture
def allowed(c):
    connect(c)
    allow(c, SCHOOL)
    return c


def test_list_folder_without_id_shows_only_the_allowed_list(allowed, drive) -> None:
    drive.calls.clear()
    items = result(allowed, "onedrive_list_folder")["structuredContent"]["items"]
    assert [(i["id"], i["type"]) for i in items] == [(SCHOOL, "folder")]
    assert drive.calls == []  # from the stored list only


def test_list_an_allowed_folder_and_one_inside_it(allowed) -> None:
    out = result(allowed, "onedrive_list_folder", folder_id=SCHOOL)["structuredContent"]
    assert {i["name"] for i in out["items"]} == {"essay.txt", "Biology", "report.docx", "photo.jpg"}
    out = result(allowed, "onedrive_list_folder", folder_id=SUB)["structuredContent"]
    assert [i["name"] for i in out["items"]] == ["cells.md"]


def test_read_files_inside_an_allowed_folder(allowed) -> None:
    essay = result(allowed, "onedrive_read_file", file_id=ESSAY)["structuredContent"]
    assert "my essay about rivers" in essay["content"]
    assert essay["content"].startswith("<<<ONEDRIVE FILE CONTENT (untrusted")
    nested = result(allowed, "onedrive_read_file", file_id=NOTES)["structuredContent"]
    assert "mitochondria" in nested["content"]
    report = result(allowed, "onedrive_read_file", file_id=REPORT)["structuredContent"]
    assert "lab report text" in report["content"]
    photo = result(allowed, "onedrive_read_file", file_id=PHOTO)["structuredContent"]
    assert photo["content"] is None and "onedrive_download_file" in photo["note"]


def test_download_an_allowed_file(allowed) -> None:
    import base64

    out = result(allowed, "onedrive_download_file", file_id=PHOTO)["structuredContent"]
    assert base64.b64decode(out["content_base64"]) == b"\xff\xd8\xff\xe0jpegbytes"


def test_items_outside_the_list_are_refused_the_same_way(allowed) -> None:
    for tool in ("onedrive_read_file", "onedrive_download_file"):
        diary = result(allowed, tool, file_id=DIARY)
        shortcut = result(allowed, tool, file_id=SHORTCUT)
        missing = result(allowed, tool, file_id="D00D!999")
        root = result(allowed, tool, file_id=ROOT)
        for out in (diary, shortcut, missing, root):
            assert out["isError"] is True
            assert out["structuredContent"]["error"] == "onedrive_not_allowed"
        assert "dear diary" not in str(diary)
    out = result(allowed, "onedrive_list_folder", folder_id=ROOT)
    assert out["structuredContent"]["error"] == "onedrive_not_allowed"


def test_a_bad_id_is_invalid_input(allowed) -> None:
    out = result(allowed, "onedrive_read_file", file_id="../../me/messages")
    assert out["structuredContent"]["error"] == "invalid_input"


def test_nothing_allowed_means_nothing_readable(c, drive) -> None:
    connect(c)
    drive.calls.clear()
    out = result(c, "onedrive_read_file", file_id=ESSAY)
    assert out["structuredContent"]["error"] == "onedrive_not_allowed"
    assert drive.calls == []  # not even a Graph call


def test_a_deleted_allowed_folder_does_not_keep_its_files_readable(allowed, drive) -> None:
    drive.items[SCHOOL]["deleted"] = {"state": "deleted"}
    out = result(allowed, "onedrive_read_file", file_id=ESSAY)
    assert out["structuredContent"]["error"] == "onedrive_not_allowed"


def test_a_file_moved_out_of_an_allowed_folder_is_unreadable(allowed, drive) -> None:
    drive.items[ESSAY]["parentReference"] = {"id": ROOT, "path": "/drive/root:"}
    out = result(allowed, "onedrive_read_file", file_id=ESSAY)
    assert out["structuredContent"]["error"] == "onedrive_not_allowed"


def test_search_returns_only_allowed_matches(allowed) -> None:
    hits = result(allowed, "onedrive_search", query="diary")["structuredContent"]["results"]
    assert hits == []
    hits = result(allowed, "onedrive_search", query="essay")["structuredContent"]["results"]
    assert [h["id"] for h in hits] == [ESSAY]
    hits = result(allowed, "onedrive_search", query="mitochondria")["structuredContent"]["results"]
    assert [h["id"] for h in hits] == [NOTES]


def test_removed_folder_is_unreadable_at_once(allowed) -> None:
    token = csrf(allowed, "/files?tab=onedrive")
    allowed.post("/onedrive/remove", data={"csrf": token, "file_id": SCHOOL})
    out = result(allowed, "onedrive_read_file", file_id=ESSAY)
    assert out["structuredContent"]["error"] == "onedrive_not_allowed"


def test_an_expired_token_is_refreshed_before_the_call(app, ms_oauth, drive, c) -> None:
    ms_oauth.expires_in = -3600  # stored as already expired
    connect(c)
    drive.tokens.clear()  # Graph no longer accepts the first token
    allow(c, SCHOOL)  # the dashboard's lookup refreshes it first
    out = result(c, "onedrive_read_file", file_id=ESSAY)["structuredContent"]
    assert "my essay" in out["content"]
    assert ms_oauth.refreshed == ["ms-refresh-1"]


def test_a_rejected_token_is_refreshed_once(allowed, drive, ms_oauth) -> None:
    drive.tokens.clear()
    out = result(allowed, "onedrive_read_file", file_id=ESSAY)["structuredContent"]
    assert "my essay" in out["content"]
    assert ms_oauth.refreshed == ["ms-refresh-1"]
    result(allowed, "onedrive_read_file", file_id=ESSAY)
    assert ms_oauth.refreshed == ["ms-refresh-1"]


def test_a_revoked_connection_asks_to_reconnect(allowed, drive, ms_oauth) -> None:
    drive.tokens.clear()

    def no_refresh(token):
        raise OneDriveOAuthError("revoked")

    ms_oauth.refresh = no_refresh
    out = result(allowed, "onedrive_read_file", file_id=ESSAY)
    assert out["structuredContent"]["error"] == "onedrive_reconnect"


def test_another_persons_onedrive_is_separate(app, allowed) -> None:
    eve = client(app)
    login(eve, "eve-code")
    page = eve.get("/files?tab=onedrive").text
    assert 'id="onedrive-connect"' in page
    assert "School" not in page


# ---- review fixes ----------------------------------------------------------------------


def test_ids_made_only_of_dots_are_refused() -> None:
    for bad in (".", "..", "...", "-", "_.!"):
        assert normalize_item_id(bad) is None


def test_not_connected_is_said_before_not_allowed(c) -> None:
    for tool in ("onedrive_read_file", "onedrive_download_file"):
        out = result(c, tool, file_id=ESSAY)
        assert out["structuredContent"]["error"] == "onedrive_not_connected"
    out = result(c, "onedrive_list_folder", folder_id=SCHOOL)
    assert out["structuredContent"]["error"] == "onedrive_not_connected"


def test_a_refresh_with_wider_scopes_drops_token_and_list(allowed, drive, ms_oauth, memstore):
    drive.tokens.clear()
    ms_oauth.scopes = ("Files.Read", "Files.Read.All", "offline_access")
    out = result(allowed, "onedrive_read_file", file_id=ESSAY)
    assert out["structuredContent"]["error"] == "onedrive_reconnect"
    assert memstore.get(f"{KEY_PREFIX}{ONEDRIVE_TOKEN_KEY}") is None
    assert stored_allowlist(memstore) == {}


def test_a_list_without_a_usable_connection_is_not_inherited(allowed, memstore) -> None:
    assert stored_allowlist(memstore)
    memstore.delete(f"{KEY_PREFIX}{ONEDRIVE_TOKEN_KEY}")  # e.g. ignored as another account's
    connect(allowed)
    assert stored_allowlist(memstore) == {}


def test_microsoft_being_down_is_not_a_reconnect(allowed, drive, ms_oauth, memstore) -> None:
    from scoped_drive_mcp.onedrive_client import OneDriveOAuthUnavailableError

    drive.tokens.clear()

    def down(token):
        raise OneDriveOAuthUnavailableError("could not reach Microsoft")

    ms_oauth.refresh = down
    out = result(allowed, "onedrive_read_file", file_id=ESSAY)
    assert out["structuredContent"]["error"] == "onedrive_unavailable"
    assert memstore.get(f"{KEY_PREFIX}{ONEDRIVE_TOKEN_KEY}") is not None
    assert stored_allowlist(memstore)


def test_search_stops_at_its_time_limit(allowed, monkeypatch) -> None:
    import scoped_drive_mcp.onedrive as od

    # Calls: set the deadline, check before the first page, then inside it (time is up).
    clock = iter([0.0, 0.0, 1000.0])
    monkeypatch.setattr(od, "_clock", lambda: next(clock, 1000.0))
    out = result(allowed, "onedrive_search", query="essay")["structuredContent"]
    assert out["results"] == [] and "could not be checked" in out["note"]


# ---- the Graph client's download, over HTTP ------------------------------------------------


def _graph(handler):
    import httpx

    from scoped_drive_mcp.onedrive_client import HttpOneDriveApi

    return HttpOneDriveApi("tok-secret", transport=httpx.MockTransport(handler))


def test_download_follows_the_redirect_without_the_token_and_caps_bytes() -> None:
    import httpx

    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.host == "graph.microsoft.com":
            return httpx.Response(302, headers={"location": "https://dl.example/f?sig=1"})
        return httpx.Response(200, content=b"x" * 5000)

    data = _graph(handler).download(ESSAY, 100)
    assert data == b"x" * 100
    assert seen[0].headers["authorization"] == "Bearer tok-secret"
    assert "authorization" not in seen[1].headers


def test_download_refuses_a_plain_http_address_and_endless_redirects() -> None:
    import httpx

    from scoped_drive_mcp.onedrive_client import OneDriveApiError

    def to_http(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://dl.example/f"})

    with pytest.raises(OneDriveApiError):
        _graph(to_http).download(ESSAY, 100)

    def loop(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://dl.example/again"})

    with pytest.raises(httpx.TooManyRedirects):
        _graph(loop).download(ESSAY, 100)


def test_download_served_directly_is_capped_too() -> None:
    import httpx

    def direct(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"y" * 5000)

    assert _graph(direct).download(ESSAY, 10) == b"y" * 10

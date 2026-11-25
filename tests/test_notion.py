"""Notion: a second connection with its own OAuth, its own allowlist and read-only tools."""

import base64
import json
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from scoped_drive_mcp.notion_client import (
    API_BASE,
    HttpNotionApi,
    NotionApiError,
    NotionForbiddenError,
    NotionNotFoundError,
    NotionOAuth,
    NotionOAuthError,
    NotionTokens,
    NotionUnauthorizedError,
    block_line,
    normalize_notion_id,
    property_text,
    title_of,
)
from scoped_drive_mcp.server import build_app
from scoped_drive_mcp.store import KEY_PREFIX, NOTION_ALLOWLIST_KEY, NOTION_TOKEN_KEY
from tests.conftest import OWNER_EMAIL, TOKENS, make_settings
from tests.dash import MCP_HEADERS, client, csrf, login, mcp_call


def nid(n: int) -> str:
    h = f"{n:032x}"
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


TOP = nid(1)  # "Team wiki", top of the workspace
CHILD = nid(2)  # page inside TOP
DB = nid(3)  # database inside TOP
ROW = nid(4)  # row in DB
OTHER = nid(5)  # "Private diary", shared with Bot RBAC but never allowed
COLUMN = nid(6)  # a column block inside TOP
NESTED = nid(7)  # page inside that column
HIDDEN = nid(8)  # exists in the workspace, not shared with Bot RBAC at all


def page(pid: str, title: str, parent: dict, **extra) -> dict:
    return {
        "object": "page",
        "id": pid,
        "parent": parent,
        "url": f"https://www.notion.so/{pid.replace('-', '')}",
        "last_edited_time": "2026-11-20T10:00:00.000Z",
        "properties": {"Name": {"type": "title", "title": [{"plain_text": title}]}},
        **extra,
    }


def para(text: str, bid: str = "b") -> dict:
    return {
        "object": "block",
        "id": bid,
        "type": "paragraph",
        "has_children": False,
        "paragraph": {"rich_text": [{"plain_text": text}]},
    }


class FakeNotion:
    """A small workspace. `shared` is what Notion lets Bot RBAC's connection see."""

    def __init__(self) -> None:
        ws = {"type": "workspace", "workspace": True}
        self.objects: dict[str, dict] = {
            TOP: page(TOP, "Team wiki", ws),
            CHILD: page(CHILD, "Onboarding", {"type": "page_id", "page_id": TOP}),
            DB: {
                "object": "database",
                "id": DB,
                "parent": {"type": "page_id", "page_id": TOP},
                "title": [{"plain_text": "Tasks"}],
                "url": "https://www.notion.so/tasks",
            },
            ROW: page(
                ROW,
                "Ship Notion",
                {"type": "database_id", "database_id": DB},
            ),
            OTHER: page(OTHER, "Private diary", ws),
            COLUMN: {
                "object": "block",
                "id": COLUMN,
                "type": "column",
                "parent": {"type": "page_id", "page_id": TOP},
            },
            NESTED: page(NESTED, "Nested notes", {"type": "block_id", "block_id": COLUMN}),
            HIDDEN: page(HIDDEN, "Hidden plans", ws),
        }
        self.children = {
            TOP: [para("welcome to the wiki")],
            CHILD: [
                para("secret onboarding steps", "b1"),
                {
                    "object": "block",
                    "id": "b2",
                    "type": "to_do",
                    "has_children": False,
                    "to_do": {"rich_text": [{"plain_text": "get a laptop"}], "checked": True},
                },
            ],
            OTHER: [para("dear diary")],
            NESTED: [para("nested secret")],
            ROW: [para("row body")],
        }
        self.shared = {TOP, CHILD, DB, ROW, OTHER, COLUMN, NESTED}
        self.tokens = {"notion-access-1"}
        self.calls: list[tuple[str, str]] = []

    def factory(self, token: str) -> "FakeNotionApi":
        return FakeNotionApi(self, token)


class FakeNotionApi:
    def __init__(self, world: FakeNotion, token: str) -> None:
        self.world = world
        self.token = token

    def _check(self) -> None:
        if self.token not in self.world.tokens:
            raise NotionUnauthorizedError(401, "unauthorized")

    def _get(self, oid: str, kind: str) -> dict:
        self._check()
        self.world.calls.append((kind, oid))
        obj = self.world.objects.get(oid)
        want = {"page": "page", "database": "database", "block": "block"}[kind]
        if oid not in self.world.shared or obj is None or obj["object"] != want:
            raise NotionNotFoundError(404, "object_not_found")
        return obj

    def get_page(self, page_id: str) -> dict:
        return self._get(page_id, "page")

    def get_database(self, database_id: str) -> dict:
        return self._get(database_id, "database")

    def get_block(self, block_id: str) -> dict:
        return self._get(block_id, "block")

    def search(self, query: str, cursor=None, page_size: int = 100) -> dict:
        self._check()
        hits = [
            o
            for oid, o in self.world.objects.items()
            if oid in self.world.shared
            and o["object"] in ("page", "database")
            and query.lower() in title_of(o).lower()
        ]
        return {"results": hits, "has_more": False, "next_cursor": None}

    def block_children(self, block_id: str, cursor=None) -> dict:
        self._check()
        if block_id not in self.world.shared:
            raise NotionNotFoundError(404, "object_not_found")
        return {"results": self.world.children.get(block_id, []), "has_more": False}

    def query_database(self, database_id: str, cursor=None) -> dict:
        self._check()
        rows = [
            o
            for o in self.world.objects.values()
            if o.get("parent", {}).get("database_id") == database_id
        ]
        return {"results": rows, "has_more": False}


class FakeNotionOAuth:
    def __init__(self) -> None:
        self.states: list[str] = []
        self.revoked: list[str] = []
        self.refreshed: list[str] = []
        self.next_access = "notion-access-1"
        self.world: FakeNotion | None = None

    def authorization_url(self, state: str) -> str:
        self.states.append(state)
        return f"https://api.notion.com/v1/oauth/authorize?state={state}"

    def exchange_code(self, code: str) -> NotionTokens:
        if code != "notion-code":
            raise NotionOAuthError("Notion rejected the connection code")
        return NotionTokens(self.next_access, "notion-refresh-1", "ws-1", "Acme HQ", "bot-1")

    def refresh(self, refresh_token: str) -> NotionTokens:
        self.refreshed.append(refresh_token)
        assert self.world is not None
        self.world.tokens.add("notion-access-2")
        return NotionTokens("notion-access-2", "notion-refresh-2", "ws-1", "Acme HQ", "bot-1")

    def revoke(self, token: str) -> bool:
        self.revoked.append(token)
        return True


@pytest.fixture
def notion() -> FakeNotion:
    return FakeNotion()


@pytest.fixture
def notion_oauth(notion) -> FakeNotionOAuth:
    o = FakeNotionOAuth()
    o.world = notion
    return o


@pytest.fixture
def app(world, p2_settings, memstore, oauth, notion, notion_oauth):
    return build_app(
        p2_settings,
        world.as_user(OWNER_EMAIL),
        store=memstore,
        owner_drive_factory=lambda token: world.as_user(OWNER_EMAIL),
        oauth=oauth,
        notion_api_factory=notion.factory,
        notion_oauth=notion_oauth,
    )


@pytest.fixture
def c(app):
    c = client(app)
    login(c)
    return c


def connect_notion(c, code: str = "notion-code"):
    token = csrf(c, "/settings")
    r = c.post("/connect/notion", data={"csrf": token, "next": "/settings"})
    assert r.status_code == 303, r.text
    assert r.headers["location"].startswith("https://api.notion.com/v1/oauth/authorize")
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
    return c.get("/connect/notion/callback", params={"code": code, "state": state})


def allow(c, page_id: str):
    token = csrf(c, "/files?tab=notion")
    return c.post("/notion/allow", data={"csrf": token, "page_id": page_id})


def result(c, tool: str, **args) -> dict:
    return mcp_call(c, tool, **args)


# ---- configuration -----------------------------------------------------------------


def test_notion_is_hidden_when_not_configured(world, p2_settings, memstore, oauth) -> None:
    app = build_app(
        p2_settings,
        world.as_user(OWNER_EMAIL),
        store=memstore,
        owner_drive_factory=lambda token: world.as_user(OWNER_EMAIL),
        oauth=oauth,
    )
    c = client(app)
    login(c)
    page = c.get("/settings")
    assert 'id="connection-notion"' not in page.text
    assert "From Notion" not in c.get("/files").text
    token = csrf(c, "/settings")
    assert c.post("/connect/notion", data={"csrf": token}).status_code == 404
    listed = c.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={**MCP_HEADERS, "Authorization": f"Bearer {TOKENS['viewer']}"},
    )
    names = {t["name"] for t in listed.json()["result"]["tools"]}
    assert not names & {"notion_list_pages", "notion_read_page", "notion_search"}


def test_placeholder_secret_does_not_turn_notion_on() -> None:
    s = make_settings(
        notion_oauth_client_id="422d872b-594c-8146-9ac2-00377e16f645",
        notion_oauth_client_secret="REPLACE_WITH_NOTION_CLIENT_SECRET",
    )
    assert not s.notion_configured
    s = make_settings(
        notion_oauth_client_id="422d872b-594c-8146-9ac2-00377e16f645",
        notion_oauth_client_secret="secret_real_value",
    )
    assert s.notion_configured


def test_normalize_notion_id_accepts_ids_and_urls() -> None:
    plain = "1a2b3c4d5e6f708192a3b4c5d6e7f809"
    dashed = "1a2b3c4d-5e6f-7081-92a3-b4c5d6e7f809"
    assert normalize_notion_id(plain) == dashed
    assert normalize_notion_id(dashed.upper()) == dashed
    assert normalize_notion_id(f"https://www.notion.so/acme/Team-wiki-{plain}?pvs=4") == dashed
    # A slug made of hex letters must not merge into the id.
    assert normalize_notion_id(f"https://www.notion.so/Bad-Face-Dad-{plain}") == dashed
    assert normalize_notion_id(f"https://www.notion.so/acme/Bad-Face-Dad-{dashed}") == dashed
    # Notion's newer link format (June 2026), with a dashed id.
    assert normalize_notion_id(f"https://app.notion.com/p/{dashed}") == dashed
    assert normalize_notion_id("not an id") is None
    assert normalize_notion_id(None) is None


# ---- connecting ----------------------------------------------------------------------


def test_connect_stores_an_encrypted_token_and_shows_the_workspace(c, memstore) -> None:
    r = connect_notion(c)
    assert r.status_code == 303
    assert r.headers["location"] == "/files?tab=notion"
    raw = memstore.get(f"{KEY_PREFIX}{NOTION_TOKEN_KEY}") or ""
    assert raw and "notion-access-1" not in raw
    settings_page = c.get("/settings").text
    assert 'id="connection-notion"' in settings_page
    assert "Workspace: Acme HQ" in settings_page


def test_connect_needs_a_matching_state(c, notion_oauth) -> None:
    token = csrf(c, "/settings")
    c.post("/connect/notion", data={"csrf": token})
    r = c.get("/connect/notion/callback", params={"code": "notion-code", "state": "forged"})
    assert r.status_code == 400
    assert "connection expired" in r.text.lower() or "didn’t start here" in r.text
    # The real state was spent by the failed attempt (the nonce is single use).
    state = notion_oauth.states[-1]
    r = c.get("/connect/notion/callback", params={"code": "notion-code", "state": state})
    assert r.status_code == 400


def test_state_from_another_account_is_refused(app, c, notion_oauth) -> None:
    connect_notion(c)
    other = client(app)
    login(other, "eve-code")
    token = csrf(other, "/settings")
    other.post("/connect/notion", data={"csrf": token})
    # Eve's browser receives a state minted for the owner.
    owner_state = notion_oauth.states[0]
    r = other.get("/connect/notion/callback", params={"code": "notion-code", "state": owner_state})
    assert r.status_code == 400


def test_cancel_on_notions_screen_changes_nothing(c) -> None:
    token = csrf(c, "/settings")
    c.post("/connect/notion", data={"csrf": token})
    r = c.get("/connect/notion/callback", params={"error": "access_denied", "state": "x"})
    assert r.status_code == 400
    assert "You didn’t connect Notion" in r.text


def test_callback_needs_sign_in(app) -> None:
    anon = client(app)
    r = anon.get("/connect/notion/callback", params={"code": "notion-code", "state": "x"})
    assert r.status_code == 303
    assert r.headers["location"].startswith("/login")


def test_connect_form_may_redirect_to_notion() -> None:
    from scoped_drive_mcp.dashboard import STRICT_CSP

    assert b"https://api.notion.com" in STRICT_CSP


def test_disconnect_removes_and_revokes_the_token_and_clears_the_list(
    c, memstore, notion_oauth
) -> None:
    connect_notion(c)
    allow(c, TOP)
    token = csrf(c, "/settings")
    r = c.post("/connect/notion/disconnect", data={"csrf": token})
    assert r.status_code == 303
    assert memstore.get(f"{KEY_PREFIX}{NOTION_TOKEN_KEY}") is None
    assert memstore.hgetall(f"{KEY_PREFIX}{NOTION_ALLOWLIST_KEY}") == {}
    assert notion_oauth.revoked == ["notion-access-1", "notion-refresh-1"]
    out = result(c, "notion_list_pages")
    assert out["structuredContent"]["error"] == "notion_not_connected"


# ---- the From Notion tab ------------------------------------------------------------------


def test_files_tab_lists_what_notion_shows_and_allows_one(c, memstore) -> None:
    connect_notion(c)
    page = c.get("/files?tab=notion").text
    assert "Team wiki" in page and "Private diary" in page
    assert "Hidden plans" not in page
    r = allow(c, TOP)
    assert r.status_code == 303
    page = c.get("/files?tab=notion").text
    assert 'id="notion-none-allowed"' not in page
    raw = memstore.hgetall(f"{KEY_PREFIX}{NOTION_ALLOWLIST_KEY}")
    # Signed like the Drive allowlist, so a store write without the key cannot add one.
    assert raw[TOP].startswith("s1.")


def test_pages_inside_an_allowed_page_say_so(c) -> None:
    connect_notion(c)
    allow(c, TOP)
    page = c.get("/files?tab=notion").text
    assert page.count("Allowed through “Team wiki”") == 3  # Onboarding, Tasks, Ship Notion
    assert "Private diary" in page


def test_cannot_allow_a_page_notion_does_not_show(c, memstore) -> None:
    connect_notion(c)
    allow(c, HIDDEN)
    assert memstore.hgetall(f"{KEY_PREFIX}{NOTION_ALLOWLIST_KEY}") == {}
    assert "doesn’t show Bot RBAC that page" in c.get("/files?tab=notion").text


def test_allow_needs_csrf(c, memstore) -> None:
    connect_notion(c)
    r = c.post("/notion/allow", data={"page_id": TOP})
    assert r.status_code == 403
    assert memstore.hgetall(f"{KEY_PREFIX}{NOTION_ALLOWLIST_KEY}") == {}


# ---- the tools -----------------------------------------------------------------------------


@pytest.fixture
def allowed(c):
    connect_notion(c)
    allow(c, TOP)
    return c


def test_list_pages_shows_only_the_allowed_list(allowed) -> None:
    items = result(allowed, "notion_list_pages")["structuredContent"]["items"]
    assert [i["title"] for i in items] == ["Team wiki"]


def test_read_allowed_page_and_what_is_inside_it(allowed) -> None:
    top = result(allowed, "notion_read_page", page_id=TOP)["structuredContent"]
    assert "welcome to the wiki" in top["content"]
    assert top["content"].startswith("<<<NOTION PAGE CONTENT (untrusted")
    child = result(allowed, "notion_read_page", page_id=CHILD)["structuredContent"]
    assert "secret onboarding steps" in child["content"]
    assert "[x] get a laptop" in child["content"]
    # Inside a column block, still under the allowed page.
    nested = result(allowed, "notion_read_page", page_id=NESTED)["structuredContent"]
    assert "nested secret" in nested["content"]
    # A Notion URL works as an id.
    url = f"https://www.notion.so/Onboarding-{CHILD.replace('-', '')}"
    assert (
        "secret onboarding"
        in result(allowed, "notion_read_page", page_id=url)["structuredContent"]["content"]
    )


def test_read_database_and_its_rows(allowed) -> None:
    db = result(allowed, "notion_read_page", page_id=DB)["structuredContent"]
    assert db["type"] == "database"
    assert "Ship Notion" in db["content"]
    row = result(allowed, "notion_read_page", page_id=ROW)["structuredContent"]
    assert "row body" in row["content"]


def test_pages_outside_the_list_are_refused_the_same_way(allowed) -> None:
    diary = result(allowed, "notion_read_page", page_id=OTHER)
    hidden = result(allowed, "notion_read_page", page_id=HIDDEN)
    missing = result(allowed, "notion_read_page", page_id=nid(99))
    for out in (diary, hidden, missing):
        assert out["isError"] is True
        assert out["structuredContent"]["error"] == "not_allowed"
    assert "dear diary" not in str(diary)


def test_nothing_allowed_means_nothing_readable(c, notion) -> None:
    connect_notion(c)
    out = result(c, "notion_read_page", page_id=TOP)
    assert out["structuredContent"]["error"] == "not_allowed"
    assert notion.calls == []  # not even a Notion call


def test_trashed_allowed_page_does_not_keep_its_children_readable(allowed, notion) -> None:
    notion.objects[TOP]["in_trash"] = True
    out = result(allowed, "notion_read_page", page_id=CHILD)
    assert out["structuredContent"]["error"] == "not_allowed"


def test_search_returns_only_allowed_matches(allowed) -> None:
    hits = result(allowed, "notion_search", query="")["structuredContent"]["results"]
    titles = {h["title"] for h in hits}
    assert "Private diary" not in titles
    assert {"Team wiki", "Onboarding", "Tasks", "Ship Notion", "Nested notes"} <= titles
    hits = result(allowed, "notion_search", query="diary")["structuredContent"]["results"]
    assert hits == []


def test_removed_page_is_off_the_list_and_unreadable_at_once(allowed, memstore) -> None:
    assert "secret onboarding" in str(result(allowed, "notion_read_page", page_id=CHILD))
    token = csrf(allowed, "/files?tab=notion")
    allowed.post("/notion/remove", data={"csrf": token, "page_id": TOP})
    assert memstore.hgetall(f"{KEY_PREFIX}{NOTION_ALLOWLIST_KEY}") == {}
    out = result(allowed, "notion_read_page", page_id=CHILD)
    assert out["structuredContent"]["error"] == "not_allowed"


def test_an_expired_token_is_refreshed_once(allowed, notion, notion_oauth) -> None:
    notion.tokens.clear()  # Notion stops accepting the first token
    out = result(allowed, "notion_read_page", page_id=TOP)["structuredContent"]
    assert "welcome to the wiki" in out["content"]
    assert notion_oauth.refreshed == ["notion-refresh-1"]
    # The new token was stored: the next call does not refresh again.
    result(allowed, "notion_read_page", page_id=TOP)
    assert notion_oauth.refreshed == ["notion-refresh-1"]


def test_a_revoked_connection_asks_to_reconnect(allowed, notion, notion_oauth) -> None:
    notion.tokens.clear()

    def no_refresh(token):
        raise NotionOAuthError("revoked")

    notion_oauth.refresh = no_refresh
    out = result(allowed, "notion_read_page", page_id=TOP)
    assert out["structuredContent"]["error"] == "notion_reconnect"


def test_the_tab_offers_connect_until_connected_and_each_person_has_their_own(app, c) -> None:
    page = c.get("/files?tab=notion")
    assert page.status_code == 200
    assert 'id="notion-connect"' in page.text
    connect_notion(c)
    allow(c, TOP)
    assert 'id="notion-connect"' not in c.get("/files?tab=notion").text
    eve = client(app)
    login(eve, "eve-code")
    page = eve.get("/files?tab=notion").text
    assert 'id="notion-connect"' in page
    assert "Team wiki" not in page


def test_a_refresh_spent_by_another_call_uses_the_stored_token(allowed, notion, app) -> None:
    """Notion rotates refresh tokens. If another call refreshed first, the spent refresh
    token fails, and the newer stored access token is used instead of asking to reconnect."""
    from scoped_drive_mcp.auth import current_actor

    notion.tokens.clear()
    notion.tokens.add("notion-access-9")
    vault = app.state.dashboard.vault
    oauth = app.state.dashboard.notion.oauth
    calls = {"n": 0}

    def racing_refresh(token):
        # The other call wins the race and stores its new pair just before ours fails.
        calls["n"] += 1
        reset = current_actor.set(OWNER_EMAIL)
        try:
            vault.set_notion("notion-access-9", "notion-refresh-9", OWNER_EMAIL, "ws-1", "Acme HQ")
        finally:
            current_actor.reset(reset)
        raise NotionOAuthError("refresh token already used")

    oauth.refresh = racing_refresh
    out = result(allowed, "notion_read_page", page_id=TOP)["structuredContent"]
    assert "welcome to the wiki" in out["content"]
    assert calls["n"] == 1


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (200, {"request_id": "r"}, True),
        (400, {"object": "error", "status": 400, "code": "invalid_grant"}, True),
        (400, {"object": "error", "status": 400, "code": "invalid_request"}, False),
        (401, {"object": "error", "status": 401, "code": "invalid_client"}, False),
        (500, {"object": "error", "status": 500, "code": "internal_server_error"}, False),
    ],
)
def test_revoke_reads_notions_answer(monkeypatch, status, body, expected) -> None:
    """Per Notion's reference: 401 is invalid_client (nothing revoked), and 400
    invalid_grant means the token is already invalid."""

    def fake_post(url, **kwargs):
        assert url == "https://api.notion.com/v1/oauth/revoke"
        assert kwargs["json"] == {"token": "tok"}
        assert kwargs["headers"]["Authorization"].startswith("Basic ")
        return httpx.Response(status, json=body)

    monkeypatch.setattr(httpx, "post", fake_post)
    assert NotionOAuth("id", "secret", "https://x/cb").revoke("tok") is expected


def test_token_exchange_sends_what_notion_documents(monkeypatch) -> None:
    seen = {}

    def fake_post(url, **kwargs):
        seen.update(url=url, **kwargs)
        return httpx.Response(
            200,
            json={
                "access_token": "ntn_a",
                "refresh_token": "nrt_r",
                "bot_id": "b",
                "workspace_id": "w",
                "workspace_name": "Acme",
                "owner": {"type": "user"},
            },
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    tokens = NotionOAuth("cid", "csec", "https://x/cb").exchange_code("c0de")
    assert seen["url"] == "https://api.notion.com/v1/oauth/token"
    assert seen["json"] == {
        "grant_type": "authorization_code",
        "code": "c0de",
        "redirect_uri": "https://x/cb",
    }
    assert seen["headers"]["Authorization"] == "Basic " + base64.b64encode(b"cid:csec").decode()
    assert (tokens.access_token, tokens.refresh_token, tokens.workspace_name) == (
        "ntn_a",
        "nrt_r",
        "Acme",
    )


def test_restricted_parent_reads_as_not_allowed(allowed, monkeypatch) -> None:
    """A 403 restricted_resource in the parent walk is answered like not found."""
    real_get_page = FakeNotionApi.get_page

    def restricted(self, page_id):
        if page_id == TOP:
            raise NotionForbiddenError(403, "restricted_resource")
        return real_get_page(self, page_id)

    monkeypatch.setattr(FakeNotionApi, "get_page", restricted)
    out = result(allowed, "notion_read_page", page_id=CHILD)
    assert out["structuredContent"]["error"] == "not_allowed"


def test_synced_copy_of_a_page_that_is_not_allowed_is_not_shown(allowed, notion) -> None:
    source = nid(20)  # original synced block, on the private diary
    notion.objects[source] = {
        "object": "block",
        "id": source,
        "type": "synced_block",
        "parent": {"type": "page_id", "page_id": OTHER},
        "synced_block": {"synced_from": None},
    }
    notion.shared.add(source)
    copy = {
        "object": "block",
        "id": nid(21),
        "type": "synced_block",
        "has_children": True,
        "synced_block": {"synced_from": {"type": "block_id", "block_id": source}},
    }
    notion.shared.add(nid(21))
    notion.children[nid(21)] = [para("diary text mirrored")]
    notion.children[CHILD] = [*notion.children[CHILD], copy]
    out = result(allowed, "notion_read_page", page_id=CHILD)["structuredContent"]["content"]
    assert "diary text mirrored" not in out
    assert "synced content from a page that is not allowed" in out
    # Once the source page is allowed, the copy is read.
    allow(allowed, OTHER)
    out = result(allowed, "notion_read_page", page_id=CHILD)["structuredContent"]["content"]
    assert "diary text mirrored" in out


def test_reconnecting_keeps_the_list_only_for_the_same_workspace(
    allowed, memstore, notion_oauth
) -> None:
    connect_notion(allowed)
    assert TOP in memstore.hgetall(f"{KEY_PREFIX}{NOTION_ALLOWLIST_KEY}")

    real = notion_oauth.exchange_code

    def other_workspace(code):
        t = real(code)
        return NotionTokens(t.access_token, t.refresh_token, "ws-2", "Other", "bot-2")

    notion_oauth.exchange_code = other_workspace
    connect_notion(allowed)
    assert memstore.hgetall(f"{KEY_PREFIX}{NOTION_ALLOWLIST_KEY}") == {}


def test_tool_closes_its_notion_client(allowed, monkeypatch) -> None:
    closed = []
    monkeypatch.setattr(FakeNotionApi, "close", lambda self: closed.append(1), raising=False)
    result(allowed, "notion_read_page", page_id=TOP)
    assert closed == [1]


# ---- the HTTP client and Notion's block and property shapes -------------------------------


def _http_api(handler) -> HttpNotionApi:
    """The real client, with Notion answered by `handler` instead of the network."""
    api = HttpNotionApi("ntn_secret")
    headers = api._client.headers
    api.close()
    api._client = httpx.Client(
        base_url=API_BASE, headers=headers, transport=httpx.MockTransport(handler)
    )
    return api


def test_the_http_client_sends_reads_as_notion_documents_them() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"object": "list", "results": []})

    api = _http_api(handler)
    api.search("wiki", cursor="c1", page_size=500)
    api.search("")
    api.get_page(TOP)
    api.get_database(DB)
    api.get_block(COLUMN)
    api.block_children(TOP, cursor="c2")
    api.query_database(DB)
    api.close()
    for request in seen:
        assert request.headers["authorization"] == "Bearer ntn_secret"
        assert request.headers["notion-version"] == "2022-06-28"
    calls = [(r.method, r.url.path, r.url.query.decode()) for r in seen]
    assert calls == [
        ("POST", "/v1/search", ""),
        ("POST", "/v1/search", ""),
        ("GET", f"/v1/pages/{TOP}", ""),
        ("GET", f"/v1/databases/{DB}", ""),
        ("GET", f"/v1/blocks/{COLUMN}", ""),
        ("GET", f"/v1/blocks/{TOP}/children", "page_size=100&start_cursor=c2"),
        ("POST", f"/v1/databases/{DB}/query", ""),
    ]
    # Page size is capped at Notion's 100; an empty query lists everything shared.
    assert json.loads(seen[0].content) == {"page_size": 100, "query": "wiki", "start_cursor": "c1"}
    assert json.loads(seen[1].content) == {"page_size": 100}
    assert json.loads(seen[-1].content) == {"page_size": 100}


@pytest.mark.parametrize(
    ("status", "body", "error", "code"),
    [
        (404, {"code": "object_not_found"}, NotionNotFoundError, "object_not_found"),
        (401, {"code": "unauthorized"}, NotionUnauthorizedError, "unauthorized"),
        (403, {"code": "restricted_resource"}, NotionForbiddenError, "restricted_resource"),
        (429, {"code": "rate_limited"}, NotionApiError, "rate_limited"),
        (502, b"<html>bad gateway</html>", NotionApiError, ""),
        (200, ["not", "an", "object"], NotionApiError, "bad_response"),
    ],
)
def test_the_http_client_maps_notions_errors(status, body, error, code) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        if isinstance(body, bytes):
            return httpx.Response(status, content=body)
        return httpx.Response(status, json=body)

    with pytest.raises(error) as raised:
        _http_api(handler).get_page(TOP)
    assert type(raised.value) is error
    assert (raised.value.status, raised.value.code) == (status, code)


def test_the_oauth_flow_asks_for_a_user_owned_connection_and_refreshes(monkeypatch) -> None:
    flow = NotionOAuth("cid", "csec", "https://x/cb")
    url = urlparse(flow.authorization_url("st4te"))
    assert f"{url.scheme}://{url.netloc}{url.path}" == "https://api.notion.com/v1/oauth/authorize"
    assert parse_qs(url.query) == {
        "client_id": ["cid"],
        "response_type": ["code"],
        "owner": ["user"],
        "redirect_uri": ["https://x/cb"],
        "state": ["st4te"],
    }

    answers: list = []
    sent: list[dict] = []

    def fake_post(_url, **kwargs):
        sent.append(kwargs["json"])
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(httpx, "post", fake_post)
    answers.append(httpx.Response(200, json={"access_token": "ntn_b", "refresh_token": ""}))
    tokens = flow.refresh("nrt_old")
    assert sent[-1] == {"grant_type": "refresh_token", "refresh_token": "nrt_old"}
    assert (tokens.access_token, tokens.refresh_token, tokens.workspace_id) == ("ntn_b", None, "")

    for answer, message in (
        (httpx.ConnectError("down"), "could not reach Notion"),
        (httpx.Response(400, json={"error": "invalid_grant"}), "rejected"),
        (httpx.Response(200, json={"access_token": ""}), "unexpected response"),
        (httpx.Response(200, json=["no"]), "unexpected response"),
        (httpx.Response(200, content=b"not json"), "unexpected response"),
    ):
        answers.append(answer)
        with pytest.raises(NotionOAuthError, match=message):
            flow.exchange_code("c0de")
    answers.append(httpx.ConnectError("down"))
    assert flow.revoke("tok") is False


def _block(kind: str, **body) -> dict:
    return {"object": "block", "id": "blk", "type": kind, kind: body}


def _rich(text: str) -> list[dict]:
    return [{"plain_text": text}]


@pytest.mark.parametrize(
    ("block", "line"),
    [
        (_block("heading_1", rich_text=_rich("Plan")), "# Plan"),
        (_block("heading_3", rich_text=_rich("Detail")), "### Detail"),
        (_block("bulleted_list_item", rich_text=_rich("one")), "- one"),
        (_block("numbered_list_item", rich_text=_rich("two")), "1. two"),
        (_block("quote", rich_text=_rich("said")), "> said"),
        (_block("toggle", rich_text=_rich("more")), "▸ more"),
        (_block("to_do", rich_text=_rich("open"), checked=False), "[ ] open"),
        (_block("code", rich_text=_rich("x = 1"), language="python"), "```python\nx = 1\n```"),
        (_block("child_page", title="Sub"), "[page] Sub (id blk)"),
        (_block("child_database", title=""), "[database] Untitled (id blk)"),
        (_block("divider"), "---"),
        (_block("equation", expression="e=mc^2"), "e=mc^2"),
        (_block("bookmark", url="https://example.com"), "<https://example.com>"),
        (_block("embed"), None),
        (_block("table_row", cells=[_rich("a"), _rich("b")]), "a | b"),
        (_block("table_row"), None),
        (_block("paragraph", rich_text=[]), None),
        (_block("image", rich_text="not a list"), None),
        ({"type": "paragraph", "paragraph": "not a dict"}, None),
    ],
)
def test_blocks_read_as_markdown_like_lines(block, line) -> None:
    assert block_line(block) == line


@pytest.mark.parametrize(
    ("prop", "text"),
    [
        ({"type": "rich_text", "rich_text": _rich("note")}, "note"),
        ({"type": "select", "select": {"name": "High"}}, "High"),
        ({"type": "status", "status": {"name": "Done"}}, "Done"),
        ({"type": "select", "select": None}, ""),
        ({"type": "multi_select", "multi_select": [{"name": "a"}, {"name": "b"}]}, "a, b"),
        ({"type": "date", "date": {"start": "2026-11-01"}}, "2026-11-01"),
        (
            {"type": "date", "date": {"start": "2026-11-01", "end": "2026-11-03"}},
            "2026-11-01 → 2026-11-03",
        ),
        ({"type": "checkbox", "checkbox": True}, "yes"),
        ({"type": "checkbox", "checkbox": False}, "no"),
        ({"type": "number", "number": 0}, "0"),
        ({"type": "number", "number": None}, ""),
        ({"type": "url", "url": "https://x"}, "https://x"),
        ({"type": "people", "people": [{"name": "Ada"}, {"name": "Bo"}]}, "Ada, Bo"),
        ({"type": "formula", "formula": {"type": "number", "number": 3}}, "3"),
        ({"type": "formula", "formula": {"type": "string", "string": None}}, ""),
        ({"type": "relation", "relation": [{"id": "x"}]}, ""),
        ({"type": None}, ""),
    ],
)
def test_database_properties_read_as_short_text(prop, text) -> None:
    assert property_text(prop) == text


def test_a_page_reads_its_properties_and_nested_blocks(allowed, notion) -> None:
    notion.objects[CHILD]["properties"]["Status"] = {"type": "status", "status": {"name": "Done"}}
    notion.objects[CHILD]["properties"]["Empty"] = {"type": "rich_text", "rich_text": []}
    notion.children[CHILD] = [
        {
            **_block("bulleted_list_item", rich_text=_rich("outer")),
            "id": nid(30),
            "has_children": True,
        },
        {**_block("child_page", title="Sub"), "id": nid(31), "has_children": True},
    ]
    notion.shared |= {nid(30), nid(31)}
    notion.children[nid(30)] = [para("inner")]
    notion.children[nid(31)] = [para("child page body, read by its own id")]
    out = result(allowed, "notion_read_page", page_id=CHILD)["structuredContent"]["content"]
    assert "# Onboarding\nStatus: Done\n" in out and "Empty:" not in out
    assert "- outer\n  inner" in out
    assert f"[page] Sub (id {nid(31)})" in out
    assert "child page body" not in out

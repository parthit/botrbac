"""Notion: a second connection with its own OAuth, its own allowlist and read-only tools."""

from urllib.parse import parse_qs, urlparse

import pytest

from scoped_drive_mcp.notion_client import (
    NotionNotFoundError,
    NotionOAuthError,
    NotionTokens,
    NotionUnauthorizedError,
    normalize_notion_id,
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
        from scoped_drive_mcp.notion_client import title_of

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


def test_disconnect_removes_and_revokes_the_token(c, memstore, notion_oauth) -> None:
    connect_notion(c)
    token = csrf(c, "/settings")
    r = c.post("/connect/notion/disconnect", data={"csrf": token})
    assert r.status_code == 303
    assert memstore.get(f"{KEY_PREFIX}{NOTION_TOKEN_KEY}") is None
    assert notion_oauth.revoked == ["notion-access-1", "notion-refresh-1"]
    out = result(c, "notion_list_pages")
    assert out["structuredContent"]["error"] == "notion_not_connected"


# ---- the From Notion tab ------------------------------------------------------------------


def test_files_tab_offers_connect_until_connected(c) -> None:
    page = c.get("/files?tab=notion")
    assert page.status_code == 200
    assert 'id="notion-connect"' in page.text


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


def test_remove_takes_it_off_the_list(c, memstore) -> None:
    connect_notion(c)
    allow(c, TOP)
    token = csrf(c, "/files?tab=notion")
    c.post("/notion/remove", data={"csrf": token, "page_id": TOP})
    assert memstore.hgetall(f"{KEY_PREFIX}{NOTION_ALLOWLIST_KEY}") == {}


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


def test_removed_page_is_unreadable_at_once(allowed) -> None:
    token = csrf(allowed, "/files?tab=notion")
    allowed.post("/notion/remove", data={"csrf": token, "page_id": TOP})
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


def test_another_persons_notion_is_separate(app, allowed) -> None:
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
    import httpx

    from scoped_drive_mcp.notion_client import NotionOAuth

    def fake_post(url, **kwargs):
        assert url == "https://api.notion.com/v1/oauth/revoke"
        assert kwargs["json"] == {"token": "tok"}
        assert kwargs["headers"]["Authorization"].startswith("Basic ")
        return httpx.Response(status, json=body)

    monkeypatch.setattr(httpx, "post", fake_post)
    assert NotionOAuth("id", "secret", "https://x/cb").revoke("tok") is expected


def test_token_exchange_sends_what_notion_documents(monkeypatch) -> None:
    import base64

    import httpx

    from scoped_drive_mcp.notion_client import NotionOAuth

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

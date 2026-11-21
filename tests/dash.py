"""Helpers for driving the dashboard and /mcp in one TestClient."""

import base64
import json
import re
from urllib.parse import parse_qs, urlparse

from starlette.testclient import TestClient

from tests.conftest import BASE_URL, TOKENS

MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
_CSRF = re.compile(r'name="csrf" value="([^"]+)"')


def client(app) -> TestClient:
    return TestClient(app, base_url=BASE_URL, follow_redirects=False)


def start_oauth(c: TestClient, path: str = "/auth/login", **form) -> str:
    r = c.post(path, data=form) if form else c.get(path)
    assert r.status_code == 303, r.text
    location = r.headers["location"]
    assert location.startswith("https://accounts.google.com/")
    return parse_qs(urlparse(location).query)["state"][0]


def sign_in(c: TestClient, code: str = "owner-code", path: str = "/auth/login"):
    """Step 1 only: identity scopes. Leaves the person signed in, Drive not connected."""
    state = start_oauth(c, path)
    return c.get("/auth/callback", params={"code": code, "state": state})


def connect_drive(c: TestClient, code: str = "owner-code", next_url: str = "/"):
    """Step 2: the explicit Connect Google Drive button on /connect."""
    token = csrf(c, "/settings")
    state = start_oauth(c, "/connect/google_drive", csrf=token, next=next_url)
    return c.get("/auth/callback", params={"code": code, "state": state})


def login(c: TestClient, code: str = "owner-code"):
    """Both steps, as a first-time person would do them. A returning person skips step 2."""
    r = sign_in(c, code)
    if r.status_code == 303 and r.headers["location"].startswith("/connect"):
        return connect_drive(c, code)
    return r


def csrf(c: TestClient, page: str = "/") -> str:
    r = c.get(page)
    assert r.status_code == 200, r.text
    m = _CSRF.search(r.text)
    assert m, "no csrf field on page"
    return m.group(1)


def pending_consent_id(c: TestClient) -> str:
    """The id of the consent page this browser last opened (it lives in the session cookie)."""
    cookie = c.cookies.get("sdm_session") or ""
    try:
        session = json.loads(base64.b64decode(cookie.split(".")[0]))
    except ValueError:
        return ""
    pending = session.get("mcp_auth")
    return str(pending.get("consent_id") or "") if isinstance(pending, dict) else ""


def post(c: TestClient, path: str, **data):
    token = csrf(c)
    if path == "/oauth/authorize":
        # What the consent form itself submits. csrf() above loads another page, as a
        # person might in between, and that must not change which request is pending.
        data.setdefault("consent_id", pending_consent_id(c))
    return c.post(path, data={"csrf": token, **data})


def mcp_call(c: TestClient, tool: str, role: str = "viewer", **arguments) -> dict:
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }
    headers = {**MCP_HEADERS, "Authorization": f"Bearer {TOKENS[role]}"}
    r = c.post("/mcp", json=body, headers=headers)
    assert r.status_code == 200, r.text
    return r.json()["result"]

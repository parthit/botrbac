"""Shared setup for the Terminal tests."""

import time

import httpx
from starlette.testclient import TestClient

from botrbac_cli import state
from botrbac_cli.api import Api
from scoped_drive_mcp.server import build_app
from tests.conftest import BASE_URL, OWNER_EMAIL, make_settings


def terminal_app(world, memstore, oauth, **overrides):
    settings = make_settings(root_folder_id=None, allowlist_cache_ttl=0, **overrides)
    return build_app(
        settings,
        world.as_user(OWNER_EMAIL),
        store=memstore,
        owner_drive_factory=lambda token: world.as_user(OWNER_EMAIL),
        oauth=oauth,
    )


DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


def connect_terminal(c, role_id: str = "read-only", name: str = "laptop") -> dict:
    """Run the whole device flow as the signed-in person. Returns the token response."""
    from tests import dash

    started = c.post("/api/terminal/device", json={"hostname": "laptop", "os": "Linux"}).json()
    page = c.get("/device", params={"code": started["user_code"]})
    assert page.status_code == 200, page.text
    token = dash.csrf(c, f"/device?code={started['user_code']}")
    r = c.post(
        "/device/approve",
        data={"csrf": token, "code": started["user_code"], "role_id": role_id, "name": name},
    )
    assert r.status_code == 303, r.text
    issued = c.post(
        "/api/terminal/token",
        data={"grant_type": DEVICE_GRANT, "device_code": started["device_code"]},
    )
    assert issued.status_code == 200, issued.text
    return issued.json()


def bearer(issued: dict) -> dict:
    return {"Authorization": f"Bearer {issued['access_token']}"}


def http_client(app, online: dict | None = None) -> httpx.Client:
    """An httpx client the CLI's Api can use, talking to the app in-process. With
    `online={"on": False}` every request fails as if the network were down."""
    inner = TestClient(app, base_url=BASE_URL)

    def handler(request: httpx.Request) -> httpx.Response:
        if online is not None and not online["on"]:
            raise httpx.ConnectError("offline", request=request)
        r = inner.request(
            request.method, str(request.url), headers=request.headers, content=request.content
        )
        return httpx.Response(r.status_code, headers=r.headers, content=r.content)

    return httpx.Client(transport=httpx.MockTransport(handler))


def cli_api(app, online: dict | None = None) -> Api:
    return Api(BASE_URL, client=http_client(app, online))


class FakeApi:
    """Stands in for botrbac_cli.api.Api in sync tests. `send` is called with each audit
    body (raise ApiError from it to refuse); every body is kept in `bodies`."""

    def __init__(self, send=None):
        # A logged-in terminal whose server sends unsigned policies (as policy() does).
        if not state.read_json("credentials.json"):
            state.write_json("credentials.json", SELF_HOSTED, private=True)
        self.send = send
        self.bodies: list[dict] = []

    def send_audit(self, body):
        self.bodies.append(body)
        return self.send(body) if self.send else {}

    def policy(self):
        return {"role": {"id": "r", "patterns": ["*"]}, "roles": []}


# Logged in to a self-hosted server without ENCRYPTION_KEY: no policy key, unsigned policies.
SELF_HOSTED = {"server": "https://rbac.self-hosted.test", "refresh_token": "r"}


def cache_policy(
    patterns, *, name="Test role", role_id="r", roles=(), revoked=(), age=0.0, **role
) -> None:
    """Write policy.json as if fetched `age` seconds ago. The policy is unsigned, so
    unless the test logged in already this also writes the credentials of a self-hosted
    server that has never sent a policy key (the only case unsigned policies are used)."""
    if not state.read_json("credentials.json"):
        state.write_json("credentials.json", SELF_HOSTED, private=True)
    state.write_json(
        "policy.json",
        {
            "policy": {
                "email": "me@example.com",
                "role": {"id": role_id, "name": name, "patterns": patterns, **role},
                "roles": list(roles),
                "revoked_sessions": list(revoked),
                "version": "v1",
            },
            "fetched_at": time.time() - age,
        },
    )


class StubSession:
    """An upstream MCP server's client session, in-process: records calls, and raises
    `fail` from call_tool when set."""

    def __init__(self, fail: Exception | None = None):
        self.fail = fail
        self.calls: list[tuple[str, dict]] = []

    async def call_tool(self, name, arguments):
        from mcp import types

        self.calls.append((name, arguments))
        if self.fail:
            raise self.fail
        return types.CallToolResult(content=[types.TextContent(type="text", text=f"ran {name}")])


def stub_upstream(server: str, *tool_names: str, session: StubSession | None = None):
    from mcp import types

    from botrbac_cli.gateway import Upstream

    tools = [types.Tool(name=n, inputSchema={"type": "object"}) for n in tool_names]
    return Upstream(server, session=session or StubSession(), tools=tools)  # type: ignore[arg-type]

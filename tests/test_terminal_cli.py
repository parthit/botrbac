"""Terminal, phase 5: the botrbac CLI, gateway, offline cache and sync."""

import os
import sys
import time
from contextlib import AsyncExitStack
from pathlib import Path

import httpx
import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from starlette.testclient import TestClient

from botrbac_cli import policy, state
from botrbac_cli.api import Api
from botrbac_cli.gateway import Gateway
from botrbac_cli.main import main
from botrbac_cli.queue import AuditQueue
from botrbac_cli.sync import sync
from tests import dash
from tests.conftest import BASE_URL, OWNER_EMAIL
from tests.terminal_helpers import terminal_app

FAKE = str(Path(__file__).parent / "fixtures" / "fake_upstream.py")
UPSTREAM = {"github": {"command": sys.executable, "args": [FAKE]}}


@pytest.fixture(autouse=True)
def botrbac_home(tmp_path, monkeypatch):
    monkeypatch.setenv("BOTRBAC_HOME", str(tmp_path / "botrbac"))
    monkeypatch.delenv(policy.SESSION_ENV, raising=False)
    return tmp_path / "botrbac"


def _cache(patterns, *, name="Test role", offline_days=7, age=0.0, revoked=()):
    state.write_json(
        "policy.json",
        {
            "policy": {
                "email": "me@example.com",
                "role": {
                    "id": "r",
                    "name": name,
                    "patterns": patterns,
                    "offline_days": offline_days,
                },
                "roles": [],
                "revoked_sessions": list(revoked),
                "version": "v1",
            },
            "fetched_at": time.time() - age,
        },
    )


def test_enforcer_fails_closed() -> None:
    enforcer = policy.Enforcer()
    assert not enforcer.decide("github/get_issue").allowed  # no policy yet
    _cache(["github/get_*"])
    assert enforcer.decide("github/get_issue").allowed
    denied = enforcer.decide("github/delete_repo")
    assert not denied.allowed and "Test role" in denied.reason
    _cache(["*"], offline_days=2, age=3 * 86400)
    stale = enforcer.decide("github/get_issue")
    assert not stale.allowed and "offline" in stale.reason
    os.environ[policy.SESSION_ENV] = "missing-session"
    try:
        _cache(["*"])
        assert not policy.Enforcer().decide("github/get_issue").allowed
    finally:
        del os.environ[policy.SESSION_ENV]


def test_clock_moved_back_blocks() -> None:
    _cache(["*"], age=-3600)  # fetched an hour "in the future"
    decision = policy.Enforcer().decide("github/get_issue")
    assert not decision.allowed and "clock" in decision.reason


def test_name_clashes_keep_the_first_tool(capsys) -> None:
    from mcp import types

    from botrbac_cli.gateway import Upstream

    _cache(["*"])
    gateway = Gateway(policy.Enforcer(), AuditQueue())
    schema = {"type": "object"}
    tools = [
        types.Tool(name="a b", inputSchema=schema),
        types.Tool(name="a_b", inputSchema=schema),
    ]
    gateway.add(Upstream("srv", session=None, tools=tools))  # type: ignore[arg-type]
    assert gateway.routes["srv__a_b"].tool.name == "a b"
    assert "clashes" in capsys.readouterr().err


def test_policy_is_fetched_even_when_upload_fails() -> None:
    class Api:
        def send_audit(self, body):
            raise RuntimeError("500")

        def policy(self):
            return {"role": {"id": "r", "patterns": ["*"]}, "roles": []}

    queue = AuditQueue()
    queue.add(decision="allow", tool="github/get_issue")
    result = sync(Api(), queue)
    assert result["waiting"] == 1 and result["policy"] is True
    assert policy.load_cached()["policy"]["role"]["id"] == "r"


def test_queue_round_trip(botrbac_home) -> None:
    queue = AuditQueue()
    a = queue.add(decision="allow", tool="github/get_issue")
    queue.add(decision="deny", tool="github/delete_repo")
    assert queue.waiting() == 2
    queue.mark_sent([a["event_id"]])
    assert queue.waiting() == 1
    assert [r["tool"] for r in queue.pending()] == ["github/delete_repo"]
    assert (botrbac_home / "audit.db").exists()


@pytest.mark.anyio
async def test_gateway_filters_and_blocks() -> None:
    _cache(["github/get_*", "github/create_issue"])
    queue = AuditQueue()
    gateway = Gateway(policy.Enforcer(), queue, agent="test-agent")
    async with AsyncExitStack() as stack:
        await gateway.connect(stack, {**UPSTREAM, "broken": {"command": "/nonexistent/x"}})
        assert "broken" in gateway.failed
        names = [t.name for t in gateway.visible_tools()]
        assert names == ["github__create_issue", "github__get_issue"]

        ok = await gateway.call("github__get_issue", {"number": 7})
        assert not ok.isError and "issue 7" in ok.content[0].text
        blocked = await gateway.call("github__delete_repo", {"name": "x"})
        assert blocked.isError and "Blocked by Bot RBAC" in blocked.content[0].text
        unknown = await gateway.call("nope__x", {})
        assert unknown.isError

    rows = queue.pending()
    assert [(r["tool"], r["decision"]) for r in rows] == [
        ("github/get_issue", "allow"),
        ("github/delete_repo", "deny"),
        ("unknown/nope__x", "deny"),
    ]
    assert all(r["agent"] == "test-agent" and "number" not in r for r in rows)
    seen = state.read_json("state.json")["tools"]
    assert "github/delete_repo" in seen  # reported so the website can offer it


@pytest.mark.anyio
async def test_gateway_over_stdio(botrbac_home) -> None:
    """The real `botrbac gateway` process, as an agent starts it."""
    _cache(["github/get_*"])
    state.write_json("config.json", {"servers": UPSTREAM})
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "botrbac_cli", "gateway", "--agent", "stdio-test"],
        env={**os.environ, "BOTRBAC_HOME": str(botrbac_home)},
    )
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        tools = await session.list_tools()
        assert [t.name for t in tools.tools] == ["github__get_issue"]
        result = await session.call_tool("github__get_issue", {"number": 3})
        assert "issue 3" in result.content[0].text
        denied = await session.call_tool("github__delete_repo", {"name": "x"})
        assert denied.isError
    assert AuditQueue().waiting() == 2


def _flaky_api(app, online: dict) -> Api:
    inner = TestClient(app, base_url=BASE_URL)

    def handler(request: httpx.Request) -> httpx.Response:
        if not online["on"]:
            raise httpx.ConnectError("offline", request=request)
        r = inner.request(
            request.method, str(request.url), headers=request.headers, content=request.content
        )
        return httpx.Response(r.status_code, headers=r.headers, content=r.content)

    return Api(BASE_URL, client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_login_offline_and_sync_end_to_end(world, memstore, oauth) -> None:
    app = terminal_app(world, memstore, oauth)
    browser = dash.client(app)
    dash.login(browser)
    online = {"on": True}
    api = _flaky_api(app, online)

    started = api.start_login("laptop", "Linux")
    assert api.poll_login(started["device_code"]) == "authorization_pending"
    token = dash.csrf(browser, "/device")
    browser.post(
        "/device/approve",
        data={"csrf": token, "code": started["user_code"], "role_id": "read-only"},
    )
    assert isinstance(api.poll_login(started["device_code"]), dict)
    assert policy.refresh(api)["role"]["id"] == "read-only"

    enforcer = policy.Enforcer()
    queue = AuditQueue()
    assert enforcer.decide("github/get_issue").allowed
    assert not enforcer.decide("github/create_issue").allowed

    # Offline: rows wait, the cached policy still applies.
    online["on"] = False
    for tool in ("github/get_issue", "github/list_issues"):
        queue.add(decision="allow", tool=tool, agent="claude-code", role="Read-only")
    result = sync(api, queue)
    assert result["waiting"] == 2 and "error" in result
    assert enforcer.decide("github/get_issue").allowed

    # Past the grace period with no contact: everything is blocked.
    late = policy.Enforcer(clock=lambda: time.time() + 8 * 86400)
    assert not late.decide("github/get_issue").allowed

    # Back online: the queue drains once, and a resend is not stored twice.
    online["on"] = True
    pending = queue.pending()
    assert sync(api, queue) == {"sent": 2, "waiting": 0, "policy": True}
    again = api.send_audit({"rows": pending})
    assert again["duplicates"] == 2
    rows = app.state.terminal.activity.recent(OWNER_EMAIL)
    assert sorted(r["tool"] for r in rows) == ["github/get_issue", "github/list_issues"]
    (terminal,) = app.state.terminal.terminals.for_person(OWNER_EMAIL)
    assert terminal.queued == 0 and terminal.last_seen > 0

    # The access token is refreshed when it expires.
    creds = state.read_json("credentials.json")
    creds["expires_at"] = 0
    state.write_json("credentials.json", creds, private=True)
    assert api.policy()["role"]["id"] == "read-only"
    assert state.read_json("credentials.json")["access_token"] != creds["access_token"]
    assert oct((state.home() / "credentials.json").stat().st_mode & 0o777) == "0o600"

    # Another gateway refreshed first (its refresh token is now spent): use its tokens.
    stale = state.read_json("credentials.json")
    other = Api(BASE_URL, client=api.client)
    stale_expired = {**stale, "expires_at": 0}
    state.write_json("credentials.json", stale_expired, private=True)
    assert other.policy()["role"]["id"] == "read-only"  # other process refreshes
    rotated = state.read_json("credentials.json")
    assert rotated["refresh_token"] != stale["refresh_token"]
    assert api._token(force_refresh=True)  # picks up a fresh token, not "disconnected"

    # Disconnected on the website: the CLI says so.
    browser.post(
        f"/terminal/t/{terminal.id}/revoke", data={"csrf": dash.csrf(browser, "/terminal")}
    )
    creds = state.read_json("credentials.json")
    creds["expires_at"] = 0
    state.write_json("credentials.json", creds, private=True)
    assert policy.refresh(api) is None


def test_servers_command(capsys) -> None:
    assert main(["servers", "add", "My GitHub", "--", "npx", "-y", "server-github"]) == 0
    assert main(["servers", "add", "remote", "--url", "https://mcp.example.com/mcp"]) == 0
    servers = state.read_json("config.json")["servers"]
    assert servers["my-github"] == {"command": "npx", "args": ["-y", "server-github"]}
    assert servers["remote"] == {"url": "https://mcp.example.com/mcp"}
    main(["servers", "remove", "remote"])
    main(["servers", "list"])
    assert "my-github" in capsys.readouterr().out
    assert main(["status"]) == 1  # not logged in


def test_refresh_uses_what_another_process_just_got(monkeypatch) -> None:
    """Process A read the old credentials; B refreshed and saved new ones while A waited
    for the lock. A must use B's tokens, not spend the old refresh token."""
    from botrbac_cli import api as api_module

    old = {"refresh_token": "brt_rt_old", "access_token": "a-old", "expires_at": 0}
    new = {"refresh_token": "brt_rt_new", "access_token": "a-new", "expires_at": time.time() + 600}
    reads = iter([old, new])
    monkeypatch.setattr(api_module, "_creds", lambda: next(reads))

    def no_network(request):
        raise AssertionError("must not refresh again")

    client = Api(
        "https://x.example", client=httpx.Client(transport=httpx.MockTransport(no_network))
    )
    assert client._token() == "a-new"


def test_one_bad_row_does_not_cost_the_good_ones(capsys) -> None:
    from botrbac_cli.api import ApiError

    class Api:
        def __init__(self):
            self.stored = []

        def send_audit(self, body):
            if "tools" in body or any(r["tool"] == "bad/row" for r in body["rows"]):
                raise ApiError(400, "invalid_request")
            self.stored += [r["tool"] for r in body["rows"]]
            return {}

        def policy(self):
            return {"role": {"id": "r", "patterns": ["*"]}, "roles": []}

    state.note_seen(tools=["github/get_issue"])
    queue = AuditQueue()
    for tool in ("github/a", "bad/row", "github/b", "github/c"):
        queue.add(decision="allow", tool=tool)
    api = Api()
    result = sync(api, queue)
    assert sorted(api.stored) == ["github/a", "github/b", "github/c"]
    assert result["rejected"] == 1 and result["waiting"] == 0
    assert queue.rejected() == 1
    assert "refused 1 audit row" in capsys.readouterr().err
    assert [r["status"] for r in queue.recent() if r["tool"] == "bad/row"] == ["rejected"]
    assert queue.requeue_rejected() == 1 and queue.waiting() == 1


def test_a_server_refusing_everything_keeps_the_rows() -> None:
    from botrbac_cli.api import ApiError

    class Broken:
        def send_audit(self, body):
            raise ApiError(400, "invalid_request")

        def policy(self):
            return {"role": {"id": "r", "patterns": ["*"]}, "roles": []}

    queue = AuditQueue()
    for tool in ("github/a", "github/b"):
        queue.add(decision="allow", tool=tool)
    result = sync(Broken(), queue)
    assert result["waiting"] == 2 and "error" in result and queue.rejected() == 0


def test_temporary_errors_keep_the_rows() -> None:
    from botrbac_cli.api import ApiError

    class Down:
        def send_audit(self, body):
            raise ApiError(503, "unavailable")

        def policy(self):
            return {"role": {"id": "r", "patterns": ["*"]}, "roles": []}

    queue = AuditQueue()
    queue.add(decision="allow", tool="github/get_issue")
    assert sync(Down(), queue)["waiting"] == 1

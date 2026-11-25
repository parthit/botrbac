"""The botrbac CLI: login, the policy cache, the gateway, the audit queue and sync."""

import asyncio
import json
import os
import sys
import time
from contextlib import AsyncExitStack
from pathlib import Path

import pytest
from mcp import ClientSession, types
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.shared.memory import create_connected_server_and_client_session

from botrbac_cli import policy, state
from botrbac_cli.api import Api, ApiError, NotLoggedIn
from botrbac_cli.check import check
from botrbac_cli.gateway import Gateway
from botrbac_cli.main import main
from botrbac_cli.queue import AuditQueue
from botrbac_cli.sync import sync
from tests import dash
from tests.conftest import BASE_URL, OWNER_EMAIL
from tests.terminal_helpers import (
    FakeApi,
    StubSession,
    cache_policy,
    cli_api,
    http_client,
    stub_upstream,
    terminal_app,
)

FAKE = str(Path(__file__).parent / "fixtures" / "fake_upstream.py")
UPSTREAM = {"github": {"command": sys.executable, "args": [FAKE]}}


@pytest.fixture(autouse=True)
def botrbac_home(tmp_path, monkeypatch):
    monkeypatch.setenv("BOTRBAC_HOME", str(tmp_path / "botrbac"))
    monkeypatch.delenv(policy.SESSION_ENV, raising=False)
    return tmp_path / "botrbac"


def _queue(*tools: str) -> AuditQueue:
    queue = AuditQueue()
    for tool in tools:
        queue.add(decision="allow", tool=tool)
    return queue


def _hook(tool: str) -> str:
    return json.dumps({"tool_name": tool, "tool_input": {}})


# ---- the whole journey ---------------------------------------------------------------


@pytest.fixture
def logged_in(world, memstore, oauth, monkeypatch, capsys):
    """Runs `botrbac login` against the app; the person approves the code on the website
    (as Read-only) while the command waits. Returns (app, browser, online switch)."""
    from botrbac_cli import main as cli

    app = terminal_app(world, memstore, oauth)
    browser = dash.client(app)
    dash.login(browser)
    online = {"on": True}
    client = http_client(app, online)
    monkeypatch.setattr(cli, "Api", lambda server=None: Api(server, client=client))
    sleeps = []

    def approve_on_second_wait(_seconds):
        sleeps.append(_seconds)
        if len(sleeps) == 2:  # the first poll saw "pending"; now the person approves
            code = capsys.readouterr().out.split("Code: ", 1)[1].split()[0]
            token = dash.csrf(browser, f"/device?code={code}")
            r = browser.post(
                "/device/approve", data={"csrf": token, "code": code, "role_id": "read-only"}
            )
            assert r.status_code == 303

    monkeypatch.setattr(cli.time, "sleep", approve_on_second_wait)
    assert main(["login", "--server", BASE_URL]) == 0
    assert capsys.readouterr().out.strip().endswith(f"Logged in as {OWNER_EMAIL}, role Read-only")
    assert state.read_json("credentials.json")["policy_key"]  # signed policies from now on
    return app, browser, online


def test_terminal_journey_end_to_end(logged_in, capsys) -> None:
    """What a person does: `botrbac login`, approve the code on the website, then the
    agent's hook and the gateway allow what the role allows and block the rest, and
    `botrbac sync` puts every decision on the website."""
    app, browser, _ = logged_in

    # The hook: Claude Code's own tools.
    assert check("claude-code", _hook("Read"), None, False)[0]
    allowed, reason = check("claude-code", _hook("Write"), None, False)
    assert not allowed and "Read-only" in reason

    # The gateway, as an MCP client sees it.
    gw = Gateway(policy.Enforcer(), AuditQueue())
    upstream = stub_upstream("github", "get_issue", "delete_repo")
    gw.add(upstream)

    async def agent_session():
        info = types.Implementation(name="Claude Code", version="1")
        async with create_connected_server_and_client_session(
            gw.server(), client_info=info
        ) as session:
            listed = await session.list_tools()
            ok = await session.call_tool("github__get_issue", {"number": 1})
            denied = await session.call_tool("github__delete_repo", {"name": "x"})
            return [t.name for t in listed.tools], ok, denied

    names, ok, denied = asyncio.run(agent_session())
    assert names == ["github__get_issue"]
    assert not ok.isError and denied.isError and "Blocked by Bot RBAC" in denied.content[0].text
    assert upstream.session.calls == [("get_issue", {"number": 1})]

    assert main(["sync"]) == 0
    assert "Sent 4 rows. 0 waiting." in capsys.readouterr().out
    rows = app.state.terminal.activity.recent(OWNER_EMAIL)
    assert sorted((r["tool"], r["decision"], r["agent"]) for r in rows) == [
        ("claude-code/Read", "allow", "claude-code"),
        ("claude-code/Write", "deny", "claude-code"),
        ("github/delete_repo", "deny", "Claude-Code"),  # named from the MCP client
        ("github/get_issue", "allow", "Claude-Code"),
    ]
    assert "github/delete_repo" in browser.get("/terminal/activity?blocked=1").text
    assert "get_issue" in browser.get("/terminal/roles/new").text  # tools seen, offered

    assert main(["status"]) == 0
    out = capsys.readouterr().out
    assert f"Account:  {OWNER_EMAIL}" in out and "Role:     Read-only" in out
    assert "online" in out and "Waiting:  0 audit rows" in out
    assert main(["log"]) == 0
    log = capsys.readouterr().out
    assert "deny    claude-code/Write" in log and "not sent yet" not in log

    assert main(["logout"]) == 0
    assert state.read_json("credentials.json") is None and policy.load_cached() is None
    assert main(["status"]) == 1
    assert not check("claude-code", _hook("Read"), None, False)[0]  # no policy: fail closed


def test_offline_refresh_and_disconnect_end_to_end(logged_in) -> None:
    app, browser, online = logged_in
    api = cli_api(app, online)
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
    assert main(["sync"]) == 1  # the command says so too

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
    state.write_json("credentials.json", {**stale, "expires_at": 0}, private=True)
    assert other.policy()["role"]["id"] == "read-only"  # other process refreshes
    rotated = state.read_json("credentials.json")
    assert rotated["refresh_token"] != stale["refresh_token"]
    assert api._token(force_refresh=True)  # picks up a fresh token, not "disconnected"

    # Disconnected on the website while the access token is still unexpired: the server
    # answers 401, the refresh is refused, and the CLI says it was disconnected.
    browser.post(
        f"/terminal/t/{terminal.id}/revoke", data={"csrf": dash.csrf(browser, "/terminal")}
    )
    assert policy.refresh(api) is None
    with pytest.raises(NotLoggedIn, match="disconnected on the website"):
        api.policy()


def test_refresh_uses_what_another_process_just_got(monkeypatch) -> None:
    """Process A read the old credentials; B refreshed and saved new ones while A waited
    for the lock. A must use B's tokens, not spend the old refresh token."""
    import httpx

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


# ---- the policy cache ----------------------------------------------------------------


def test_enforcer_fails_closed(monkeypatch) -> None:
    enforcer = policy.Enforcer()
    assert not enforcer.decide("github/get_issue").allowed  # no policy yet
    cache_policy(["github/get_*"])
    assert enforcer.decide("github/get_issue").allowed
    denied = enforcer.decide("github/delete_repo")
    assert not denied.allowed and "Test role" in denied.reason
    cache_policy(["*"], offline_days=2, age=3 * 86400)
    stale = enforcer.decide("github/get_issue")
    assert not stale.allowed and "offline" in stale.reason
    cache_policy(["*"], age=-3600)  # fetched an hour "in the future"
    moved_back = enforcer.decide("github/get_issue")
    assert not moved_back.allowed and "clock" in moved_back.reason
    cache_policy(["*"])
    monkeypatch.setenv(policy.SESSION_ENV, "missing-session")
    assert not policy.Enforcer().decide("github/get_issue").allowed


# ---- the gateway ---------------------------------------------------------------------


@pytest.mark.anyio
async def test_gateway_filters_and_blocks() -> None:
    cache_policy(["github/get_*", "github/create_issue"])
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
async def test_gateway_syncs_in_the_background(monkeypatch) -> None:
    """The running gateway sends its own rows: sync runs in a worker thread while the
    event loop keeps adding rows to the same queue (a SQLite connection that refused
    other threads once made every background sync fail, silently)."""
    monkeypatch.setattr("botrbac_cli.gateway.SYNC_EVERY", 0.01)
    cache_policy(["github/*"])
    api = FakeApi()
    queue = AuditQueue()
    gateway = Gateway(policy.Enforcer(), queue, agent="test-agent", api=api)
    gateway.add(stub_upstream("github", "get_issue"))
    syncer = asyncio.create_task(gateway.keep_synced())
    try:
        for n in range(20):
            await gateway.call("github__get_issue", {"number": n})
            await asyncio.sleep(0)
        for _ in range(200):
            if queue.waiting() == 0:
                break
            await asyncio.sleep(0.01)
    finally:
        syncer.cancel()
    sent = [row["event_id"] for body in api.bodies for row in body["rows"]]
    assert queue.waiting() == 0 and len(sent) == len(set(sent)) == 20


@pytest.mark.anyio
async def test_gateway_over_stdio(botrbac_home) -> None:
    """The real `botrbac gateway` process, as an agent starts it."""
    cache_policy(["github/get_*"])
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


def test_name_clashes_keep_the_first_tool(capsys) -> None:
    cache_policy(["*"])
    gateway = Gateway(policy.Enforcer(), AuditQueue())
    gateway.add(stub_upstream("srv", "a b", "a_b"))
    assert gateway.routes["srv__a_b"].tool.name == "a b"
    assert "clashes" in capsys.readouterr().err


@pytest.mark.anyio
async def test_a_failing_upstream_is_an_error_not_a_crash() -> None:
    cache_policy(["*"])
    queue = AuditQueue()
    gateway = Gateway(policy.Enforcer(), queue, agent="t")
    gateway.add(stub_upstream("github", "get_issue", session=StubSession(fail=TimeoutError())))
    result = await gateway.call("github__get_issue", {})
    assert result.isError and "github failed: TimeoutError" in result.content[0].text
    (row,) = queue.pending()
    assert row["decision"] == "error" and row["reason"] == "TimeoutError"


# ---- the audit queue and sync --------------------------------------------------------


def test_queue_round_trip(botrbac_home) -> None:
    queue = AuditQueue()
    a = queue.add(decision="allow", tool="github/get_issue")
    queue.add(decision="deny", tool="github/delete_repo")
    assert queue.waiting() == 2
    queue.mark_sent([a["event_id"]])
    assert queue.waiting() == 1
    assert [r["tool"] for r in queue.pending()] == ["github/delete_repo"]
    assert (botrbac_home / "audit.db").exists()


def test_policy_is_fetched_even_when_upload_fails() -> None:
    def down(body):
        raise RuntimeError("500")

    result = sync(FakeApi(down), _queue("github/get_issue"))
    assert result["waiting"] == 1 and result["policy"] is True
    assert policy.load_cached()["policy"]["role"]["id"] == "r"


def test_one_bad_row_does_not_cost_the_good_ones(capsys) -> None:
    stored = []

    def refuse_bad(body):
        if "tools" in body or any(r["tool"] == "bad/row" for r in body["rows"]):
            raise ApiError(400, "invalid_request")
        stored.extend(r["tool"] for r in body["rows"])

    state.note_seen(tools=["github/get_issue"])
    queue = _queue("github/a", "bad/row", "github/b", "github/c")
    result = sync(FakeApi(refuse_bad), queue)
    assert sorted(stored) == ["github/a", "github/b", "github/c"]
    assert result["rejected"] == 1 and result["waiting"] == 0
    assert queue.rejected() == 1
    assert "refused 1 audit row" in capsys.readouterr().err
    assert [r["status"] for r in queue.recent() if r["tool"] == "bad/row"] == ["rejected"]
    assert "tools" not in (state.read_json("state.json") or {})  # refused report: dropped
    assert queue.requeue_rejected() == 1 and queue.waiting() == 1


@pytest.mark.parametrize("status", [400, 422, 503])
def test_a_server_refusing_everything_keeps_the_rows(status) -> None:
    """Permanent refusals of every row look like a bad deploy, not bad rows; temporary
    errors are offline. Either way nothing is set aside."""

    def refuse(body):
        raise ApiError(status, "x")

    queue = _queue("github/a", "github/b")
    result = sync(FakeApi(refuse), queue)
    assert result["waiting"] == 2 and "error" in result and queue.rejected() == 0


def test_a_server_refusing_everything_costs_few_requests() -> None:
    def refuse(body):
        raise ApiError(422, "x")

    api = FakeApi(refuse)
    queue = _queue(*(f"github/t{i}" for i in range(300)))
    result = sync(api, queue)
    assert len(api.bodies) <= 25 and result["waiting"] == 300 and queue.rejected() == 0


def test_refused_empty_report_does_not_loop() -> None:
    def refuse(body):
        raise ApiError(400, "invalid_request")

    state.note_seen(tools=["github/get_issue"])
    api = FakeApi(refuse)
    assert sync(api, AuditQueue())["waiting"] == 0  # nothing queued, only the tool report
    assert len(api.bodies) == 2


@pytest.mark.parametrize(
    ("bad", "syncs"),
    [
        ({10, 200, 390, 480}, 10),  # scattered: every sync makes progress
        (set(range(25)), 40),  # a run at the head does not wedge the queue
    ],
)
def test_bad_rows_never_wedge_the_queue(bad, syncs) -> None:
    bad_tools = {f"github/t{i}" for i in bad}
    stored = []

    def refuse_bad(body):
        if any(r["tool"] in bad_tools for r in body["rows"]):
            raise ApiError(422, "x")
        stored.extend(r["tool"] for r in body["rows"])

    queue = _queue(*(f"github/t{i}" for i in range(500)))
    waiting = [queue.waiting()]
    for _ in range(syncs):
        sync(FakeApi(refuse_bad), queue)
        waiting.append(queue.waiting())
        if not waiting[-1]:
            break
    assert waiting[-1] == 0
    assert all(b < a for a, b in zip(waiting, waiting[1:], strict=False))  # always progress
    assert queue.rejected() == len(bad) and len(stored) == 500 - len(bad)


def test_too_large_keeps_the_tool_report() -> None:
    def small_only(body):
        if len(body["rows"]) > 2:
            raise ApiError(413, "too_large")

    state.note_seen(tools=["github/get_issue"])
    queue = _queue(*(f"github/t{i}" for i in range(4)))
    api = FakeApi(small_only)
    sync(api, queue)
    accepted = [b for b in api.bodies if len(b["rows"]) <= 2]
    assert queue.waiting() == 0 and sum("tools" in b for b in accepted) == 1
    assert "tools" in (state.read_json("state.json") or {})


# ---- other commands ------------------------------------------------------------------


def test_servers_command(capsys) -> None:
    assert main(["servers", "add", "My GitHub", "--", "npx", "-y", "server-github"]) == 0
    assert main(["servers", "add", "remote", "--url", "https://mcp.example.com/mcp"]) == 0
    assert main(["servers", "add", "cmd", "--", "x"]) == 2  # reserved for cmd/ patterns
    servers = state.read_json("config.json")["servers"]
    assert servers["my-github"] == {"command": "npx", "args": ["-y", "server-github"]}
    assert servers["remote"] == {"url": "https://mcp.example.com/mcp"}
    assert "cmd" not in servers
    main(["servers", "remove", "remote"])
    main(["servers", "list"])
    assert "my-github" in capsys.readouterr().out
    assert main(["status"]) == 1  # not logged in

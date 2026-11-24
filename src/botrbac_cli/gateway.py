"""`botrbac gateway`: one MCP server in front of the person's other MCP servers.

Agents (Claude Code, Codex, Cursor, Gemini CLI, ...) connect to this over stdio. It
connects to each upstream server listed in config.json, exposes their tools as
`<server>__<tool>`, hides the tools the role does not allow, checks every call before
forwarding it, and writes one audit row per call (identifiers and decisions only).
"""

import asyncio
import contextlib
import logging
import os
import re
import sys
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any

from mcp import ClientSession, types
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamablehttp_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from . import __version__, policy, state
from .patterns import normalize_server
from .queue import AuditQueue

logger = logging.getLogger("botrbac.gateway")
SEPARATOR = "__"
SYNC_EVERY = 60.0
_UNSAFE = re.compile(r"[^A-Za-z0-9_.:-]")


def load_config() -> dict[str, Any]:
    data = state.read_json("config.json", {}) or {}
    servers = data.get("servers")
    return {"servers": servers if isinstance(servers, dict) else {}}


def safe_tool(name: str) -> str:
    return (_UNSAFE.sub("_", name) or "tool")[:128]


@dataclass
class Upstream:
    name: str
    session: ClientSession
    tools: list[types.Tool] = field(default_factory=list)


@dataclass
class Route:
    upstream: Upstream
    tool: types.Tool
    tool_id: str


class Gateway:
    def __init__(
        self,
        enforcer: policy.Enforcer,
        queue: AuditQueue,
        agent: str | None = None,
        api: Any = None,
    ):
        self.enforcer = enforcer
        self.queue = queue
        self.agent = agent
        self.api = api
        self.routes: dict[str, Route] = {}
        self.failed: dict[str, str] = {}

    # ---- upstream servers ------------------------------------------------------

    async def connect(self, stack: AsyncExitStack, servers: dict[str, Any]) -> None:
        for raw_name, spec in servers.items():
            name = normalize_server(str(raw_name))
            try:
                session = await stack.enter_async_context(_open(spec))
                await session.initialize()
                upstream = Upstream(name, session, await _all_tools(session))
            except Exception as exc:  # noqa: BLE001 - one broken server must not stop the rest
                self.failed[name] = type(exc).__name__
                print(f"botrbac: could not start {name}: {exc}", file=sys.stderr)
                continue
            self.add(upstream)

    def add(self, upstream: Upstream) -> None:
        for tool in upstream.tools:
            exposed = f"{upstream.name}{SEPARATOR}{safe_tool(tool.name)}"[:128]
            tool_id = f"{upstream.name}/{safe_tool(tool.name)}"
            if exposed in self.routes:
                # Two names that clean up the same ("a b" and "a_b"): keep the first, so
                # a role written for one never quietly applies to the other.
                print(
                    f"botrbac: skipped {upstream.name} tool {tool.name!r}: its name clashes "
                    f"with another tool as {exposed}",
                    file=sys.stderr,
                )
                continue
            self.routes[exposed] = Route(upstream, tool, tool_id)
        state.note_seen(tools=[r.tool_id for r in self.routes.values()])

    # ---- MCP handlers ----------------------------------------------------------

    def visible_tools(self) -> list[types.Tool]:
        out = []
        for exposed, route in sorted(self.routes.items()):
            if not self.enforcer.decide(route.tool_id).allowed:
                continue
            tool = route.tool
            out.append(
                types.Tool(
                    name=exposed,
                    title=tool.title,
                    description=f"[{route.upstream.name}] {tool.description or ''}".strip(),
                    inputSchema=tool.inputSchema,
                    outputSchema=tool.outputSchema,
                    annotations=tool.annotations,
                )
            )
        return out

    async def call(self, exposed: str, arguments: dict[str, Any]) -> types.CallToolResult:
        route = self.routes.get(exposed)
        if route is None:
            self.queue.add(
                decision="deny",
                reason="unknown tool",
                tool=f"unknown/{safe_tool(exposed)}",
                agent=self.agent or "mcp-client",
                via="gateway",
                **policy.session_fields(),
            )
            return _error(f"Unknown tool {exposed!r}.")
        decision = self.enforcer.decide(route.tool_id)
        row = {
            "tool": route.tool_id,
            "agent": self.agent or "mcp-client",
            "role": decision.role,
            "via": "gateway",
            **policy.session_fields(),
        }
        if not decision.allowed:
            self.queue.add(decision="deny", reason=decision.reason, **row)
            return _error(
                f"Blocked by Bot RBAC: {route.tool_id} is {decision.reason}. "
                "Ask the person to change the role on the Terminal page if this tool is needed."
            )
        try:
            result = await route.upstream.session.call_tool(route.tool.name, arguments)
        except Exception as exc:  # noqa: BLE001 - report to the agent, keep the gateway up
            self.queue.add(decision="error", reason=type(exc).__name__, **row)
            return _error(f"{route.upstream.name} failed: {type(exc).__name__}")
        self.queue.add(decision="allow", reason="error" if result.isError else "ok", **row)
        return result

    # ---- background sync -------------------------------------------------------

    async def keep_synced(self) -> None:
        from .sync import sync

        while True:
            if self.api is not None:
                with contextlib.suppress(Exception):
                    await asyncio.to_thread(sync, self.api, self.queue)
            await asyncio.sleep(SYNC_EVERY)

    def server(self) -> Server:
        app: Server = Server("botrbac", version=__version__)

        @app.list_tools()
        async def list_tools() -> list[types.Tool]:
            self._note_agent(app)
            return self.visible_tools()

        @app.call_tool(validate_input=False)
        async def call_tool(name: str, arguments: dict[str, Any]) -> types.CallToolResult:
            self._note_agent(app)
            return await self.call(name, arguments)

        return app

    def _note_agent(self, app: Server) -> None:
        if self.agent:
            return
        with contextlib.suppress(Exception):
            info = app.request_context.session.client_params.clientInfo  # type: ignore[union-attr]
            self.agent = re.sub(r"[^A-Za-z0-9_.-]", "-", info.name)[:40] or None


def _error(message: str) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)], isError=True
    )


async def _all_tools(session: ClientSession) -> list[types.Tool]:
    tools: list[types.Tool] = []
    cursor = None
    for _ in range(50):
        page = await session.list_tools(cursor) if cursor else await session.list_tools()
        tools.extend(page.tools)
        cursor = page.nextCursor
        if not cursor:
            break
    return tools


@contextlib.asynccontextmanager
async def _open(spec: dict[str, Any]):
    """A client session to one upstream: {command, args, env} or {url, headers}."""
    if spec.get("url"):
        async with (
            streamablehttp_client(str(spec["url"]), headers=dict(spec.get("headers") or {})) as (
                read,
                write,
                _,
            ),
            ClientSession(read, write) as session,
        ):
            yield session
        return
    params = StdioServerParameters(
        command=str(spec["command"]),
        args=[str(a) for a in spec.get("args") or []],
        env={**os.environ, **{str(k): str(v) for k, v in (spec.get("env") or {}).items()}},
        cwd=spec.get("cwd"),
    )
    async with (
        stdio_client(params, errlog=sys.stderr) as (read, write),
        ClientSession(read, write) as session,
    ):
        yield session


async def serve(agent: str | None, api: Any) -> None:
    gateway = Gateway(policy.Enforcer(), AuditQueue(), agent, api)
    if api is not None and gateway.enforcer.stale():
        await asyncio.to_thread(policy.refresh, api)
    async with AsyncExitStack() as stack:
        await gateway.connect(stack, load_config()["servers"])
        app = gateway.server()
        syncer = asyncio.create_task(gateway.keep_synced())
        try:
            async with stdio_server() as (read, write):
                await app.run(read, write, app.create_initialization_options())
        finally:
            syncer.cancel()
            if api is not None:
                from .sync import sync

                with contextlib.suppress(Exception):
                    await asyncio.to_thread(sync, api, gateway.queue)

"""What every tool module shares: the annotations a tool is listed with, and the helper
that runs blocking work off the event loop."""

from collections.abc import Callable
from functools import partial
from typing import Any

import anyio.to_thread
from mcp.types import ToolAnnotations

# `policy.require` with the access-request handler already bound (see server.create_mcp).
Guarded = Callable[[str], Callable[[Callable[..., Any]], Callable[..., Any]]]

READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False)
WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False)
DESTRUCTIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False)


async def _run[T](fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    # googleapiclient is blocking; anyio copies contextvars into the worker thread.
    return await anyio.to_thread.run_sync(partial(fn, *args, **kwargs))

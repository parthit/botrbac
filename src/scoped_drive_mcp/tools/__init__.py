"""The MCP tools, one module per group.

Each module has a `register(mcp, ...)` function that defines its tools on the FastMCP
server it is given. `server.create_mcp` calls them in a fixed order: clients see the
tools in the order they are registered. Every tool is wrapped by `policy.require` (some
through `guarded`, which adds the access-request link to a scope denial).
"""

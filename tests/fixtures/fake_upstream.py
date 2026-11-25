"""A tiny MCP server for the gateway tests (stdio)."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fake-github")


@mcp.tool()
def get_issue(number: int) -> str:
    """Read an issue."""
    return f"issue {number}"


@mcp.tool()
def create_issue(title: str) -> str:
    """Open an issue."""
    return f"created {title}"


@mcp.tool()
def delete_repo(name: str) -> str:
    """Delete a repository."""
    return f"deleted {name}"


if __name__ == "__main__":
    mcp.run("stdio")

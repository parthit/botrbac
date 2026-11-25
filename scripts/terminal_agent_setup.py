"""Write docs/terminal-agent-setup.md from the template the website serves at
/terminal/setup.md, so the two never drift. Run: uv run python scripts/terminal_agent_setup.py
"""

from pathlib import Path

from scoped_drive_mcp.terminal.feature import setup_markdown

OUT = Path(__file__).resolve().parent.parent / "docs" / "terminal-agent-setup.md"

if __name__ == "__main__":
    OUT.write_text(setup_markdown("https://botrbac.com"), encoding="utf-8")
    print(f"Wrote {OUT}")

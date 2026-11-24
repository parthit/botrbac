"""Bot RBAC Terminal: roles defined on the website, enforced by a local CLI.

A separate feature next to the hosted Drive server. It has its own pages, its own
`term:` store keys, and its own tokens and API. Nothing here changes how /mcp, the
existing pages or existing connections behave. See docs/terminal.md.
"""

from .feature import TerminalFeature

__all__ = ["TerminalFeature"]

"""Wrapping untrusted text (another person's file, a Notion page, a mailbox message) in
start and end markers that the text itself cannot forge.

Every marker this server writes has the shape ``<<<...>>>`` on one line. Before a body is
wrapped, any run of that shape inside it has its brackets swapped for look-alikes, so the
body can neither close its own block early nor open a fake one, including with a marker
that hides an invisible character (a zero-width space) inside. A ``>>>`` or ``<<<`` on its
own (a shift operator, a here-string, a merge-conflict line) is left as it is.
"""

import re

_MARKER_SHAPE = re.compile(r"<<<[^<>\n]{0,200}>>>")


def _defang(match: re.Match[str]) -> str:
    return match.group(0).replace("<<<", "‹‹‹").replace(">>>", "›››")


def defang_markers(text: str) -> str:
    """`text` with every marker-shaped run made harmless."""
    return _MARKER_SHAPE.sub(_defang, text)


def wrap(text: str, start: str, end: str) -> str:
    """`text` between `start` and `end`, which nothing inside it can imitate."""
    return f"{start}\n{defang_markers(text)}\n{end}"

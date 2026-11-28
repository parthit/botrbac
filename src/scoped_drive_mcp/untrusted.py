"""Wrapping untrusted text (another person's file, a Notion page, a mailbox message) in
start and end markers that the text itself cannot forge.

Every marker this server writes looks like ``<<<SOME WORDS>>>``. Before a body is wrapped:

- Anything inside it that a model would read as one of those markers becomes
  ``[removed-marker]``. "Would read as" is decided on a normalised copy: invisible
  characters (zero-width spaces, joiners, bidi controls, soft hyphens) removed, NFKC applied
  (so fullwidth ``＜`` is ``<``), look-alike brackets (``‹ 〈 《 ﹤``) read as ``<``, spaces
  collapsed and case ignored, with any number of brackets, or none at the end.
- Any other run of three or more opening brackets has them swapped for ``‹``, so the
  body cannot open a block of its own either. ``>>>`` (a shift operator) and ``<<`` (a
  here-document) are left as they are; ``<<<`` in code reads as ``‹‹‹``.
"""

import re
import unicodedata

# Unicode format characters that render as nothing (category Cf) and a few others that
# do the same: they could sit inside a marker without a model seeing them.
_INVISIBLE_RANGES = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160),
    (0x17B4, 0x17B5), (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E),
    (0x2060, 0x206F), (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
)  # fmt: skip
# As a regex character class body, with escapes so no invisible character is in this file.
_INVISIBLE = "".join(
    f"\\u{lo:04x}" if lo == hi else f"\\u{lo:04x}-\\u{hi:04x}" for lo, hi in _INVISIBLE_RANGES
)
# "<" and what renders like it: ‹ 〈 《 ﹤ fullwidth ＜ ⟨ 〈 (and the closing ones).
_OPEN = "".join(map(chr, (0x3C, 0x2039, 0x3008, 0x300A, 0xFE64, 0xFF1C, 0x27E8, 0x2329)))
_CLOSE = "".join(map(chr, (0x3E, 0x203A, 0x3009, 0x300B, 0xFE65, 0xFF1E, 0x27E9, 0x232A)))
_INVISIBLE_RE = re.compile(f"[{_INVISIBLE}]")
# Three or more opening brackets (invisible characters between them allowed), and a run of
# closing ones.
_OPEN_RUN = re.compile(rf"(?:[{_OPEN}][{_INVISIBLE}]*){{3,}}")
_CLOSE_RUN = re.compile(rf"(?:[{_CLOSE}][{_INVISIBLE}]*)+")
# How far past the opening brackets a marker's words may reach.
_MAX_MARKER = 1000
_OPEN_TO_ANGLE = str.maketrans({c: "<" for c in _OPEN} | {c: ">" for c in _CLOSE})
_SAFE_BRACKETS = str.maketrans({c: "‹" for c in _OPEN if c != "‹"})

# Every marker the server writes, registered by the modules that define them, so a page
# from one source cannot carry another source's end marker either.
_KNOWN: set[str] = set()


def _words(text: str) -> str:
    """What a model reads inside a marker: brackets, invisible characters, width and case
    differences and extra spaces taken away."""
    plain = unicodedata.normalize("NFKC", _INVISIBLE_RE.sub("", text)).translate(_OPEN_TO_ANGLE)
    return " ".join(plain.strip().strip("<>").split()).upper()


def _first_words(count: int) -> re.Pattern[str]:
    """The first `count` space-separated words (a word may hold invisible characters)."""
    return re.compile(rf"\s*\S+(?:\s+\S+){{{count - 1}}}")


def register(*markers: str) -> None:
    """Markers this server writes around untrusted text."""
    _KNOWN.update(_words(m) for m in markers)


def defang_markers(text: str, *markers: str) -> str:
    """`text` with every marker-shaped run made harmless (see the module docstring)."""
    known = _KNOWN | {_words(m) for m in markers}

    out: list[str] = []
    pos = 0
    while (opening := _OPEN_RUN.search(text, pos)) is not None:
        # The marker runs to the first closing brackets on the same line, or to the end
        # of the line, at most _MAX_MARKER characters on. The next search starts after
        # it, so each character is looked at a bounded number of times.
        stop = text.find("\n", opening.end(), opening.end() + _MAX_MARKER)
        stop = stop if stop != -1 else min(len(text), opening.end() + _MAX_MARKER)
        closing = _CLOSE_RUN.search(text, opening.end(), stop)
        end = closing.end() if closing else stop
        found = text[opening.start() : end]
        out.append(text[pos : opening.start()])
        words = _words(found)
        if words in known:
            # A forged marker and nothing else (with or without closing brackets).
            out.append("[removed-marker]")
        elif prefix := next((k for k in known if words.startswith(k + " ")), None):
            # A real marker's words followed by more text on the line: the marker's
            # words go, the rest of the line stays.
            after = found[opening.end() - opening.start() :]
            cut = _first_words(len(prefix.split())).match(after)
            rest = after[cut.end() :] if cut else ""
            out.append("[removed-marker]" + rest.translate(_SAFE_BRACKETS))
        else:
            # Shaped like a marker but not one: its text stays, opening brackets swapped.
            out.append(found.translate(_SAFE_BRACKETS))
        pos = end
    out.append(text[pos:])
    return "".join(out)


def wrap(text: str, start: str, end: str) -> str:
    """`text` between `start` and `end`, which nothing inside it can imitate."""
    register(start, end)
    return f"{start}\n{defang_markers(text, start, end)}\n{end}"

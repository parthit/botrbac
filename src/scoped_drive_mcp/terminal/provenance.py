"""Provenance fields on Terminal audit rows: where a call came from and how it ended.

All optional, so rows from older CLIs are accepted as they are. In the clear (metadata,
like the hostname): the agent's own ids, the permission mode, the cwd and the git
checkout (`repo` as host/owner/name, `branch`, `head`), and a result row's outcome and
sizes. Sealed, and kept only while "Record commands" is on and only if they open for
this row and field: `task` (`botrbac run --task`). A `description` (the model's own
summary of its command) is never stored: rows from CLIs that sent one lose it here.
`input_digest` and `input_size` are kept only while recording is on, as they describe
the recorded command.
"""

import re
from typing import Any

from botrbac_cli import sealing

ID_FIELDS = (
    "agent_session_id",
    "prompt_id",
    "tool_use_id",
    "agent_id",
    "agent_type",
    "parent_agent_id",
)
SEALED_FIELDS = ("task",)
# Every field this module may add, in the order exports list them.
FIELDS = (
    *ID_FIELDS,
    "permission_mode",
    "cwd",
    "repo",
    "branch",
    "head",
    "task",
    "input_digest",
    "input_size",
    "outcome",
    "exit_code",
    "duration_ms",
    "result_size",
)
_PID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_MODE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_ABSOLUTE = re.compile(r"^(/|[A-Za-z]:[\\/])")
_REPO = re.compile(r"^[a-z0-9.-]+(/[A-Za-z0-9._~-]+)+$")
_BRANCH = re.compile(r"^[A-Za-z0-9._/+@-]{1,200}$")
_HEAD = re.compile(r"^[0-9a-f]{7,64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
OUTCOMES = frozenset({"ok", "error"})
_INTS = {
    "exit_code": (-(2**31), 2**31),
    "duration_ms": (0, 10**10),
    "result_size": (0, 10**12),
    "input_size": (0, 10**12),
}


def _int(value: Any, name: str) -> int | None:
    low, high = _INTS[name]
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if low <= value <= high else None


def opens(command_key: Any, event_id: str, name: str, value: Any) -> bool:
    try:
        sealing.open_sealed(command_key, f"{event_id}:{name}", value)
    except sealing.SealError:
        return False
    return True


def clean_fields(raw: dict[str, Any], event_id: str, decision: str, command_key: Any) -> dict:
    """The provenance fields of `raw` worth keeping; anything malformed is left out."""
    out: dict[str, Any] = {}
    for name in ID_FIELDS:
        value = raw.get(name)
        if isinstance(value, str) and _PID.match(value):
            out[name] = value
    mode = raw.get("permission_mode")
    if isinstance(mode, str) and _MODE.match(mode):
        out["permission_mode"] = mode
    cwd = raw.get("cwd")
    if isinstance(cwd, str):
        cwd = _CONTROL.sub("", cwd)[:512]
        if _ABSOLUTE.match(cwd):
            out["cwd"] = cwd
    repo = raw.get("repo")
    if isinstance(repo, str) and len(repo) <= 200 and _REPO.match(repo) and ".." not in repo:
        out["repo"] = repo
    branch = raw.get("branch")
    if isinstance(branch, str) and _BRANCH.match(branch):
        out["branch"] = branch
    head = raw.get("head")
    if isinstance(head, str) and _HEAD.match(head):
        out["head"] = head
    if decision == "result":
        outcome = raw.get("outcome")
        if outcome in OUTCOMES:
            out["outcome"] = outcome
        for name in ("exit_code", "duration_ms", "result_size"):
            value = _int(raw.get(name), name)
            if value is not None:
                out[name] = value
    if command_key is not None:
        # Recording is on: the sealed text fields, and the digest of the command.
        for name in SEALED_FIELDS:
            value = raw.get(name)
            if isinstance(value, str) and opens(command_key, event_id, name, value):
                out[name] = value
        digest = raw.get("input_digest")
        if isinstance(digest, str) and _DIGEST.match(digest):
            out["input_digest"] = digest
            size = _int(raw.get("input_size"), "input_size")
            if size is not None:
                out["input_size"] = size
    return out

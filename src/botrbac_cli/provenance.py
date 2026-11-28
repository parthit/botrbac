"""Where a tool call came from: the agent's own ids, the folder and the git checkout.

An agent's hook sends JSON with more than the tool call: its session, the prompt the
call belongs to, the call's own id, the subagent that made it, the permission mode
and the working folder. `hook_fields()` keeps those, under botrbac's names, whatever
the agent calls them (Claude Code, Codex and Cursor differ). They are identifiers and
metadata, stored in the clear like the hostname; nothing here is user text.

`git_context()` adds the checkout the agent works in: the remote as host/owner/name
(no userinfo or token), the branch and the commit. It never fails the check.

Text the person wrote (the prompt, a `--task`) is never kept here: the caller seals it
(queue.AuditQueue.add). The model's own description of its command is not kept at all.
"""

import hashlib
import json
import os
import re
import subprocess
import time
from typing import Any

from . import state

# botrbac's name -> the keys agents send it under, first match wins.
ID_KEYS: dict[str, tuple[str, ...]] = {
    # The agent's own session id; botrbac's `session_id` is the `botrbac run` session.
    "agent_session_id": ("session_id", "sessionId", "conversation_id", "conversationId"),
    "prompt_id": ("prompt_id", "promptId", "turn_id", "turnId", "generation_id", "generationId"),
    "tool_use_id": ("tool_use_id", "toolUseId", "tool_call_id", "toolCallId", "call_id"),
    "agent_id": ("agent_id", "agentId"),
    "agent_type": ("agent_type", "agentType"),
    "parent_agent_id": ("parent_agent_id", "parentAgentId"),
}
_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_MODE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
MAX_CWD = 512


def event_name(payload: Any) -> str:
    if isinstance(payload, dict):
        for key in ("hook_event_name", "hookEventName"):
            value = payload.get(key)
            if isinstance(value, str):
                return value
    return ""


def clean_id(value: Any) -> str | None:
    if isinstance(value, int) and not isinstance(value, bool):
        value = str(value)
    return value if isinstance(value, str) and _ID.match(value) else None


def clean_cwd(value: Any) -> str | None:
    """An absolute path (POSIX or a Windows drive), control characters taken out."""
    if not isinstance(value, str):
        return None
    path = _CONTROL.sub("", value)[:MAX_CWD]
    if path.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", path):
        return path
    return None


def hook_fields(payload: Any) -> dict[str, Any]:
    """The ids, permission mode and cwd from a hook's JSON, under botrbac's names.
    Anything missing or malformed is left out."""
    if not isinstance(payload, dict):
        return {}
    out: dict[str, Any] = {}
    for name, keys in ID_KEYS.items():
        for key in keys:
            value = clean_id(payload.get(key))
            if value:
                out[name] = value
                break
    mode = payload.get("permission_mode") or payload.get("permissionMode")
    if isinstance(mode, str) and _MODE.match(mode):
        out["permission_mode"] = mode
    cwd = payload.get("cwd")
    if cwd is None:
        roots = payload.get("workspace_roots")  # Cursor
        cwd = roots[0] if isinstance(roots, list) and roots else None
    cwd = clean_cwd(cwd)
    if cwd:
        out["cwd"] = cwd
    return out


def input_digest(text: str) -> dict[str, Any]:
    """sha256 and size in bytes of the full input, before sealing cuts it at 8,000
    characters. Encoded the way sealing encodes it."""
    data = text.encode("utf-8", errors="replace")
    return {"input_digest": "sha256:" + hashlib.sha256(data).hexdigest(), "input_size": len(data)}


# ---- results ------------------------------------------------------------------------

# Not "status_code": a fetch tool's HTTP status is not a process exit code.
_EXIT_KEYS = ("exit_code", "exitCode", "returncode", "return_code")
_DURATION_KEYS = ("duration_ms", "durationMs")
_RESULT_KEYS = ("tool_response", "toolResponse", "tool_output", "output", "result")


def _int(value: Any, low: int, high: int) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    return value if isinstance(value, int) and low <= value <= high else None


def _find(blocks: list[Any], keys: tuple[str, ...], low: int, high: int) -> int | None:
    for block in blocks:
        if isinstance(block, dict):
            for key in keys:
                found = _int(block.get(key), low, high)
                if found is not None:
                    return found
    return None


_EXIT_TEXT = re.compile(r"^\s*Exit code (-?\d{1,10})\b")


def result_fields(payload: Any, failed: bool) -> dict[str, Any]:
    """outcome, exit_code, duration_ms and result_size for a finished call. Sizes only:
    the result's text is never kept."""
    payload = payload if isinstance(payload, dict) else {}
    response = next((payload[k] for k in _RESULT_KEYS if k in payload), None)
    if response is None and failed:
        response = payload.get("error")
    blocks = [response, payload]
    out: dict[str, Any] = {}
    exit_code = _find(blocks, _EXIT_KEYS, -(2**31), 2**31)
    if exit_code is None and failed:
        # Claude Code's PostToolUseFailure gives the shell's status only in its error
        # text ("Exit code 2\n…"). Keep the number, never the text.
        error = payload.get("error")
        match = _EXIT_TEXT.match(error) if isinstance(error, str) else None
        if match:
            exit_code = int(match.group(1))
    if exit_code is not None:
        out["exit_code"] = exit_code
    duration = _find(blocks, _DURATION_KEYS, 0, 10**10)
    if duration is not None:
        out["duration_ms"] = duration
    if response is not None:
        text = response if isinstance(response, str) else _json(response)
        out["result_size"] = len(text.encode("utf-8", errors="replace"))
    errored = isinstance(response, dict) and (
        response.get("is_error") is True
        or response.get("isError") is True
        or response.get("success") is False
        or response.get("interrupted") is True
    )
    out["outcome"] = "error" if failed or errored or exit_code not in (None, 0) else "ok"
    return out


def _json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        return str(value)


# ---- git ----------------------------------------------------------------------------

GIT_TIMEOUT = 1.0
GIT_CACHE = "git-cache.json"
GIT_CACHE_TTL = 5.0
_GIT_CACHE_MAX = 20
_HEX = re.compile(r"^[0-9a-f]{7,64}$")
_BRANCH = re.compile(r"[^A-Za-z0-9._/+@-]+")
_REPO_PART = re.compile(r"^[A-Za-z0-9._~-]+$")
# Repository config cannot make these commands run a program: rev-parse and config
# read refs and config only. fsmonitor is switched off anyway, and git never prompts.
_GIT = ("git", "--no-optional-locks", "-c", "core.fsmonitor=false")


def sanitize_remote(url: Any) -> str:
    """A git remote as host/owner/name: no scheme, userinfo, token, port, query or
    `.git`. A local path (no host) gives ""."""
    if not isinstance(url, str):
        return ""
    url = url.strip()
    if "://" in url:
        rest = url.split("://", 1)[1]
        authority, _, path = rest.partition("/")
    elif re.match(r"^[^/@:]+@[^/:]+:", url) or re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]+:[^/]", url):
        authority, _, path = url.partition(":")  # scp-like: git@github.com:o/r.git
    else:
        return ""
    host = authority.rsplit("@", 1)[-1]
    if host.startswith("["):
        return ""  # an IPv6 literal: not worth the trouble
    host = host.split(":", 1)[0].lower()
    path = re.split(r"[?#]", path, maxsplit=1)[0].strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    parts = [p for p in path.split("/") if p]
    if not host or not re.match(r"^[a-z0-9.-]+$", host) or not parts:
        return ""
    if not all(_REPO_PART.match(p) and p not in (".", "..") for p in parts):
        return ""
    return "/".join([host, *parts])[:200]


def _git(cwd: str, args: list[str], deadline: float) -> str | None:
    left = deadline - time.monotonic()
    if left <= 0:
        return None
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"}
    try:
        done = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [*_GIT, "-C", cwd, *args],
            capture_output=True,
            text=True,
            timeout=left,
            env=env,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    return done.stdout if done.returncode == 0 else None


def _read_git(cwd: str) -> dict[str, str]:
    deadline = time.monotonic() + GIT_TIMEOUT
    out: dict[str, str] = {}
    # The commit, then (after --abbrev-ref) the branch: "HEAD" when detached.
    refs = _git(cwd, ["rev-parse", "HEAD", "--abbrev-ref", "HEAD"], deadline)
    if refs is None:
        return out  # not a checkout, no commits yet, or no git
    lines = refs.split()
    if len(lines) == 2:
        if _HEX.match(lines[0]):
            out["head"] = lines[0]
        branch = _BRANCH.sub("", lines[1])[:200]
        if branch and branch != "HEAD":
            out["branch"] = branch
    remote = sanitize_remote(_git(cwd, ["config", "--get", "remote.origin.url"], deadline))
    if remote:
        out["repo"] = remote
    return out


def git_context(cwd: str | None) -> dict[str, str]:
    """repo, branch and head for `cwd`, or {} when there is none. Cached per folder for
    a few seconds, since an agent makes many calls in a row. Never raises."""
    if not cwd:
        return {}
    try:
        if not os.path.isdir(cwd):
            return {}
        now = time.time()
        # Read, then written back below without a lock: hooks running at once (subagents)
        # can drop each other's entries. Accepted: the cost is one more git call.
        cache = state.read_json(GIT_CACHE, {}) or {}
        if not isinstance(cache, dict):
            cache = {}
        hit = cache.get(cwd)
        if isinstance(hit, dict) and 0 <= now - float(hit.get("at", 0)) < GIT_CACHE_TTL:
            found = hit.get("git")
            if isinstance(found, dict):
                return {k: v for k, v in found.items() if k in ("repo", "branch", "head")}
        found = _read_git(cwd)
        fresh = {
            k: v
            for k, v in cache.items()
            if isinstance(v, dict) and 0 <= now - float(v.get("at", 0)) < GIT_CACHE_TTL
        }
        fresh[cwd] = {"at": now, "git": found}
        if len(fresh) > _GIT_CACHE_MAX:
            fresh = dict(sorted(fresh.items(), key=lambda kv: kv[1]["at"])[-_GIT_CACHE_MAX:])
        state.write_json(GIT_CACHE, fresh, private=True)
        return found
    except Exception:  # noqa: BLE001 - git context is a nice-to-have
        return {}


# ---- rows for the hooks that do not decide anything ---------------------------------


def prompt_row(agent: str, payload: Any) -> tuple[dict[str, Any], str | None]:
    """A `prompt` row (UserPromptSubmit) and the prompt text, which the caller seals."""
    row = {"decision": "prompt", "tool": "", "agent": agent, "via": "hook", "reason": ""}
    row.update(hook_fields(payload))
    text = payload.get("prompt") if isinstance(payload, dict) else None
    return row, text if isinstance(text, str) else None


def result_row(agent: str, tool_id: str, payload: Any, failed: bool) -> dict[str, Any]:
    """A `result` row (PostToolUse, PostToolUseFailure). No result text, ever."""
    row = {"decision": "result", "tool": tool_id, "agent": agent, "via": "hook", "reason": ""}
    row.update(hook_fields(payload))
    row.update(result_fields(payload, failed))
    return row

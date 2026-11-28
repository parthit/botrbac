"""Activity rows in plain words, for the Activity page.

The stored rows are made for audit (tool ids, ids, hashes). People reading the page
want to know what they asked, what the agent did, whether it was allowed, and what
to do about a block. This turns rows (already opened by `open_commands`) into
*stories*: one per prompt, holding the actions it led to, each with a sentence, the
command or file it touched, the agent's own reason, and how it ended. Everything
technical stays on the action, under "Details", and in the exports.
"""

import json
import posixpath
import re
from collections.abc import Iterable, Mapping
from typing import Any

AGENTS = {
    "claude-code": "Claude Code",
    "claude": "Claude",
    "codex": "Codex",
    "gemini": "Gemini CLI",
    "gemini-cli": "Gemini CLI",
    "cursor": "Cursor",
    "mcp-client": "An MCP client",
}

SHELL = {"Bash", "shell", "run_shell_command", "Shell", "exec_command", "execute"}
WRITE = {"Write", "write_file", "create_file"}
EDIT = {"Edit", "MultiEdit", "replace", "apply_patch", "edit_file", "NotebookEdit"}
READ = {"Read", "read_file", "read_many_files", "NotebookRead"}
SEARCH = {"Grep", "Glob", "LS", "list_directory", "glob", "search_file_content"}
VERBS = {
    "WebFetch": "Fetched a web page",
    "web_fetch": "Fetched a web page",
    "WebSearch": "Searched the web",
    "google_web_search": "Searched the web",
    "Agent": "Started a helper agent",
    "Task": "Started a helper agent",
    "TodoWrite": "Updated its to-do list",
}

_PROGRAMS = re.compile(r"^running (.+?) is not in role (.+)$")
_TOOL = re.compile(r"^not in role (.+)$")


def agent_name(agent: Any) -> str:
    agent = str(agent or "")
    return AGENTS.get(agent, agent or "An agent")


def _tool_parts(tool: str) -> tuple[str, str]:
    server, _, name = tool.partition("/")
    return server, name or tool


def _input(row: Mapping[str, Any]) -> dict[str, Any]:
    """A non-shell tool's input, when it was recorded (JSON text in `command`)."""
    try:
        value = json.loads(str(row.get("command") or ""))
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def _path(data: Mapping[str, Any]) -> str:
    for key in ("file_path", "path", "absolute_path", "notebook_path", "filePath"):
        if isinstance(data.get(key), str) and data[key]:
            return data[key]
    return ""


def action(row: Mapping[str, Any]) -> dict[str, Any]:
    """What one call did, in words: {sentence, shown, kind}. `shown` is the one
    thing worth reading (the command, or a file's name); None when not recorded."""
    tool = str(row.get("tool") or "")
    server, name = _tool_parts(tool)
    data = _input(row)
    path = _path(data)
    file_name = posixpath.basename(path) if path else ""
    if server == "cmd":
        return {"sentence": f"Ran {name}", "shown": None, "kind": "shell"}
    if name in SHELL:
        return {"sentence": "Ran a command", "shown": row.get("command"), "kind": "shell"}
    if name in WRITE:
        return {
            "sentence": f"Wrote the file {file_name}" if file_name else "Wrote a file",
            "shown": path or None,
            "kind": "file",
        }
    if name in EDIT:
        return {
            "sentence": f"Edited the file {file_name}" if file_name else "Edited a file",
            "shown": path or None,
            "kind": "file",
        }
    if name in READ:
        return {
            "sentence": f"Read the file {file_name}" if file_name else "Read a file",
            "shown": path or None,
            "kind": "file",
        }
    if name in SEARCH:
        pattern = data.get("pattern") or data.get("query") or ""
        return {
            "sentence": f"Searched files for {pattern!r}" if pattern else "Looked through files",
            "shown": None,
            "kind": "read",
        }
    if name in VERBS:
        url = data.get("url") or data.get("query") or data.get("description") or ""
        return {"sentence": VERBS[name], "shown": url or None, "kind": "other"}
    if server in AGENTS:
        return {"sentence": f"Used its {name} tool", "shown": None, "kind": "other"}
    # An MCP server's tool, through the gateway or seen by the hook.
    return {
        "sentence": f"Used {name.replace('_', ' ')} on {server}",
        "shown": None,
        "kind": "mcp",
    }


_TRIED = {
    "Ran": "run",
    "Wrote": "write",
    "Edited": "edit",
    "Read": "read",
    "Searched": "search",
    "Looked": "look",
    "Fetched": "fetch",
    "Started": "start",
    "Updated": "update",
    "Used": "use",
}


def tried(sentence: str) -> str:
    """ "Ran a command" -> "Tried to run a command", for a call that never happened."""
    first, _, rest = sentence.partition(" ")
    verb = _TRIED.get(first)
    return f"Tried to {verb} {rest}" if verb else sentence


def blocked_because(reason: Any, role: Any = "") -> dict[str, Any]:
    """Why a call was blocked, in words, and whether changing the role would fix it."""
    reason = str(reason or "").strip()
    m = _PROGRAMS.match(reason)
    if m:
        programs = [p.strip().removeprefix("cmd/") for p in m.group(1).split(",")]
        listed = ", ".join(programs)
        noun = "program" if len(programs) == 1 else "programs"
        return {
            "text": f"The role “{m.group(2)}” doesn't allow the {noun} {listed}.",
            "fix": "add " + ", ".join(f"cmd/{p}" for p in programs) + " to the role",
            "role_fix": True,
        }
    m = _TOOL.match(reason)
    if m:
        return {
            "text": f"The role “{m.group(1)}” doesn't allow this tool.",
            "fix": "add the tool to the role",
            "role_fix": True,
        }
    if reason == "protected file":
        return {
            "text": "It would have changed the agent's own settings or Bot RBAC's files. "
            "Agents are never allowed to do that, whatever the role.",
            "fix": "",
            "role_fix": False,
        }
    if "gateway" in reason:
        return {
            "text": "It used a tool server that doesn't go through Bot RBAC, so it couldn't "
            "be checked.",
            "fix": "run botrbac wrap on that computer",
            "role_fix": False,
        }
    if reason.startswith("botrbac"):
        return {
            "text": "Bot RBAC couldn't safely read this command, so it stopped it "
            f"({reason.removeprefix('botrbac ')}).",
            "fix": "run simpler commands, one program at a time",
            "role_fix": False,
        }
    return {"text": reason or "Blocked.", "fix": "", "role_fix": False}


def outcome(result: Mapping[str, Any] | None) -> str:
    """How a call ended, from its result row: "Finished in 89 ms", "Failed (exit code 2)"."""
    if not result:
        return ""
    ms = result.get("duration_ms")
    took = ""
    if isinstance(ms, int):
        took = f"{ms} ms" if ms < 1000 else f"{ms / 1000:.1f} s"
    if result.get("outcome") == "error":
        code = result.get("exit_code")
        detail = f"exit code {code}" if isinstance(code, int) else ""
        detail = ", ".join(p for p in (detail, took) if p)
        return f"Failed ({detail})" if detail else "Failed"
    return f"Finished in {took}" if took else "Finished"


def stories(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Rows (newest first) as stories, newest first. A prompt row heads the actions with
    its prompt id; a session row is a story of its own; a call's result row is folded
    into the call. Rows with no prompt id stand alone."""
    rows = list(rows)
    results = {
        r["tool_use_id"]: r for r in rows if r.get("decision") == "result" and r.get("tool_use_id")
    }
    used: set[str] = set()
    order: list[dict[str, Any]] = []
    by_prompt: dict[str, dict[str, Any]] = {}
    for row in rows:
        decision = row.get("decision")
        if decision == "result":
            continue
        if decision == "session":
            order.append({"kind": "session", "head": row, "steps": []})
            continue
        key = str(row.get("prompt_id") or "")
        if decision == "prompt":
            story = by_prompt.get(key) if key else None
            if story is None:
                story = {"kind": "prompt", "head": row, "steps": []}
                order.append(story)
                if key:
                    by_prompt[key] = story
            else:
                story["head"] = row
            continue
        item = dict(row)
        item["action"] = action(row)
        result = results.get(str(row.get("tool_use_id") or ""))
        if result is not None:
            used.add(str(row["tool_use_id"]))
            item["outcome"] = outcome(result)
            item["failed"] = result.get("outcome") == "error"
        if decision in ("deny", "error"):
            item["action"] = {**item["action"], "sentence": tried(item["action"]["sentence"])}
        if decision == "deny":
            item["blocked"] = blocked_because(row.get("reason"), row.get("role"))
        if not key:
            order.append({"kind": "single", "head": None, "steps": [item]})
            continue
        story = by_prompt.get(key)
        if story is None:
            story = {"kind": "prompt", "head": None, "steps": []}
            by_prompt[key] = story
            order.append(story)
        story["steps"].append(item)
    for story in order:
        heads = [story["head"]] if story["head"] else []
        all_rows = heads + story["steps"]
        story["agent"] = agent_name(next((r.get("agent") for r in all_rows if r.get("agent")), ""))
        story["terminal"] = next((r.get("terminal") for r in all_rows if r.get("terminal")), "")
        story["ts"] = max((r.get("ts") or 0) for r in all_rows) if all_rows else 0
        story["blocked"] = sum(1 for r in story["steps"] if r.get("decision") == "deny")
        story["failed"] = sum(1 for r in story["steps"] if r.get("failed"))
        story["steps"].reverse()  # oldest first inside a story: the order it happened
    return order


def trouble(row: Mapping[str, Any]) -> str:
    """A plain warning for a row whose record does not add up, or ""."""
    chain = row.get("chain")
    if chain == "gap":
        return (
            "Some earlier records from this computer haven't arrived. They may still be "
            "on their way, or they were deleted there."
        )
    if chain == "fork":
        return "This record doesn't match the computer's log: it may have been changed."
    return ""

"""Files an agent must not change, whatever its role.

Bot RBAC's own controls live in files on the computer: Claude Code's settings (which hold
the hook), ~/.claude.json (which lists the MCP servers, including the gateway) and
botrbac's own folder (the cached role, sessions, the login). An agent that could edit
those could switch Bot RBAC off or widen its own role, so tool calls that name them are
refused for every role. Reading is allowed, except for the login (it holds tokens).

This reads the tool call's text. It stops an agent that writes to these files the
ordinary way (Edit/Write, `sed -i`, `echo >`, `rm`, an MCP file tool); it cannot follow
a path the agent builds at run time (variables, base64, a script it writes elsewhere).
It guards against the agent, not the person who owns the computer.
"""

import fnmatch
import glob
import itertools
import os
import re
import shlex
from pathlib import Path
from typing import Any

from . import state

# Codex's, Gemini CLI's and Cursor's files that hold botrbac's hook or gateway.
OTHER_AGENT_FILES = (
    ".codex/hooks.json",
    ".codex/config.toml",
    ".gemini/settings.json",
    ".cursor/hooks.json",
    ".cursor/mcp.json",
)

# Tools that only read. They may look at protected files, but not at the login.
READ_TOOLS = frozenset(
    {"Read", "Grep", "Glob", "LS", "NotebookRead", "read_file", "read_many_files",
     "list_directory", "search_file_content", "glob"}
)  # fmt: skip
_READ_PREFIXES = ("read", "get", "list", "search", "find", "view", "glob", "grep", "stat")
# A name that starts like a read but also says it writes (`get_and_write`) is not one.
_WRITE_WORDS = ("write", "edit", "update", "create", "delete", "remove", "move", "rename",
                "set", "put", "save", "patch", "append", "replace")  # fmt: skip


def _variants(path: Path) -> set[str]:
    """How a path may be written in a command: absolute, ~/…, $HOME/…, ${HOME}/…"""
    text = str(path)
    out = {text}
    home = str(Path.home())
    if text.startswith(home + os.sep):
        rest = text[len(home) + 1 :]
        out |= {f"~/{rest}", f"$HOME/{rest}", f"${{HOME}}/{rest}"}
    return {v.lower() for v in out}


def markers() -> tuple[set[str], set[str]]:
    """(text that marks a protected file, text that marks the login). Lower case."""
    home = Path.home()
    protected = {
        # Claude Code settings anywhere (user, project, local), and its MCP server list.
        ".claude/settings.json",
        ".claude/settings.local.json",
        ".claude.json",
        # The other agents' hook files (agents.HOOK_FILES), and the ones that list the
        # gateway or can switch hooks off.
        *OTHER_AGENT_FILES,
        # botrbac's own folder, under its default name and wherever BOTRBAC_HOME puts it.
        ".config/botrbac",
    }
    protected |= _variants(home / ".claude" / "settings.json")
    for name in OTHER_AGENT_FILES:
        protected |= _variants(home / name)
    protected |= _variants(state.home())
    protected |= {
        # Switching hooks off, or taking botrbac's out, by command or by settings text.
        "disableallhooks",
        "hooks remove",
    }
    login = {"botrbac/credentials.json"} | _variants(state.home() / "credentials.json")
    return {m.lower() for m in protected}, {m.lower() for m in login}


def _targets() -> tuple[list[Path], Path]:
    """(protected files and folders, the login file), with symlinks resolved."""
    home, cwd = Path.home(), Path.cwd()
    files = [
        home / ".claude" / "settings.json",
        home / ".claude" / "settings.local.json",
        home / ".claude.json",
        cwd / ".claude" / "settings.json",
        cwd / ".claude" / "settings.local.json",
        *(base / name for base in (home, cwd) for name in OTHER_AGENT_FILES),
        state.home(),
    ]
    return [Path(os.path.realpath(f)) for f in files], Path(
        os.path.realpath(state.home() / "credentials.json")
    )


def _folders() -> tuple[set[Path], set[Path]]:
    """(folders that hold protected files, and the folders above them, which removing
    or moving would take the files along; home, the working folder and what is above
    them, which only `rm`/`mv` of the whole folder counts against)."""
    home, cwd = Path(os.path.realpath(Path.home())), Path(os.path.realpath(Path.cwd()))
    agent = {base / name for base in (home, cwd) for name in AGENT_FOLDERS}
    agent.add(Path(os.path.realpath(state.home())))
    broad = {home, cwd, *home.parents, *cwd.parents}
    folders = {
        p for d in agent for p in (d, *d.parents) if p not in broad
    }  # e.g. ~/.config for ~/.config/botrbac
    return folders, broad


# Agent folders under home and under the project.
AGENT_FOLDERS = (".claude", ".codex", ".gemini", ".cursor")
# Shell tools whose input is a command line (shellcmd.SHELL_TOOLS, by tool name).
SHELL_TOOLS = frozenset({"Bash", "shell", "run_shell_command", "exec_command", "local_shell"})
# Commands that only look. Anything else (or a `>` redirect) counts as a change.
_LOOK_COMMANDS = frozenset(
    {"ls", "cat", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "rg", "ag",
     "stat", "file", "wc", "du", "tree", "cd", "pushd", "popd", "pwd", "readlink",
     "realpath", "diff", "cmp", "md5sum", "sha256sum", "shasum", "jq", "bat", "test",
     "[", "find", "fd", "echo", "printf", "type", "which", "mkdir", "touch"}
)  # fmt: skip
_REMOVE_COMMANDS = frozenset({"rm", "rmdir", "mv", "unlink", "shred", "trash", "trash-put"})
_COPY_COMMANDS = frozenset({"cp", "rsync", "scp", "ln", "install"})
_PREFIX_COMMANDS = frozenset(
    {"sudo", "doas", "command", "builtin", "env", "nice", "nohup", "time", "exec"}
)  # fmt: skip
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish", "ash"})
_FIND_ACTIONS = ("-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fls")
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_GLOB = re.compile(r"[*?\[]")
_MAX_WORDS = 400

# (word, folder it is relative to, "look" | "remove" | "change")
Word = tuple[str, Path, str]


def _tokens(command: str) -> list[str]:
    """Shell words, quotes removed (`'sett''ings'` is `settings`), operators apart."""
    try:
        lex = shlex.shlex(command.replace("\n", ";"), posix=True, punctuation_chars=";&|()<>")
        lex.whitespace_split = True
        lex.commenters = ""
        return list(lex)
    except ValueError:  # unbalanced quotes: the raw words
        return command.split()


def _shell_words(command: str, base: Path, depth: int = 0) -> list[Word]:
    """The words of a command line, each with the folder it resolves against (following
    `cd DIR` through the line) and what its command does."""
    segments: list[list[str]] = [[]]
    for tok in _tokens(command)[: _MAX_WORDS * 4]:
        if tok and set(tok) <= set(";&|()"):
            segments.append([])
        else:
            segments[-1].append(tok)
    out: list[Word] = []
    for seg in segments:
        args = list(seg)
        while args and (_ASSIGNMENT.match(args[0]) or args[0] in _PREFIX_COMMANDS):
            args.pop(0)
        if not args:
            continue
        name = os.path.basename(args[0])
        rest = args[1:]
        if name in ("cd", "pushd"):
            target = next((a for a in rest if not a.startswith("-")), None)
            if target is None:
                base = Path.home()
            else:
                found = _resolved(target, base)
                base = found if found is not None else base
        if depth < 3 and name in _SHELLS and "-c" in rest[:-1]:
            out += _shell_words(rest[rest.index("-c") + 1], base, depth + 1)
        elif depth < 3 and name == "eval":
            out += _shell_words(" ".join(rest), base, depth + 1)
        if name in _REMOVE_COMMANDS:
            kind = "remove"
        elif name in _LOOK_COMMANDS and not any(
            t in (">", ">>") or t.startswith(_FIND_ACTIONS) for t in args
        ):
            kind = "look"
        else:
            kind = "change"
        last = max((i for i, a in enumerate(args) if not a.startswith("-")), default=0)
        for i, word in enumerate(args):
            # A commit message names paths without touching them, and a copy changes
            # only where it goes (`cp -r ~/.claude backup` is fine, `cp x ~/.claude` not).
            message = name == "git" and i > 0 and args[i - 1] in ("-m", "--message")
            source = name in _COPY_COMMANDS and i < last
            out.append((word, base, "look" if message or source else kind))
        if len(out) > _MAX_WORDS:
            break
    return out[:_MAX_WORDS]


def _expand(text: str) -> str:
    """`~`, `$HOME` and `${HOME}` at the start, as the shell would expand them."""
    for var in ("$HOME", "${HOME}"):
        if text == var or text.startswith(var + "/"):
            text = "~" + text[len(var) :]
    return os.path.expanduser(text)


def _resolved(text: str, base: Path | None = None) -> Path | None:
    if not text or "\0" in text or "://" in text or text.startswith("-"):
        return None
    try:
        path = Path(_expand(text))
        return Path(os.path.realpath(path if path.is_absolute() else (base or Path.cwd()) / path))
    except (OSError, ValueError, RuntimeError):
        return None


def _within(path: Path, target: Path) -> bool:
    return path == target or target in path.parents


def _pattern_parts(word: str, base: Path) -> list[str] | None:
    """A glob word as absolute parts, the fixed folders before the first glob resolved."""
    try:
        path = Path(_expand(word))
        parts = (path if path.is_absolute() else base / path).parts
    except (ValueError, RuntimeError):
        return None
    fixed = next((i for i, part in enumerate(parts) if _GLOB.search(part)), len(parts))
    try:
        head = Path(os.path.realpath(Path(*parts[:fixed]))).parts
    except (OSError, ValueError, RuntimeError):
        return None
    return [*head, *(p for p in parts[fixed:] if p not in ("", "."))]


def _glob_matches(parts: list[str], path: Path) -> bool:
    """Whether a glob (as parts) could name `path`, the way the shell matches."""
    names = path.parts
    if len(parts) != len(names):
        return False
    for pat, name in zip(parts, names, strict=True):
        if name.startswith(".") and not pat.startswith("."):
            return False  # `*` does not match a leading dot
        if not fnmatch.fnmatchcase(name, pat):
            return False
    return True


def _candidates(word: str, base: Path) -> tuple[list[Path], list[str] | None]:
    """(real paths a word names, its glob pattern as parts if it is one)."""
    one = _resolved(word, base)
    paths = [one] if one is not None else []
    if not _GLOB.search(word) or len(word) > 1024 or word.startswith("-"):
        return paths, None
    try:
        pattern = _expand(word)
        found = glob.iglob(pattern if os.path.isabs(pattern) else str(base / pattern))
        paths += [Path(os.path.realpath(p)) for p in itertools.islice(found, 50)]
    except (OSError, ValueError, RuntimeError, re.error):
        pass
    return paths, _pattern_parts(word, base)


def _words(tool: str, raw: list[str]) -> list[Word]:
    name = tool.rsplit("/", 1)[-1].rsplit("__", 1)[-1]
    cwd = Path.cwd()
    short = [t for t in raw if len(t) <= 100_000]
    kind = "look" if is_read_only(tool) else "change"
    # Each whole argument (a path with spaces) and each word of it (a command's paths).
    # Only whole arguments and shell words count against folders: a word in an edit's
    # text is not the path being changed.
    out: list[Word] = [(t, cwd, kind) for t in short if len(t) <= 4096]
    if name in SHELL_TOOLS:
        for text in short:
            out += _shell_words(text, cwd)
    out += [(w.strip("'\"<>;|&()"), cwd, "look") for t in short for w in t.split()]
    return out[: _MAX_WORDS * 2]


def _normalised(raw: list[str]) -> list[str]:
    """The text as written, as the shell reads it (quotes taken out, spaces collapsed),
    and with every quote dropped (`"disableAll""Hooks"`), all lower case."""
    out = []
    for text in raw:
        out.append(text.lower())
        if len(text) <= 100_000:
            out.append(" ".join(_tokens(text)).lower())
            out.append(" ".join(re.sub(r"[\'\"\\]", "", text).split()).lower())
    return out


def _strings(value: Any, depth: int = 0) -> list[str]:
    if depth > 6:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v, depth + 1)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v, depth + 1)]
    return []


def is_read_only(tool: str) -> bool:
    name = tool.rsplit("/", 1)[-1].rsplit("__", 1)[-1]
    if name in READ_TOOLS:
        return True
    lower = name.lower()
    words = re.split(r"[_\-.]+|(?<=[a-z])(?=[A-Z])", name)
    return lower.startswith(_READ_PREFIXES) and not any(
        w.lower().startswith(_WRITE_WORDS) for w in words[1:]
    )


def refusal(tool: str, arguments: Any) -> str | None:
    """Why this call must be refused, or None. `arguments` is the tool's input."""
    raw = _strings(arguments)
    if not raw:
        return None
    texts = _normalised(raw)
    protected, login = markers()
    targets, login_file = _targets()
    folders, broad = _folders()
    read_only = is_read_only(tool)
    found: str | None = None
    for word, base, kind in _words(tool, raw):
        paths, pattern = _candidates(word, base)
        if login_file in paths or (pattern and _glob_matches(pattern, login_file)):
            return "it names botrbac's login file, which holds its tokens"
        if read_only or found is not None:
            continue
        hit = next((p for p in paths for t in targets if _within(p, t)), None)
        if hit is None and kind != "look":
            hit = next(
                (p for p in paths if p in folders or (kind == "remove" and p in broad)),
                None,
            )
        if hit is None and pattern:
            hit = next((t for t in targets if _glob_matches(pattern, t)), None)
            if hit is None and kind != "look":
                hit = next((f for f in folders if _glob_matches(pattern, f)), None)
            if hit is None and kind == "remove":
                hit = next((b for b in broad if _glob_matches(pattern, b)), None)
        if hit is not None:
            found = str(hit)
    if any(m in t for t in texts for m in login):
        return "it names botrbac's login file, which holds its tokens"
    if read_only:
        return None
    found = next((m for t in texts for m in sorted(protected) if m in t), None) or found
    if found is not None:
        return (
            f"it mentions {found!r}, which Bot RBAC protects (an agent's hook or MCP "
            "settings, ~/.claude.json, botrbac's own folder, the folders that hold them, "
            "or switching hooks off). Ask the person to make that change"
        )
    return None

"""The programs a shell command runs, for `cmd/<program>` patterns.

An agent runs `gh pr list` through its shell tool (Claude Code's `Bash`), so the hook
sees one tool call holding a whole command line. `programs()` lists the programs that
line starts, conservatively: anything it cannot follow (command substitution, `eval`,
`bash -c '…'`, unbalanced quotes) raises CommandError, and the caller blocks the call.

It reads names, not binaries: `/tmp/gh` counts as `gh`. And a program that starts other
programs itself (`make`, `npm run`, `find -exec`, a script) runs whatever it runs. This
limits what an agent asks the shell to do; it is not a sandbox.
"""

import re
import shlex
from typing import Any

# Agent name -> the names of its shell tool. Add an agent here to check its commands.
SHELL_TOOLS: dict[str, frozenset[str]] = {
    "claude-code": frozenset({"Bash"}),
    "codex": frozenset({"shell"}),
    "gemini": frozenset({"run_shell_command"}),
    "gemini-cli": frozenset({"run_shell_command"}),
}

# Programs that run the next word as the program: `sudo gh`, `env X=1 gh`, `xargs gh`.
WRAPPERS = frozenset({"sudo", "env", "time", "nohup", "xargs", "command", "exec"})
SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish", "ash"})
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_SEPARATOR_CHARS = set(";&|\n")
_PROGRAM = re.compile(r"^[A-Za-z0-9_.+-]{1,64}$")
MAX_COMMAND = 100_000
# Never followed: they run text that is only known when the shell runs it.
_UNCHECKABLE = (
    ("$(", "command substitution $(…)"),
    ("`", "command substitution with backticks"),
    ("<(", "process substitution <(…)"),
    (">(", "process substitution >(…)"),
)


class CommandError(ValueError):
    """A command botrbac cannot check; the message says why (never the command)."""


def is_shell_tool(agent: str, tool: str) -> bool:
    return tool in SHELL_TOOLS.get(agent, frozenset())


def command_text(payload: Any) -> str | None:
    """The command line from a hook's JSON, or None when there is none.

    Codex sends argv, often `["bash", "-lc", "<script>"]`: that outer shell is the
    tool's own, so the script inside it is what gets checked."""
    if not isinstance(payload, dict):
        return None
    for key in ("tool_input", "toolInput", "input", "args", "arguments", "parameters"):
        block = payload.get(key)
        if isinstance(block, dict) and "command" in block:
            value = block["command"]
            break
    else:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, list) and value and all(isinstance(v, str) for v in value):
        if len(value) == 3 and _base(value[0]) in SHELLS and _is_c_flag(value[1]):
            return value[2]
        return shlex.join(value)
    return None


def _base(word: str) -> str:
    return word.rstrip("/").rsplit("/", 1)[-1]


def _is_c_flag(word: str) -> bool:
    """-c, -lc, -ic, -ec …: the shell runs the next argument as a script."""
    return word.startswith("-") and not word.startswith("--") and "c" in word[1:]


def _tokens(command: str) -> list[tuple[str, bool]]:
    """(token, is an operator). Quotes are honoured; `#` is not a comment here, so text
    after it is still checked."""
    lex = shlex.shlex(command, posix=True, punctuation_chars=";&|<>()\n")
    lex.whitespace = " \t\r"
    lex.whitespace_split = True
    lex.commenters = ""
    out: list[tuple[str, bool]] = []
    try:
        while True:
            token = lex.get_token()
            if token is None or token == lex.eof:
                break
            # shlex returns operators as runs of punctuation. A quoted ";" alone looks the
            # same and is read as an operator too, which can only make the check stricter.
            is_op = bool(token) and all(c in ";&|<>()\n" for c in token)
            out.append((token, is_op))
    except ValueError as exc:
        raise CommandError("botrbac could not read this command (unbalanced quotes)") from exc
    return out


def programs(command: str) -> list[str]:
    """Every program the command line starts, in order, without repeats."""
    if len(command) > MAX_COMMAND:
        raise CommandError("the command is too long to check")
    for needle, what in _UNCHECKABLE:
        if needle in command:
            raise CommandError(f"botrbac does not run commands that use {what}")
    found: list[str] = []
    expect_program = True
    skip_next = False  # the word after a redirect is a file name
    in_wrapper = False
    shell_running: str | None = None
    for word, is_op in _tokens(command):
        if is_op:
            if "(" in word or ")" in word:
                raise CommandError("botrbac does not check commands in ( … ) subshells")
            if "<" in word or ">" in word:
                skip_next = True
                continue
            if set(word) <= _SEPARATOR_CHARS:
                expect_program, in_wrapper, shell_running = True, False, None
                continue
            raise CommandError("botrbac could not read this command")
        if skip_next:
            skip_next = False
            continue
        if word == "eval":
            raise CommandError("botrbac does not run commands that use eval")
        if shell_running and _is_c_flag(word):
            raise CommandError(
                f"botrbac does not run {shell_running} -c: the script inside is not checked"
            )
        if not expect_program:
            continue
        if _ASSIGNMENT.match(word):
            continue  # FOO=1 gh …
        if in_wrapper and word.startswith("-"):
            continue  # sudo -E gh, env -i gh, xargs -n1 gh
        name = _base(word)
        if "$" in word or not _PROGRAM.fullmatch(name):
            raise CommandError("botrbac cannot tell which program this command runs")
        if name in WRAPPERS:
            in_wrapper = True  # checked as the program it runs, not as itself
            continue
        if name not in found:
            found.append(name)
        expect_program, in_wrapper = False, False
        shell_running = name if name in SHELLS else None
    if not found:
        raise CommandError("botrbac found no program in this command")
    return found

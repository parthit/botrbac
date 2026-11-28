"""The programs a shell command runs, for `cmd/<program>` patterns.

An agent runs `gh pr list` through its shell tool (Claude Code's `Bash`), so the hook
sees one tool call holding a whole command line. `programs()` lists the programs that
line starts, conservatively: anything it cannot follow (command substitution, `eval`,
`bash -c '…'`, heredocs, $'…' quoting, unbalanced quotes) raises CommandError, and the
caller blocks the call. A `#` that starts a word is a comment to the end of its line.

It reads names, not binaries: `/tmp/gh` counts as `gh`. And a program that starts other
programs itself (`make`, `npm run`, `find -exec`, a script) runs whatever it runs. This
limits what an agent asks the shell to do; it is not a sandbox.
"""

import re
import shlex
from typing import Any, NamedTuple

# Agent name -> the names of its shell tool. Add an agent here to check its commands.
SHELL_TOOLS: dict[str, frozenset[str]] = {
    "claude-code": frozenset({"Bash"}),
    # Codex's hooks name its shell `Bash` (codex-rs/hooks); `shell` is its older name.
    "codex": frozenset({"shell", "Bash"}),
    # Cursor's beforeShellExecution, as agents.py hands it to check.
    "cursor": frozenset({"Shell"}),
    "gemini": frozenset({"run_shell_command"}),
    "gemini-cli": frozenset({"run_shell_command"}),
}

# Programs that run the next word as the program: `sudo gh`, `env X=1 gh`, `xargs gh`.
# Both must be allowed: `sudo gh` needs cmd/sudo and cmd/gh.
WRAPPERS = frozenset(
    {"sudo", "env", "time", "nohup", "xargs", "command", "exec", "nice", "ionice", "setsid",
     "stdbuf"}
)  # fmt: skip
# Each wrapper's options: (short flags taking a value, short flags without one, long
# options taking a value, long options without one). An option not listed here makes
# the command unreadable (blocked): `sudo -u gh rm` must not read `gh` as the program.
_WRAPPER_OPTIONS: dict[str, tuple[str, str, frozenset[str], frozenset[str]]] = {
    "sudo": (
        "ughpCDrtTU",
        "EHnkKSbisPAB",
        frozenset({"user", "group", "host", "prompt", "close-from", "chdir", "role",
                   "type", "command-timeout", "other-user"}),
        frozenset({"preserve-env", "set-home", "non-interactive", "reset-timestamp",
                   "remove-timestamp", "stdin", "background", "login", "shell",
                   "preserve-groups", "askpass", "bell"}),
    ),
    "env": ("uC", "i0v", frozenset({"unset", "chdir"}),
            frozenset({"ignore-environment", "null", "debug"})),
    "xargs": (
        "nIPLsdEa",
        "0rtpxil",
        frozenset({"max-args", "max-procs", "max-lines", "max-chars", "delimiter",
                   "eof", "arg-file", "process-slot-var"}),
        frozenset({"null", "no-run-if-empty", "verbose", "interactive", "exit",
                   "open-tty"}),
    ),
    "time": ("fo", "pav", frozenset({"format", "output"}),
             frozenset({"portability", "append", "verbose", "quiet"})),
    "nohup": ("", "", frozenset(), frozenset()),
    "command": ("", "pvV", frozenset(), frozenset()),
    "exec": ("a", "cl", frozenset(), frozenset()),
    "nice": ("n", "", frozenset({"adjustment"}), frozenset()),
    "ionice": ("cn", "t", frozenset({"class", "classdata"}), frozenset({"ignore"})),
    "setsid": ("", "cfw", frozenset(), frozenset({"ctty", "fork", "wait"})),
    "stdbuf": ("ioe", "", frozenset({"input", "output", "error"}), frozenset()),
}  # fmt: skip


def _wrapper_option(wrapper: str, word: str) -> int:
    """How many following words belong to this option (0 or 1). Raises for an option
    botrbac does not know, since it could hide which program runs."""
    value_short, plain_short, value_long, plain_long = _WRAPPER_OPTIONS[wrapper]
    if word.startswith("--"):
        name, eq, _ = word[2:].partition("=")
        if name in value_long:
            return 0 if eq else 1
        if name in plain_long and not eq:
            return 0
    elif word == "-":
        if wrapper == "env":
            return 0  # `env -` is env -i
    else:
        letters = word[1:]
        for i, letter in enumerate(letters):
            if letter in value_short:
                return 0 if letters[i + 1 :] else 1
            if letter not in plain_short:
                break
        else:
            return 0
    raise CommandError(f"botrbac cannot read the {wrapper} option {word.split('=')[0]!r}")


# Shell control flow: the commands inside `if …; then …; fi` or `for … do …` would read
# as arguments of the keyword, so they are refused rather than left unchecked.
KEYWORDS = frozenset(
    {"if", "then", "elif", "else", "fi", "for", "while", "until", "do", "done", "case",
     "esac", "select", "function", "!", "{", "}", "[[", "]]", "coproc"}
)  # fmt: skip
SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish", "ash"})
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# One shell operator. _tokens hands back a run of operator characters as one token
# (`;>` in `gh;>f rm`), so the run is split into these, longest first, as bash does.
_OPERATOR = re.compile(r"&>>|&>|>>|>&|<&|<<<|<<-|<<|<>|>\||;;&|;;|;&|&&|\|\||\|&|[;&|\n<>()]")
_SEPARATORS = frozenset({";;&", ";;", ";&", "&&", "||", "|&", ";", "&", "|", "\n"})
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


_OPERATOR_CHARS = frozenset(";&|<>()\n")
_BLANKS = frozenset(" \t")


class _Token(NamedTuple):
    text: str
    is_op: bool
    # A word: whether any of it was quoted or escaped. An operator: whether it follows
    # a word with nothing between them (`2>f`), which is what makes `2` a file descriptor.
    quoted_or_glued: bool


def _parameter(command: str, i: int) -> int:
    """`${…}` starting at command[i]: the index just past its `}`. Inside one, bash
    allows nested quotes (`"${x:-"a"}"`), which would throw the quote tracking off, so
    anything but plain text there is refused."""
    close = command.find("}", i + 2)
    if close < 0:
        raise CommandError("botrbac could not read this command (unclosed ${)")
    inner = command[i + 2 : close]
    if any(c in inner for c in "'\"\\$`{\n"):
        raise CommandError("botrbac does not read quotes or nesting inside ${…}")
    return close + 1


def _tokens(command: str) -> list[_Token]:
    """The command's words and operator runs, read the way bash reads them: quotes and
    backslashes, and a `#` that starts a word begins a comment running to the end of the
    line (the newline after it still separates commands). Quoting botrbac cannot follow
    exactly ($'…', $"…") raises CommandError."""
    out: list[_Token] = []
    word: list[str] = []
    in_word = False  # a word has started (it may still be empty: `''`)
    quoted = False
    i, n = 0, len(command)

    def finish() -> None:
        nonlocal in_word, quoted
        if in_word:
            out.append(_Token("".join(word), False, quoted))
        word.clear()
        in_word, quoted = False, False

    while i < n:
        c = command[i]
        if c in _BLANKS:
            finish()
            i += 1
        elif c in _OPERATOR_CHARS:
            glued = in_word
            finish()
            j = i
            while j < n and command[j] in _OPERATOR_CHARS:
                j += 1
            out.append(_Token(command[i:j], True, glued))
            i = j
        elif c == "#" and not in_word:
            newline = command.find("\n", i)
            i = n if newline < 0 else newline  # the newline itself is read next
        elif c == "\\":
            if i + 1 >= n:
                raise CommandError("botrbac could not read this command (trailing backslash)")
            if command[i + 1] != "\n":  # backslash-newline: the line continues
                word.append(command[i + 1])
                in_word, quoted = True, True
            i += 2
        elif c == "'":
            close = command.find("'", i + 1)
            if close < 0:
                raise CommandError("botrbac could not read this command (unbalanced quotes)")
            word.append(command[i + 1 : close])
            in_word, quoted = True, True
            i = close + 1
        elif c == '"':
            i += 1
            while True:
                if i >= n:
                    raise CommandError("botrbac could not read this command (unbalanced quotes)")
                d = command[i]
                if d == '"':
                    i += 1
                    break
                if d == "\\" and i + 1 < n and command[i + 1] in '$`"\\\n':
                    if command[i + 1] != "\n":
                        word.append(command[i + 1])
                    i += 2
                elif d == "$" and command.startswith("${", i):
                    end = _parameter(command, i)
                    word.append(command[i:end])
                    i = end
                else:
                    word.append(d)
                    i += 1
            in_word, quoted = True, True
        elif c == "$" and i + 1 < n and command[i + 1] in "'\"":
            raise CommandError("botrbac does not read $'…' or $\"…\" quoting: use plain quotes")
        elif c == "$" and command.startswith("${", i):
            end = _parameter(command, i)
            word.append(command[i:end])
            in_word = True
            i = end
        else:
            word.append(c)
            in_word = True
            i += 1
    finish()
    return out


def _operators(run: str) -> list[str]:
    ops = _OPERATOR.findall(run)
    if "".join(ops) != run:
        raise CommandError("botrbac could not read this command")
    return ops


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
    in_wrapper: str | None = None  # the wrapper whose options come next
    wrapper_skip = 0  # option values still to skip
    shell_running: str | None = None
    tokens = _tokens(command)
    for index, (word, is_op, quoted_or_glued) in enumerate(tokens):
        # An option's value (`xargs -n 1 >f rm`) is consumed below, never read as an fd.
        if not is_op and not quoted_or_glued and not wrapper_skip and word.isdigit():
            after = tokens[index + 1] if index + 1 < len(tokens) else None
            if after and after.is_op and after.quoted_or_glued and after.text[:1] in "<>":
                # `2>f rm`: a file descriptor number, not a program. Only when the number
                # touches the operator, as in bash: in `2 >f` (spaced) or `"2">f`
                # (quoted), 2 is the program.
                continue
        if is_op:
            for op in _operators(word):
                if op in ("(", ")"):
                    raise CommandError("botrbac does not check commands in ( … ) subshells")
                if op in ("<<", "<<-"):
                    raise CommandError(
                        "botrbac does not check heredocs (<<): write the text to a file "
                        "first, or pass it with <<< or a pipe"
                    )
                if op in _SEPARATORS:
                    expect_program, in_wrapper, shell_running = True, None, None
                    wrapper_skip = 0
                    skip_next = False
                else:
                    skip_next = True  # a redirect: the next word is a file name
            continue
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
        # An option's value first, whatever it looks like: `sudo -u A=b rm` must not
        # read A=b as an assignment and then take `rm` for the value.
        if wrapper_skip:
            wrapper_skip -= 1  # sudo -u USER, xargs -I {}
            continue
        # Only where a program would be: `echo done` and `git commit -m fi` are fine.
        if word in KEYWORDS:
            raise CommandError(
                "botrbac does not check shell control flow (if, for, while …): "
                "run the commands one by one"
            )
        if _ASSIGNMENT.match(word):
            continue  # FOO=1 gh …
        if in_wrapper and word == "--":
            in_wrapper = None  # end of the wrapper's options: the program is next
            continue
        if in_wrapper and word.startswith("-"):
            wrapper_skip = _wrapper_option(in_wrapper, word)
            continue
        name = _base(word)
        if "$" in word or not _PROGRAM.fullmatch(name):
            raise CommandError("botrbac cannot tell which program this command runs")
        if name in WRAPPERS:
            # Checked itself (cmd/sudo) and as the program it runs.
            if name not in found:
                found.append(name)
            in_wrapper = name
            continue
        if name not in found:
            found.append(name)
        expect_program, in_wrapper = False, None
        shell_running = name if name in SHELLS else None
    if not found:
        raise CommandError("botrbac found no program in this command")
    return found

"""`botrbac shell-init`: lets `claude --botrbac --role reviewer` work in any agent.

Agents cannot be given new flags, so this prints small shell functions named after
each agent. With `--botrbac` the function removes `--botrbac` and `--role NAME` and runs
`botrbac run --role NAME -- <agent> <the rest>`. Without `--botrbac` it runs the agent
exactly as before. Add `eval "$(botrbac shell-init)"` to your shell's startup file.
"""

import re
import shlex
import shutil
import sys

DEFAULT_AGENTS = ("claude", "codex", "gemini", "cursor-agent", "opencode", "aider")
_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,40}$")


def botrbac_command() -> list[str]:
    found = shutil.which("botrbac")
    return [found] if found else [sys.executable, "-m", "botrbac_cli"]


def posix(agents: list[str]) -> str:
    me = " ".join(shlex.quote(part) for part in botrbac_command())
    lines = [
        "# botrbac shell-init: `<agent> --botrbac --role NAME` runs the agent under that role.",
        "__botrbac_wrap() {",
        '  local prog="$1"; shift',
        '  local use=0 a role="" done=0',
        "  # Only flags before a `--` count: after it, everything is the agent's.",
        '  for a in "$@"; do [ "$a" = "--" ] && break; [ "$a" = "--botrbac" ] && use=1; done',
        '  if [ "$use" = 0 ]; then command "$prog" "$@"; return $?; fi',
        "  local -a rest",
        "  rest=()",
        "  while [ $# -gt 0 ]; do",
        '    a="$1"; shift',
        '    if [ "$done" = 1 ]; then rest+=("$a"); continue; fi',
        '    case "$a" in',
        '      --) done=1; rest+=("$a") ;;',
        "      --botrbac) ;;",
        "      --role)",
        '        if [ $# -eq 0 ]; then echo "botrbac: --role needs a value" >&2; return 2; fi',
        '        role="$1"; shift ;;',
        '      --role=*) role="${a#--role=}" ;;',
        '      *) rest+=("$a") ;;',
        "    esac",
        "  done",
        '  if [ -z "$role" ]; then',
        '    echo "botrbac: give --role NAME with --botrbac" >&2; return 2',
        "  fi",
        f'  {me} run --role "$role" --agent "$prog" -- "$prog" "${{rest[@]}}"',
        "}",
    ]
    lines += [f'{a}() {{ __botrbac_wrap {a} "$@"; }}' for a in agents]
    return "\n".join(lines) + "\n"


def fish(agents: list[str]) -> str:
    me = " ".join(shlex.quote(part) for part in botrbac_command())
    lines = [
        "# botrbac shell-init: `<agent> --botrbac --role NAME` runs the agent under that role.",
        "function __botrbac_wrap",
        "    set -l prog $argv[1]",
        "    set -e argv[1]",
        "    set -l head $argv",
        "    set -l cut (contains -i -- -- $argv)",
        '    if test -n "$cut"',
        "        set head",
        "        if test $cut -gt 1",
        "            set head $argv[1..(math $cut - 1)]",
        "        end",
        "    end",
        "    if not contains -- --botrbac $head",
        "        command $prog $argv",
        "        return $status",
        "    end",
        '    set -l role ""',
        "    set -l rest",
        "    set -l skip 0",
        "    set -l done 0",
        "    for i in (seq (count $argv))",
        "        if test $skip = 1",
        "            set skip 0",
        "            continue",
        "        end",
        "        set -l a $argv[$i]",
        "        if test $done = 1",
        "            set -a rest $a",
        "            continue",
        "        end",
        "        switch $a",
        "            case --",
        "                set done 1",
        "                set -a rest $a",
        "            case --botrbac",
        "            case --role",
        "                set role $argv[(math $i + 1)]",
        "                set skip 1",
        "            case '--role=*'",
        "                set role (string replace -- --role= '' $a)",
        "            case '*'",
        "                set -a rest $a",
        "        end",
        "    end",
        '    if test -z "$role"',
        '        echo "botrbac: give --role NAME with --botrbac" >&2',
        "        return 2",
        "    end",
        f"    {me} run --role $role --agent $prog -- $prog $rest",
        "end",
    ]
    for a in agents:
        lines += [f"function {a} --wraps {a}", f"    __botrbac_wrap {a} $argv", "end"]
    return "\n".join(lines) + "\n"


def script(shell: str, agents: list[str]) -> str:
    bad = [a for a in agents if not _NAME.match(a)]
    if bad:
        raise ValueError(f"not an agent command name: {', '.join(bad)}")
    return fish(agents) if shell == "fish" else posix(agents)

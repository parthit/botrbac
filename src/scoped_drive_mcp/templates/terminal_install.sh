#!/bin/sh
# Bot RBAC Terminal: install botrbac, connect this computer to {{ server }}, and add the
# Bot RBAC gateway to one agent. Read it first: {{ server }}/terminal/install.sh
#
#   curl -fsSL {{ server }}/terminal/install.sh | sh -s -- --agent claude-code
#
# Agents: claude-code (default), cursor, codex, gemini. Never uses sudo. Safe to run
# again: it upgrades botrbac and skips steps that are already done.
#
# It also adds the agent's pre-tool hook, so the agent's own tools (its shell, file edits)
# follow this computer's role too. --no-hook leaves that out; `botrbac hooks remove <agent>
# --user` undoes it later.
set -eu

SERVER='{{ server }}'
SOURCE='git+https://github.com/parthit/botrbac'

say() { printf '%s\n' "$*"; }
step() { printf '\n==> %s\n' "$*"; }
run() { printf '    $ %s\n' "$*"; "$@" </dev/null; }
fail() { printf 'botrbac install failed: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

main() {
  agent=claude-code
  hook=yes
  while [ $# -gt 0 ]; do
    case "$1" in
      --agent) [ $# -ge 2 ] || fail "--agent needs a value"; agent=$2; shift 2 ;;
      --agent=*) agent=${1#--agent=}; shift ;;
      --no-hook) hook=no; shift ;;
      -h|--help)
        say "usage: sh install.sh [--agent claude-code|cursor|codex|gemini] [--no-hook]"
        return 0 ;;
      *) fail "unknown option: $1" ;;
    esac
  done
  case "$agent" in
    claude-code) agent_name="Claude Code" ;;
    cursor) agent_name="Cursor" ;;
    codex) agent_name="Codex" ;;
    gemini) agent_name="Gemini CLI" ;;
    *) fail "unknown agent '$agent' (use claude-code, cursor, codex or gemini)" ;;
  esac
  PATH="$HOME/.local/bin:$PATH"
  export PATH

  step "Install botrbac"
  if have uv; then
    run uv tool install --upgrade "$SOURCE" || fail "uv could not install botrbac"
  elif have pipx; then
    run pipx install --force "$SOURCE" || fail "pipx could not install botrbac"
  else
    say "Neither uv nor pipx is installed, so installing uv first (https://astral.sh/uv)."
    have curl || fail "curl is needed to install uv"
    printf '    $ %s\n' "curl -LsSf https://astral.sh/uv/install.sh | sh"
    curl -LsSf https://astral.sh/uv/install.sh </dev/null | sh || fail "could not install uv"
    PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
    export PATH
    have uv || fail "uv was installed but is not on PATH; open a new shell and run this again"
    run uv tool install --upgrade "$SOURCE" || fail "uv could not install botrbac"
  fi
  have botrbac || fail "botrbac was installed but is not on PATH (try: uv tool update-shell)"
  botrbac=$(command -v botrbac)

  step "Connect this computer to $SERVER"
  if "$botrbac" status </dev/null >/dev/null 2>&1; then
    say "Already logged in. (To connect again: $botrbac login --server $SERVER)"
  else
    say "Open the link below in your browser and approve the code. This waits for you."
    run "$botrbac" login --server "$SERVER" || fail "login did not complete"
  fi

  step "Add Bot RBAC to $agent_name"
  if [ "$agent" = claude-code ]; then
    if ! have claude; then
      say "Claude Code (claude) is not installed here, so this was skipped. Once it is, run:"
      say "    claude mcp add --scope user botrbac -- $botrbac gateway"
    elif claude mcp get botrbac </dev/null >/dev/null 2>&1; then
      say "Claude Code already has a server called botrbac; left as it is."
    else
      run claude mcp add --scope user botrbac -- "$botrbac" gateway \
        || fail "claude mcp add did not work"
    fi
  else
    run "$botrbac" add-gateway --agent "$agent" || fail "could not add the gateway"
  fi

  if [ "$hook" = yes ]; then
    step "Let the role cover $agent_name's own tools (shell, file edits)"
    run "$botrbac" hooks install "$agent" --user --allow-unguarded \
      || fail "could not add the $agent_name hook"
    say "Undo any time: $botrbac hooks remove $agent --user"
    if [ "$agent" = codex ]; then
      say "Codex runs a new hook only once you trust it: open Codex and run /hooks."
    fi
  fi

  step "Check"
  run "$botrbac" doctor || say "(doctor lists what to look at above; the setup itself is done)"

  say ""
  say "Done. Restart $agent_name to load Bot RBAC."
  if [ "$hook" = yes ]; then
    say "This computer's role now decides what $agent_name may do, including running commands"
    say "and editing files. A new computer starts as Read-only: $agent_name can read but not"
    say "change anything until you give it a wider role at $SERVER/terminal"
  else
    say "Your computers and their roles: $SERVER/terminal"
  fi
}

# Everything runs from here, so a download cut short runs nothing.
main "$@"
